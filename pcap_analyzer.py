"""
pcap_analyzer.py
================
Reads a PCAP / PCAPNG file and extracts structured information from it.

Everything in this module is computed by our own code from the raw packets.
scapy is used only to decode packet headers (Ethernet / IP / TCP / UDP / DNS);
TCP reassembly, HTTP parsing, request/response matching and TLS SNI extraction
are implemented here.

Frame numbers are 1-based and follow the order of packets in the file,
exactly like Wireshark's "No." column, so every result can be checked
against Wireshark.
"""

from __future__ import annotations

import bisect
import gzip
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pandas as pd
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Well-known UDP ports -> protocol name (used to label UDP packets).
UDP_PORT_NAMES = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 137: "NBNS", 138: "NetBIOS",
    443: "QUIC", 1900: "SSDP", 3478: "STUN", 5353: "MDNS", 5355: "LLMNR",
}

# TCP flag bits.
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")

# Maximum number of body bytes we keep as a readable preview.
BODY_PREVIEW_LIMIT = 3000


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Segment:
    """One TCP segment that carried payload."""
    seq: int
    payload: bytes
    frame: int
    time: float


@dataclass
class TcpStream:
    """All the information we collect about one TCP connection."""
    index: int                       # like Wireshark's tcp.stream (0-based)
    endpoint_a: tuple[str, int]      # first endpoint seen
    endpoint_b: tuple[str, int]
    frames: list[int] = field(default_factory=list)
    first_time: float = 0.0
    last_time: float = 0.0
    total_bytes: int = 0
    flag_counts: Counter = field(default_factory=Counter)
    client: tuple[str, int] | None = None   # sender of the first pure SYN
    # payload segments, keyed by the sending endpoint
    segments: dict[tuple[str, int], list[Segment]] = field(
        default_factory=lambda: defaultdict(list))


@dataclass
class HttpMessage:
    """A single HTTP request or response reassembled from a TCP stream."""
    kind: str                        # "request" or "response"
    start_line: str
    headers: dict[str, str]          # header names in lower case
    raw_header: str
    body: bytes
    first_frame: int
    last_frame: int                  # Wireshark shows the message in this frame
    time: float                      # time of last_frame
    segment_frames: list[int]        # frames that carried bytes of this message
    complete: bool
    method: str | None = None
    uri: str | None = None
    version: str | None = None
    status: int | None = None
    reason: str | None = None


@dataclass
class CaptureAnalysis:
    """The full result of analysing one capture file."""
    file_name: str
    summary: dict
    packets: pd.DataFrame            # one row per frame
    streams: pd.DataFrame            # one row per TCP stream
    transactions: pd.DataFrame       # one row per HTTP request/response pair
    hostnames: dict[str, list[str]]  # IP -> names learned from DNS / SNI / Host


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _flags_to_text(flags: int) -> str:
    """Convert TCP flag bits to Wireshark-like text, e.g. 'SYN, ACK'."""
    names = [(SYN, "SYN"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (ACK, "ACK")]
    return ", ".join(name for bit, name in names if flags & bit)


def _tcp_payload(pkt, ip_layer) -> bytes:
    """
    Return the real TCP payload.
    We compute the length from the IP header because scapy may append
    Ethernet padding bytes to the payload of short frames.
    """
    tcp = pkt[TCP]
    header_len = (tcp.dataofs or 5) * 4
    if isinstance(ip_layer, IP):
        payload_len = ip_layer.len - ip_layer.ihl * 4 - header_len
    else:  # IPv6 (assumes no extension headers, which is the normal case)
        payload_len = ip_layer.plen - header_len
    raw = bytes(tcp.payload)
    return raw[:max(payload_len, 0)]


def _decode_body(body: bytes, headers: dict[str, str]) -> bytes:
    """Undo gzip / deflate content encoding when possible."""
    encoding = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in encoding:
            return gzip.decompress(body)
        if "deflate" in encoding:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError):
        pass  # truncated / unsupported -> keep the original bytes
    return body


def _body_preview(body: bytes, headers: dict[str, str]) -> str:
    """Readable preview of a body (text only; binary bodies are summarised)."""
    if not body:
        return ""
    content_type = headers.get("content-type", "").lower()
    is_text = any(t in content_type for t in
                  ("text", "json", "xml", "javascript", "x-www-form-urlencoded"))
    if not is_text and content_type:
        return f"<{len(body)} bytes of {content_type}>"
    text = body[:BODY_PREVIEW_LIMIT].decode("utf-8", errors="replace")
    if len(body) > BODY_PREVIEW_LIMIT:
        text += f"\n... ({len(body) - BODY_PREVIEW_LIMIT} more bytes)"
    return text


# ---------------------------------------------------------------------------
# TCP reassembly
# ---------------------------------------------------------------------------

def reassemble(segments: list[Segment]) -> tuple[bytes, list[tuple[int, int, int, float]]]:
    """
    Rebuild the byte stream of one TCP direction.

    Segments are ordered by their sequence number; retransmitted bytes that we
    already have are dropped. Returns the data and a list of "chunks"
    (start_offset, end_offset, frame, time) that tells which frame carried
    which bytes - this is how we know the frame of every HTTP message.
    """
    if not segments:
        return b"", []

    # The stream starts at the LOWEST sequence number, not at the first segment
    # we saw: segments can arrive out of order (a later segment captured before
    # an earlier one). Offsets are computed modulo 2^32 to survive wrap-around.
    first_seq = segments[0].seq
    offsets = [((s.seq - first_seq + 2**31) % 2**32) - 2**31 for s in segments]
    base_seq = (first_seq + min(offsets)) % 2**32

    def relative(seq: int) -> int:
        return (seq - base_seq) % 2**32

    ordered = sorted(segments, key=lambda s: (relative(s.seq), s.frame))
    data = bytearray()
    chunks: list[tuple[int, int, int, float]] = []

    for seg in ordered:
        start = relative(seg.seq)
        if start > 2**31:          # segment from before the first one we saw
            continue
        end = start + len(seg.payload)
        if end <= len(data):       # retransmission of bytes we already have
            continue
        payload = seg.payload
        if start < len(data):      # partial overlap -> keep only the new bytes
            payload = payload[len(data) - start:]
        # (if start > len(data) bytes are missing from the capture; we simply
        #  continue after the gap)
        chunks.append((len(data), len(data) + len(payload), seg.frame, seg.time))
        data += payload

    return bytes(data), chunks


def _chunks_in_range(chunks, start: int, end: int):
    """Return the chunks that carry bytes in the range [start, end)."""
    starts = [c[0] for c in chunks]
    i = max(bisect.bisect_right(starts, start) - 1, 0)
    result = []
    while i < len(chunks) and chunks[i][0] < end:
        if chunks[i][1] > start:
            result.append(chunks[i])
        i += 1
    return result


# ---------------------------------------------------------------------------
# HTTP parsing
# ---------------------------------------------------------------------------

def _read_chunked(data: bytes, pos: int) -> tuple[bytes, int, bool]:
    """Decode a 'Transfer-Encoding: chunked' body. Returns (body, end, complete)."""
    body = bytearray()
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return bytes(body), len(data), False
        try:
            size = int(data[pos:line_end].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(body), len(data), False
        pos = line_end + 2
        if size == 0:                                   # last chunk
            if data[pos:pos + 2] == b"\r\n":
                return bytes(body), pos + 2, True
            trailer_end = data.find(b"\r\n\r\n", pos)   # optional trailers
            if trailer_end == -1:
                return bytes(body), len(data), False
            return bytes(body), trailer_end + 4, True
        if pos + size + 2 > len(data):                  # truncated chunk
            body += data[pos:]
            return bytes(body), len(data), False
        body += data[pos:pos + size]
        pos += size + 2


def parse_http_messages(data: bytes, chunks, kind: str,
                        request_methods: list[str] | None = None) -> list[HttpMessage]:
    """
    Split one reassembled TCP direction into HTTP messages.

    kind            - "request" (client->server) or "response" (server->client)
    request_methods - methods of the requests on the same connection, needed
                      because a response to HEAD never has a body.
    """
    messages: list[HttpMessage] = []
    pos = 0
    response_index = 0

    while pos < len(data):
        # Each message must start with a request line / status line.
        head = data[pos:pos + 16]
        if kind == "request" and not head.startswith(HTTP_METHODS):
            break
        if kind == "response" and not head.startswith(b"HTTP/"):
            break

        header_end = data.find(b"\r\n\r\n", pos)
        if header_end == -1:                 # headers not fully captured
            break

        raw_header = data[pos:header_end].decode("iso-8859-1")
        lines = raw_header.split("\r\n")
        start_line = lines[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

        msg = HttpMessage(kind=kind, start_line=start_line, headers=headers,
                          raw_header=raw_header, body=b"", first_frame=0,
                          last_frame=0, time=0.0, segment_frames=[], complete=True)

        # Parse the first line.
        parts = start_line.split(" ", 2)
        if kind == "request":
            msg.method = parts[0]
            msg.uri = parts[1] if len(parts) > 1 else ""
            msg.version = parts[2] if len(parts) > 2 else ""
        else:
            msg.version = parts[0]
            try:
                msg.status = int(parts[1])
            except (IndexError, ValueError):
                msg.status = None
            msg.reason = parts[2] if len(parts) > 2 else ""

        # Work out where the body ends (RFC 9112, section 6.3).
        body_start = header_end + 4
        is_chunked = "chunked" in headers.get("transfer-encoding", "").lower()
        content_length = headers.get("content-length")
        no_body = False
        if kind == "response":
            method = (request_methods[response_index]
                      if request_methods and response_index < len(request_methods) else None)
            status = msg.status or 0
            no_body = method == "HEAD" or 100 <= status < 200 or status in (204, 304)

        if no_body:
            body, end, complete = b"", body_start, True
        elif is_chunked:
            body, end, complete = _read_chunked(data, body_start)
        elif content_length is not None and content_length.isdigit():
            end = body_start + int(content_length)
            complete = end <= len(data)
            end = min(end, len(data))
            body = data[body_start:end]
        elif kind == "request":
            body, end, complete = b"", body_start, True
        else:                                 # response without length: until close
            body, end, complete = data[body_start:], len(data), True

        msg.body = _decode_body(body, headers)
        msg.complete = complete

        # Which frames carried this message? Wireshark shows the message in
        # the frame that completed it, i.e. the segment that ARRIVED last
        # (with out-of-order segments this is not the one with the highest seq).
        used = _chunks_in_range(chunks, pos, end)
        if used:
            msg.segment_frames = sorted(c[2] for c in used)
            completing = max(used, key=lambda c: c[2])
            msg.first_frame = msg.segment_frames[0]
            msg.last_frame = completing[2]
            msg.time = completing[3]
        messages.append(msg)

        if kind == "response" and not (msg.status and 100 <= msg.status < 200):
            response_index += 1
        pos = end

    return messages


# ---------------------------------------------------------------------------
# TLS (HTTPS) - Server Name Indication
# ---------------------------------------------------------------------------

def parse_tls_sni(data: bytes) -> str | None:
    """
    Extract the server name (SNI) from a TLS ClientHello.
    Even with HTTPS this name is sent in clear text, so it reveals which site
    the user visited.
    """
    try:
        # record header: type 0x16 = handshake; handshake type 0x01 = ClientHello
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None
        p = 9 + 2 + 32                         # headers + client version + random
        p += 1 + data[p]                       # session id
        p += 2 + int.from_bytes(data[p:p + 2], "big")   # cipher suites
        p += 1 + data[p]                       # compression methods
        ext_end = p + 2 + int.from_bytes(data[p:p + 2], "big")
        p += 2
        while p + 4 <= min(ext_end, len(data)):
            ext_type = int.from_bytes(data[p:p + 2], "big")
            ext_len = int.from_bytes(data[p + 2:p + 4], "big")
            p += 4
            if ext_type == 0:                  # server_name extension
                name_len = int.from_bytes(data[p + 3:p + 5], "big")
                return data[p + 5:p + 5 + name_len].decode("ascii", errors="replace")
            p += ext_len
    except IndexError:
        pass
    return None


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def _classify_tcp(payload: bytes, sport: int, dport: int) -> str:
    """Initial protocol label for a TCP packet (HTTP frames are refined later)."""
    if not payload:
        return "TCP"
    if 443 in (sport, dport) or payload[:1] in (b"\x14", b"\x15", b"\x16", b"\x17"):
        if payload[1:2] == b"\x03":         # TLS record header: 0x03 0x0X version
            return "TLS"
    return "TCP"


def analyze_pcap(path: str | Path) -> CaptureAnalysis:
    """Read a capture file and return a CaptureAnalysis with all extracted data."""
    path = Path(path)
    rows: list[dict] = []
    streams: dict[frozenset, TcpStream] = {}
    stream_order: list[TcpStream] = []
    dns_names: dict[str, set[str]] = defaultdict(set)

    # ---- pass 1: read every packet ------------------------------------------
    with PcapReader(str(path)) as reader:
        for frame_no, pkt in enumerate(reader, start=1):
            t = float(pkt.time)
            length = getattr(pkt, "wirelen", None) or len(pkt)
            row = {"frame": frame_no, "time": t, "src": "", "dst": "",
                   "sport": None, "dport": None, "protocol": "Other",
                   "length": length, "tcp_stream": None, "tcp_flags": "",
                   "payload_len": 0, "info": ""}

            ip_layer = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)

            if ip_layer is not None:
                row["src"], row["dst"] = ip_layer.src, ip_layer.dst

                if TCP in pkt:
                    tcp = pkt[TCP]
                    payload = _tcp_payload(pkt, ip_layer)
                    flags = int(tcp.flags)
                    row.update(sport=tcp.sport, dport=tcp.dport,
                               tcp_flags=_flags_to_text(flags),
                               payload_len=len(payload),
                               protocol=_classify_tcp(payload, tcp.sport, tcp.dport))
                    row["info"] = (f"{tcp.sport} → {tcp.dport} [{row['tcp_flags']}] "
                                   f"Len={len(payload)}")

                    # find / create the TCP stream of this packet
                    a, b = (ip_layer.src, tcp.sport), (ip_layer.dst, tcp.dport)
                    key = frozenset((a, b))
                    stream = streams.get(key)
                    if stream is None:
                        stream = TcpStream(index=len(stream_order), endpoint_a=a,
                                           endpoint_b=b, first_time=t)
                        streams[key] = stream
                        stream_order.append(stream)
                    stream.frames.append(frame_no)
                    stream.last_time = t
                    stream.total_bytes += length
                    for bit, name in ((SYN, "SYN"), (FIN, "FIN"), (RST, "RST")):
                        if flags & bit:
                            stream.flag_counts[name] += 1
                    if flags & SYN and not flags & ACK and stream.client is None:
                        stream.client = a
                    if payload:
                        stream.segments[a].append(Segment(tcp.seq, payload, frame_no, t))
                    row["tcp_stream"] = stream.index

                elif UDP in pkt:
                    udp = pkt[UDP]
                    row.update(sport=udp.sport, dport=udp.dport)
                    row["protocol"] = (UDP_PORT_NAMES.get(udp.dport)
                                       or UDP_PORT_NAMES.get(udp.sport) or "UDP")
                    row["info"] = f"{udp.sport} → {udp.dport} Len={len(udp.payload)}"
                    if DNS in pkt:
                        row["protocol"] = "MDNS" if row["protocol"] == "MDNS" else "DNS"
                        row["info"] = _dns_info(pkt[DNS], dns_names)

                elif ICMP in pkt:
                    row["protocol"] = "ICMP"
                elif isinstance(ip_layer, IPv6) and ip_layer.nh == 58:
                    row["protocol"] = "ICMPv6"
                elif isinstance(ip_layer, IP) and ip_layer.proto == 2:
                    row["protocol"] = "IGMP"
                else:
                    row["protocol"] = ip_layer.payload.name

            elif ARP in pkt:
                arp = pkt[ARP]
                row.update(src=arp.psrc, dst=arp.pdst, protocol="ARP",
                           info=f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1
                           else f"{arp.psrc} is at {arp.hwsrc}")
            elif Ether in pkt:
                row.update(src=pkt[Ether].src, dst=pkt[Ether].dst,
                           protocol=pkt[Ether].payload.name or "Ethernet")

            rows.append(row)

    packets = pd.DataFrame(rows)
    if packets.empty:
        raise ValueError("The capture file contains no packets.")
    start_time = packets["time"].iloc[0]
    packets["rel_time"] = packets["time"] - start_time

    # ---- pass 2: per-stream reassembly, HTTP and TLS ------------------------
    transactions: list[dict] = []
    stream_rows: list[dict] = []
    sni_names: dict[str, set[str]] = defaultdict(set)
    http_hosts: dict[str, set[str]] = defaultdict(set)
    frame_updates: dict[int, tuple[str, str]] = {}   # frame -> (protocol, info)

    for stream in stream_order:
        client, server = _client_server(stream)
        client_data, client_chunks = reassemble(stream.segments.get(client, []))
        server_data, server_chunks = reassemble(stream.segments.get(server, []))

        app_protocol = "TCP"
        sni = None
        requests: list[HttpMessage] = []
        responses: list[HttpMessage] = []

        if client_data.startswith(HTTP_METHODS) or server_data.startswith(b"HTTP/"):
            app_protocol = "HTTP"
            requests = parse_http_messages(client_data, client_chunks, "request")
            responses = parse_http_messages(server_data, server_chunks, "response",
                                            [r.method for r in requests])
        elif client_data[:1] == b"\x16":
            app_protocol = "TLS"
            sni = parse_tls_sni(client_data)
            if sni:
                sni_names[server[0]].add(sni)
                hello_frame = client_chunks[0][2]
                frame_updates[hello_frame] = ("TLS", f"Client Hello (SNI={sni})")

        # Mark HTTP frames like Wireshark does (on the last segment).
        for msg in requests + responses:
            if msg.last_frame:
                frame_updates[msg.last_frame] = ("HTTP", msg.start_line)

        # Match requests to responses: HTTP/1.x answers in order (FIFO).
        final_responses = [r for r in responses if not (r.status and 100 <= r.status < 200)]
        for i, req in enumerate(requests):
            resp = final_responses[i] if i < len(final_responses) else None
            transactions.append(_make_transaction(len(transactions) + 1, stream.index,
                                                  client, server, req, resp, start_time))
            if req.headers.get("host"):
                http_hosts[server[0]].add(req.headers["host"].split(":")[0])

        duration = stream.last_time - stream.first_time
        stream_rows.append({
            "stream": stream.index,
            "client": f"{client[0]}:{client[1]}",
            "server": f"{server[0]}:{server[1]}",
            "client_ip": client[0], "client_port": client[1],
            "server_ip": server[0], "server_port": server[1],
            "app_protocol": app_protocol,
            "sni": sni,
            "packets": len(stream.frames),
            "bytes": stream.total_bytes,
            "client_payload_bytes": len(client_data),
            "server_payload_bytes": len(server_data),
            "first_frame": stream.frames[0],
            "last_frame": stream.frames[-1],
            "start_rel": stream.first_time - start_time,
            "duration": duration,
            "syn": stream.flag_counts["SYN"],
            "fin": stream.flag_counts["FIN"],
            "rst": stream.flag_counts["RST"],
            "http_requests": len(requests),
        })
        stream.segments.clear()              # free memory

    for frame_no, (proto, info) in frame_updates.items():
        packets.loc[frame_no - 1, ["protocol", "info"]] = [proto, info]

    # ---- hostnames learned from DNS, TLS SNI and HTTP Host -----------------
    hostnames: dict[str, list[str]] = {}
    for source in (dns_names, sni_names, http_hosts):
        for ip, names in source.items():
            hostnames.setdefault(ip, [])
            for n in sorted(names):
                if n not in hostnames[ip]:
                    hostnames[ip].append(n)

    streams_df = pd.DataFrame(stream_rows)
    transactions_df = pd.DataFrame(transactions)
    summary = _build_summary(path.name, packets, streams_df, transactions_df, hostnames)

    return CaptureAnalysis(file_name=path.name, summary=summary, packets=packets,
                           streams=streams_df, transactions=transactions_df,
                           hostnames=hostnames)


def _dns_info(dns, names: dict[str, set[str]]) -> str:
    """Build an info string for a DNS packet and remember IP -> name answers."""
    try:
        qname = dns.qd[0].qname.decode(errors="replace").rstrip(".") if dns.qdcount else ""
    except (AttributeError, IndexError, TypeError):
        qname = ""
    if dns.qr == 0:
        return f"Query {qname}"
    answers = []
    try:
        for rr in dns.an or []:
            if getattr(rr, "type", None) in (1, 28):          # A / AAAA records
                ip = str(rr.rdata)
                names[ip].add(qname or rr.rrname.decode(errors="replace").rstrip("."))
                answers.append(ip)
    except TypeError:
        pass
    return f"Response {qname} → {', '.join(answers) or 'no A/AAAA'}"


def _client_server(stream: TcpStream) -> tuple[tuple[str, int], tuple[str, int]]:
    """
    Decide which side is the client.
    1) the sender of the first SYN (without ACK) is the client;
    2) otherwise (capture started mid-connection) the side with the smaller,
       well-known port is assumed to be the server.
    """
    a, b = stream.endpoint_a, stream.endpoint_b
    if stream.client is not None:
        return (a, b) if stream.client == a else (b, a)
    return (a, b) if a[1] > b[1] else (b, a)


def _make_transaction(tx_id: int, stream_index: int, client, server,
                      req: HttpMessage, resp: HttpMessage | None,
                      start_time: float) -> dict:
    """Flatten one request/response pair into a dictionary (one table row)."""
    split = urlsplit(req.uri or "")
    query_params = {k: v if len(v) > 1 else v[0]
                    for k, v in parse_qs(split.query, keep_blank_values=True).items()}
    form_params = {}
    if "x-www-form-urlencoded" in req.headers.get("content-type", ""):
        form_params = {k: v if len(v) > 1 else v[0] for k, v in
                       parse_qs(req.body.decode("utf-8", errors="replace"),
                                keep_blank_values=True).items()}

    row = {
        "id": tx_id,
        "stream": stream_index,
        "request_frame": req.last_frame,
        "response_frame": resp.last_frame if resp else None,
        "request_time": req.time - start_time,           # seconds from capture start
        "response_time_ms": round((resp.time - req.time) * 1000, 3) if resp else None,
        "method": req.method,
        "host": req.headers.get("host", ""),
        "uri": req.uri,
        "path": split.path,
        "http_version": req.version,
        "client_ip": client[0], "client_port": client[1],
        "server_ip": server[0], "server_port": server[1],
        "status": resp.status if resp else None,
        "reason": resp.reason if resp else "(no response captured)",
        "content_type": resp.headers.get("content-type") if resp else None,
        "content_length": resp.headers.get("content-length") if resp else None,
        "server_header": resp.headers.get("server") if resp else None,
        "user_agent": req.headers.get("user-agent", ""),
        "request_segments": len(req.segment_frames),
        "response_segments": len(resp.segment_frames) if resp else 0,
        "request_segment_frames": req.segment_frames,
        "response_segment_frames": resp.segment_frames if resp else [],
        "query_params": query_params,
        "form_params": form_params,
        "request_headers": req.raw_header,
        "response_headers": resp.raw_header if resp else "",
        "request_body": _body_preview(req.body, req.headers),
        "response_body": _body_preview(resp.body, resp.headers) if resp else "",
        "response_complete": resp.complete if resp else False,
    }
    return row


def _build_summary(file_name: str, packets: pd.DataFrame, streams: pd.DataFrame,
                   transactions: pd.DataFrame, hostnames: dict) -> dict:
    """Capture-level statistics: counts, times, top endpoints, protocols."""
    first, last = packets["time"].iloc[0], packets["time"].iloc[-1]

    # endpoint statistics (an IP counts once as source and once as destination)
    ip_packets = packets[packets["src"].str.contains(r"[.:]", regex=True, na=False)]
    endpoint_stats = pd.concat([
        ip_packets[["src", "length"]].rename(columns={"src": "address"}),
        ip_packets[["dst", "length"]].rename(columns={"dst": "address"}),
    ]).groupby("address")["length"].agg(packets="count", bytes="sum")
    endpoint_stats = endpoint_stats.sort_values("packets", ascending=False)

    top_endpoints = [
        {"address": addr, "packets": int(r.packets), "bytes": int(r.bytes),
         "names": hostnames.get(addr, [])}
        for addr, r in endpoint_stats.head(10).iterrows()
    ]

    # IP-pair conversations
    pairs = ip_packets.assign(pair=[" ↔ ".join(sorted((s, d)))
                                    for s, d in zip(ip_packets["src"], ip_packets["dst"])])
    conversations = (pairs.groupby("pair")["length"].agg(packets="count", bytes="sum")
                     .sort_values("bytes", ascending=False).head(10))

    return {
        "file": file_name,
        "packet_count": int(len(packets)),
        "start": datetime.fromtimestamp(first).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "end": datetime.fromtimestamp(last).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "duration_s": round(last - first, 3),
        "total_bytes": int(packets["length"].sum()),
        "protocols": packets["protocol"].value_counts().to_dict(),
        "top_endpoints": top_endpoints,
        "likely_local_host": top_endpoints[0]["address"] if top_endpoints else None,
        "top_conversations": [
            {"pair": p, "packets": int(r.packets), "bytes": int(r.bytes)}
            for p, r in conversations.iterrows()
        ],
        "tcp_streams": int(len(streams)),
        "http_transactions": int(len(transactions)),
    }


def stream_timeline(analysis: CaptureAnalysis, stream_index: int) -> pd.DataFrame:
    """All packets of one TCP stream, with the direction of each packet."""
    pk = analysis.packets[analysis.packets["tcp_stream"] == stream_index].copy()
    row = analysis.streams[analysis.streams["stream"] == stream_index].iloc[0]
    pk["direction"] = ["client → server" if s == row["client_ip"] and sp == row["client_port"]
                       else "server → client"
                       for s, sp in zip(pk["src"], pk["sport"])]
    return pk[["frame", "rel_time", "direction", "protocol", "tcp_flags",
               "payload_len", "length", "info"]]
