"""
app.py - PCAP Dashboard V1 (Streamlit)
=====================================
Run with:   streamlit run app.py

Layout
------
Sidebar  : choose a capture (from the captures/ folder or upload), AI settings.
Tabs     : Overview | Packets | HTTP Transactions | TCP Streams | Ask AI | Exposure Report
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

import charts
from ai_assistant import (DEFAULT_MODEL, ask_gemini, build_context, describe_stream,
                          get_api_key, mask_personal_data, verify_evidence)
from pcap_analyzer import CaptureAnalysis, analyze_pcap, stream_timeline

load_dotenv(override=True)      # reads GEMINI_API_KEY from .env (re-read on every rerun)
CAPTURES_DIR = Path(__file__).parent / "captures"

st.set_page_config(page_title="PCAP Dashboard", page_icon="📡", layout="wide")


# ---------------------------------------------------------------------------
# Loading (cached, so switching tabs does not re-parse the file)
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Parsing capture…")
def load_from_path(path: str, _mtime: float) -> CaptureAnalysis:
    """Analyse a file from disk. _mtime makes the cache refresh if the file changes."""
    return analyze_pcap(path)


@st.cache_data(show_spinner="Parsing uploaded capture…")
def load_from_bytes(data: bytes, name: str) -> CaptureAnalysis:
    """Analyse an uploaded file (written to a temporary file first)."""
    suffix = Path(name).suffix or ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        analysis = analyze_pcap(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    analysis.file_name = name
    analysis.summary["file"] = name
    return analysis


def format_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("📂 Capture file")
    source = st.radio("Source", ["captures/ folder", "Upload a file"], horizontal=True)
    analysis: CaptureAnalysis | None = None
    try:
        if source == "captures/ folder":
            files = sorted(p for p in CAPTURES_DIR.glob("*") if p.suffix.lower() in (".pcap", ".pcapng", ".cap"))
            if files:
                chosen = st.selectbox("Choose a capture", files, format_func=lambda p: p.name)
                analysis = load_from_path(str(chosen), chosen.stat().st_mtime)
            else:
                st.info("No .pcap / .pcapng files in the captures/ folder.")
        else:
            uploaded = st.file_uploader("PCAP / PCAPNG", type=["pcap", "pcapng", "cap"])
            if uploaded is not None:
                analysis = load_from_bytes(uploaded.getvalue(), uploaded.name)
    except Exception as exc:                     # corrupt / unsupported file
        st.error(f"Could not read the capture: {exc}")

    st.divider()
    st.header("🤖 AI settings")
    api_key = get_api_key()
    if api_key:
        st.success("Gemini API key loaded from .env")
    else:
        api_key = st.text_input("Gemini API key", type="password",
                                help="Not saved anywhere. Better: put GEMINI_API_KEY in a .env file.")
    # A single, fixed model: the lightest one, to keep token usage low.
    model_name = DEFAULT_MODEL
    st.caption(f"Model: `{model_name}` (lightest Gemini model, lowest token usage)")
    mask_pii = st.checkbox("Mask e-mails / phone numbers before sending to the AI", value=True)
    include_facts = st.checkbox("Give the AI pre-computed facts", value=True,
                                help="Exact values computed by Python (slowest request, counts…). "
                                     "Turn off to see how the model does on its own.")

if analysis is None:
    st.title("📡 PCAP Dashboard")
    st.write("Choose or upload a capture file in the sidebar to begin.")
    st.stop()

summary = analysis.summary
packets = analysis.packets
streams = analysis.streams
transactions = analysis.transactions

# ---------------------------------------------------------------------------
# Header metrics (items 24)
# ---------------------------------------------------------------------------

st.title(f"📡 {analysis.file_name}")
c = st.columns(6)
c[0].metric("Packets", f"{summary['packet_count']:,}")
c[1].metric("Duration", f"{summary['duration_s']:.3f} s")
c[2].metric("Total size", format_bytes(summary["total_bytes"]))
c[3].metric("TCP streams", summary["tcp_streams"])
c[4].metric("HTTP transactions", summary["http_transactions"])
c[5].metric("Protocols", len(summary["protocols"]))
st.caption(f"**Start:** {summary['start']}  ·  **End:** {summary['end']}  (local time)")

tabs = st.tabs(["📊 Overview", "📦 Packets", "🌐 HTTP Transactions", "🔗 TCP Streams",
                "🤖 Ask AI", "🔓 Exposure Report"])

# ---------------------------------------------------------------------------
# Tab 1 - Overview (items 25, 26)
# ---------------------------------------------------------------------------

with tabs[0]:
    st.plotly_chart(charts.traffic_over_time(packets), width="stretch")

    left, right = st.columns([1, 1])
    with left:
        st.plotly_chart(charts.protocol_distribution(summary["protocols"]),
                        width="stretch")
    with right:
        st.subheader("Main endpoints")
        st.caption(f"Most active address (probably this computer): "
                   f"**{summary['likely_local_host']}**")
        endpoints = pd.DataFrame(summary["top_endpoints"])
        if not endpoints.empty:
            endpoints["names"] = endpoints["names"].map(lambda n: ", ".join(n[:3]))
            endpoints["bytes"] = endpoints["bytes"].map(format_bytes)
            st.dataframe(endpoints, hide_index=True, width="stretch",
                         column_config={"names": "Known names (DNS / SNI / Host)"})

    st.subheader("Top conversations (IP pairs)")
    conv = pd.DataFrame(summary["top_conversations"])
    if not conv.empty:
        conv["bytes"] = conv["bytes"].map(format_bytes)
        st.dataframe(conv, hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
# Tab 2 - Packet list with interactive filters
# ---------------------------------------------------------------------------

with tabs[1]:
    st.caption("Like Wireshark's display filters: combine protocol, address and port filters.")
    f1, f2, f3 = st.columns([2, 2, 1])
    protocols = f1.multiselect("Protocol", sorted(packets["protocol"].unique()))
    address = f2.text_input("IP address (source or destination contains)")
    port = f3.text_input("Port (source or destination)")

    view = packets
    if protocols:
        view = view[view["protocol"].isin(protocols)]
    if address:
        view = view[view["src"].str.contains(address, regex=False) |
                    view["dst"].str.contains(address, regex=False)]
    if port.strip().isdigit():
        p = int(port)
        view = view[(view["sport"] == p) | (view["dport"] == p)]

    st.write(f"Showing **{len(view):,}** of {len(packets):,} packets")
    st.dataframe(view[["frame", "rel_time", "src", "dst", "protocol", "length", "info"]],
                 hide_index=True, width="stretch", height=500,
                 column_config={"rel_time": st.column_config.NumberColumn("time (s)", format="%.6f")})

# ---------------------------------------------------------------------------
# Tab 3 - HTTP transactions (items 27-29)
# ---------------------------------------------------------------------------

with tabs[2]:
    if transactions.empty:
        st.info("No clear-text HTTP traffic was found in this capture. "
                "(HTTPS traffic is encrypted, so its requests cannot be read.)")
    else:
        st.caption("Each row is a request matched with its response on the same TCP "
                   "connection. Frames are the frames where Wireshark shows the message. "
                   "**Click a row** to see its details.")
        table = transactions[["id", "request_frame", "response_frame", "method", "host", "uri",
                              "client_ip", "client_port", "server_ip", "server_port",
                              "status", "response_time_ms", "stream"]]
        event = st.dataframe(
            table, hide_index=True, width="stretch",
            on_select="rerun", selection_mode="single-row", key="tx_table",
            column_config={
                "response_frame": st.column_config.NumberColumn(format="%d"),
                "status": st.column_config.NumberColumn(format="%d"),
                "response_time_ms": st.column_config.NumberColumn("response time (ms)", format="%.3f"),
                "uri": st.column_config.TextColumn(width="medium"),
            })

        st.plotly_chart(charts.response_times(transactions), width="stretch")

        selected_rows = event.selection.rows
        if selected_rows:
            tx = transactions.iloc[selected_rows[0]]
            st.subheader(f"Transaction #{tx['id']}: {tx['method']} {tx['host']}{tx['path']}")

            d = st.columns(4)
            d[0].metric("Request frame", int(tx["request_frame"]))
            d[1].metric("Response frame",
                        int(tx["response_frame"]) if pd.notna(tx["response_frame"]) else "—")
            d[2].metric("Status", f"{int(tx['status'])} {tx['reason']}"
                        if pd.notna(tx["status"]) else "no response")
            d[3].metric("Response time", f"{tx['response_time_ms']:.3f} ms"
                        if pd.notna(tx["response_time_ms"]) else "—")

            req_col, resp_col = st.columns(2)
            with req_col:
                st.markdown("**➡️ Request (client → server)**")
                st.write(f"`{tx['client_ip']}:{tx['client_port']}` → "
                         f"`{tx['server_ip']}:{tx['server_port']}` · TCP stream {tx['stream']}")
                st.write(f"Version: `{tx['http_version']}` · "
                         f"{tx['request_segments']} TCP segment(s): {tx['request_segment_frames']}")
                st.code(tx["request_headers"], language="http")
                if tx["query_params"]:
                    st.markdown("Parameters in the **URL query string**:")
                    st.json(tx["query_params"])
                if tx["form_params"]:
                    st.markdown("Parameters in the **request body** (form):")
                    st.json(tx["form_params"])
                elif tx["request_body"]:
                    st.markdown("Request body:")
                    st.code(tx["request_body"])
            with resp_col:
                st.markdown("**⬅️ Response (server → client)**")
                if pd.notna(tx["response_frame"]):
                    st.write(f"Content-Type: `{tx['content_type']}` · "
                             f"Content-Length: `{tx['content_length']}` · "
                             f"Server: `{tx['server_header'] or 'not present'}`")
                    st.write(f"Reassembled from **{tx['response_segments']} TCP segment(s)**: "
                             f"frames {tx['response_segment_frames']}")
                    if not tx["response_complete"]:
                        st.warning("The response body was not fully captured.")
                    st.code(tx["response_headers"], language="http")
                    if tx["response_body"]:
                        with st.expander("Response body"):
                            st.code(tx["response_body"])
                else:
                    st.warning("No response was captured for this request "
                               "(see the TCP Streams tab for what happened on the connection).")

# ---------------------------------------------------------------------------
# Tab 4 - TCP streams ("Follow TCP stream" view)
# ---------------------------------------------------------------------------

with tabs[3]:
    if streams.empty:
        st.info("No TCP streams in this capture.")
    else:
        st.caption("Every TCP connection in the capture. Click a row to see its packets.")
        stream_event = st.dataframe(
            streams[["stream", "client", "server", "app_protocol", "sni", "packets", "bytes",
                     "start_rel", "duration", "syn", "fin", "rst", "http_requests"]],
            hide_index=True, width="stretch", height=300,
            on_select="rerun", selection_mode="single-row", key="stream_table",
            column_config={"start_rel": st.column_config.NumberColumn("start (s)", format="%.3f"),
                           "duration": st.column_config.NumberColumn("duration (s)", format="%.3f")})
        if stream_event.selection.rows:
            idx = int(streams.iloc[stream_event.selection.rows[0]]["stream"])
            st.session_state["ai_stream"] = idx          # pre-select it in the AI tab
            info = describe_stream(analysis, idx)
            st.subheader(f"TCP stream {idx}: {info['client']} → {info['server']}")
            for event_text in info["events"]:
                st.write("• " + event_text)
            st.dataframe(stream_timeline(analysis, idx), hide_index=True,
                         width="stretch",
                         column_config={"rel_time": st.column_config.NumberColumn("time (s)", format="%.6f")})

# ---------------------------------------------------------------------------
# Tab 5 - Ask AI (items 30-34)
# ---------------------------------------------------------------------------

HEBREW_LETTER = re.compile(r"[֐-׿]")
LATIN_LETTER = re.compile(r"[A-Za-z]")

# The question box picks its direction from the first letter typed
# (unicode-bidi: plaintext), so Hebrew is typed right-to-left immediately.
st.markdown("""<style>
[data-testid="stChatInput"] textarea { unicode-bidi: plaintext; text-align: start; }
</style>""", unsafe_allow_html=True)


def is_rtl(text: str) -> bool:
    """
    True when the text is mainly Hebrew. Hebrew answers contain many English
    technical terms (GET, frame, httpbin.org...), so Hebrew only needs to be
    at least half as frequent as Latin letters to count as a Hebrew text.
    """
    hebrew = len(HEBREW_LETTER.findall(text))
    latin = len(LATIN_LETTER.findall(text))
    return hebrew > 0 and hebrew >= latin * 0.5


def show_text(text: str) -> None:
    """Markdown that is right-aligned and right-to-left when the text is Hebrew."""
    if is_rtl(text):
        # blank lines around the text keep markdown (bold, `code`, lists) working
        st.markdown(f'<div dir="rtl" style="text-align: right">\n\n{text}\n\n</div>',
                    unsafe_allow_html=True)
    else:
        st.markdown(text)


STREAM_IN_QUESTION = re.compile(r"(?i)(?:stream|סטרים|זרם)\s*#?\s*(\d+)")


def stream_for_question(text: str) -> int | None:
    """
    Which TCP stream the question is about:
    1) a stream number written in the question ("stream 23" / "סטרים 23"), or
    2) the row selected in the TCP Streams tab.
    """
    known = set(streams["stream"]) if not streams.empty else set()
    match = STREAM_IN_QUESTION.search(text)
    if match and int(match.group(1)) in known:
        return int(match.group(1))
    selected = st.session_state.get("ai_stream")
    return selected if selected in known else None    # may be left from another capture


with tabs[4]:
    # st.chat_input enables its send button while typing (no need to click outside
    # the box) and sends on Enter.
    question = st.chat_input("Ask anything about this capture (any language)…")

    if question:
        selected_stream = stream_for_question(question)
        context = build_context(analysis, selected_stream, include_facts)
        if not api_key:
            st.error("Add a Gemini API key in the sidebar or in the .env file.")
        else:
            try:
                with st.spinner("Asking Gemini…"):
                    result = ask_gemini(question, context, api_key, model_name, mask_pii)
                result = verify_evidence(result, analysis)
                st.session_state.setdefault("history", []).insert(
                    0, (question, result, selected_stream))
            except Exception as exc:
                message = str(exc)
                if "429" in message or "RESOURCE_EXHAUSTED" in message:
                    st.error("Gemini free-tier rate limit reached — wait a minute and try again.")
                elif "503" in message or "UNAVAILABLE" in message:
                    st.error("Gemini is temporarily overloaded (error 503, on Google's side). "
                             "Wait a few seconds and send the question again.")
                elif "404" in message or "not found" in message.lower():
                    st.error(f"Model '{model_name}' is not available for this API key. "
                             "Change DEFAULT_MODEL in ai_assistant.py.")
                else:
                    st.error(f"AI request failed: {message}")

    badge = {"high": "🟢 high", "medium": "🟡 medium", "low": "🔴 low"}
    for q, result, used_stream in st.session_state.get("history", []):
        with st.container(border=True):
            show_text(f"**❓ {q}**")
            show_text(result.answer)
            stream_note = f" · included details of TCP stream {used_stream}" \
                if used_stream is not None else ""
            st.caption(f"Model confidence: {badge.get(result.confidence, result.confidence)}"
                       f"{stream_note}")
            for warning in result.warnings:
                st.warning(warning)
            if result.caveats:
                show_text(f"ℹ️ *{result.caveats}*")
            if result.verification:
                st.markdown("**Evidence (verified against the capture):**")
                ev = pd.DataFrame(result.verification)
                ev.insert(2, "model_says", [e.get("description", "") for e in result.evidence][:len(ev)])
                st.dataframe(ev, hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
# Tab 6 - Exposure report (creative feature)
# ---------------------------------------------------------------------------

with tabs[5]:
    st.markdown("### What could an eavesdropper on this network learn?")
    st.caption("Compares what is readable in clear-text HTTP with what is still visible "
               "in encrypted HTTPS traffic (the topic of parts 19–22).")

    http_streams = set(streams.loc[streams["app_protocol"] == "HTTP", "stream"]) \
        if not streams.empty else set()
    st.plotly_chart(charts.encrypted_vs_plain(packets, http_streams), width="stretch")

    left, right = st.columns(2)
    with left:
        st.markdown("#### 🔓 Readable in clear-text HTTP")
        if transactions.empty:
            st.success("No clear-text HTTP requests — page contents and form data were not exposed.")
        else:
            exposed = []
            for _, tx in transactions.iterrows():
                for kind, params in (("form field", tx["form_params"]),
                                     ("URL parameter", tx["query_params"])):
                    for name, value in params.items():
                        exposed.append({"frame": tx["request_frame"], "what": f"{kind}: {name}",
                                        "value": mask_personal_data(str(value))})
                exposed.append({"frame": tx["request_frame"], "what": "full URL",
                                "value": f"http://{tx['host']}{tx['uri']}"[:120]})
                if tx["user_agent"]:
                    exposed.append({"frame": tx["request_frame"], "what": "browser (User-Agent)",
                                    "value": tx["user_agent"][:120]})
                if "cookie:" in tx["request_headers"].lower():
                    exposed.append({"frame": tx["request_frame"], "what": "cookie header",
                                    "value": "(session cookie sent in clear text)"})
            sensitive = sum(1 for e in exposed if e["what"].startswith(("form", "URL")))
            if sensitive:
                st.error(f"⚠️ {sensitive} form/URL values were sent without encryption. "
                         "Anyone on the network path could read them.")
            st.dataframe(pd.DataFrame(exposed), hide_index=True, width="stretch")

    with right:
        st.markdown("#### 🔒 Still visible in encrypted HTTPS")
        tls = streams[streams["app_protocol"] == "TLS"] if not streams.empty else streams
        if tls.empty:
            st.info("No TLS connections in this capture.")
        else:
            st.write("Contents are encrypted, but these are still visible: "
                     "**IP addresses, ports, timing, sizes, and the site name (SNI)** "
                     "sent in clear text in the TLS Client Hello.")
            sites = (tls.groupby(tls["sni"].fillna("(no SNI seen)"))
                     .agg(connections=("stream", "count"), bytes=("bytes", "sum"),
                          first_frame=("first_frame", "min"))
                     .sort_values("bytes", ascending=False).reset_index())
            sites["bytes"] = sites["bytes"].map(format_bytes)
            st.dataframe(sites, hide_index=True, width="stretch")

    problems = transactions[transactions["status"].isna() | (transactions["status"] >= 400)] \
        if not transactions.empty else transactions
    if not problems.empty:
        st.markdown("#### 🚨 HTTP problems")
        st.dataframe(problems[["id", "request_frame", "response_frame", "method", "host",
                               "path", "status", "reason"]],
                     hide_index=True, width="stretch")
