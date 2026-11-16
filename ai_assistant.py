"""
ai_assistant.py
===============
Answers free-text questions about a capture using Google Gemini.

Important design decisions (see README):
1. The model NEVER receives the PCAP file. It receives only a JSON "context"
   that our own code (pcap_analyzer.py) already extracted.
2. Facts that require calculation (slowest request, counts per host/status...)
   are computed by Python and given to the model as "precomputed_facts", so the
   model does not have to do arithmetic over long tables (a source of errors).
3. The model must return JSON with the answer AND the evidence (frames +
   timestamps). Our code then verifies every cited frame against the real
   packet table, so hallucinated evidence is detected and shown to the user.
4. Personal data (emails, phone numbers) can be masked before anything is sent.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

import pandas as pd

from pcap_analyzer import CaptureAnalysis, stream_timeline

# A light "lite" Gemini model, to keep token usage low.
DEFAULT_MODEL = "gemini-3.5-flash-lite"

# Each attempt gives up after this many seconds instead of loading forever.
REQUEST_TIMEOUT_S = 25

# Limits that keep the prompt small enough for the free tier.
MAX_TRANSACTIONS_IN_CONTEXT = 150
MAX_STREAM_PACKETS_IN_CONTEXT = 120
MAX_TLS_STREAMS_IN_CONTEXT = 40
TIMESTAMP_TOLERANCE_S = 0.002   # allowed difference when checking a cited timestamp

SYSTEM_PROMPT = """You are a network-traffic analyst helping a student understand a packet capture.

RULES:
1. Answer ONLY from the JSON context you are given. It was extracted from the capture by
   a parser; you do not have the capture itself. Never invent frames, IPs, hosts or numbers.
2. Prefer the values in "precomputed_facts" over computing things yourself
   (they were calculated exactly by code). If you must count or compare, say so.
3. Times: "request_time_s" / "rel_time" are seconds from the start of the capture.
   "response_time_ms" = time between the request frame and the response frame.
4. Frame numbers are Wireshark frame numbers. HTTP messages that span several TCP segments
   are reported at the frame that completed them (like Wireshark).
5. Every answer must cite evidence: the frame numbers (and their timestamps) that support it.
   Only cite frames that appear in the context.
6. If the context does not contain enough information, say so clearly and set confidence to "low".
7. Answer in the same language as the question (Hebrew question -> Hebrew answer).
   Keep technical terms (HTTP, frame, TCP, status code) in English.

Return ONLY a JSON object with this exact structure:
{
  "answer": "the answer, short and precise (markdown allowed)",
  "evidence": [
    {"frame": <int>, "timestamp_s": <float seconds from capture start or null>,
     "description": "what this frame shows"}
  ],
  "confidence": "high" | "medium" | "low",
  "caveats": "limitations / assumptions, or empty string"
}"""


# ---------------------------------------------------------------------------
# Privacy: masking personal data before sending it to an external service
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"[\w.+-]+(?:@|%40)[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"(?<![\d.])(?:\+972|0)(?:[-\s]?\d){8,9}(?![\d.])")


def mask_personal_data(text: str) -> str:
    """Replace e-mail addresses and phone numbers with placeholders."""
    text = EMAIL_RE.sub("<EMAIL-MASKED>", text)
    return PHONE_RE.sub("<PHONE-MASKED>", text)


# ---------------------------------------------------------------------------
# Building the context
# ---------------------------------------------------------------------------

def _clean(value):
    """Make pandas / numpy values JSON-serialisable (NaN -> None, numpy -> python)."""
    if isinstance(value, float) and pd.isna(value):
        return None
    if hasattr(value, "item"):          # numpy scalar
        return value.item()
    return value


def _transaction_for_context(tx: pd.Series) -> dict:
    """Compact version of one HTTP transaction for the model."""
    return {
        "id": _clean(tx["id"]),
        "tcp_stream": _clean(tx["stream"]),
        "request_frame": _clean(tx["request_frame"]),
        "response_frame": _clean(tx["response_frame"]),
        "request_time_s": round(float(tx["request_time"]), 6),
        "response_time_ms": _clean(tx["response_time_ms"]),
        "method": tx["method"],
        "host": tx["host"],
        "uri": (tx["uri"] or "")[:150],
        "http_version": tx["http_version"],
        "client": f"{tx['client_ip']}:{tx['client_port']}",
        "server": f"{tx['server_ip']}:{tx['server_port']}",
        "status": _clean(tx["status"]),
        "reason": tx["reason"],
        "content_type": _clean(tx["content_type"]),
        "content_length": _clean(tx["content_length"]),
        "server_header": _clean(tx["server_header"]),
        "user_agent": tx["user_agent"],
        "response_tcp_segments": _clean(tx["response_segments"]),
        "response_segment_frames": list(tx["response_segment_frames"]),
        "query_params": tx["query_params"],
        "form_params": tx["form_params"],
        "request_body_preview": (tx["request_body"] or "")[:400],
    }


def compute_facts(analysis: CaptureAnalysis) -> dict:
    """Facts computed exactly by Python, so the model does not have to."""
    tx = analysis.transactions
    if tx.empty:
        return {"note": "No HTTP (clear-text) transactions were found in this capture."}

    answered = tx.dropna(subset=["response_time_ms"])
    facts: dict = {"http_transaction_count": int(len(tx))}

    if not answered.empty:
        slowest = answered.loc[answered["response_time_ms"].idxmax()]
        fastest = answered.loc[answered["response_time_ms"].idxmin()]
        facts["slowest_transaction"] = {
            "id": int(slowest["id"]), "request_frame": int(slowest["request_frame"]),
            "response_frame": int(slowest["response_frame"]),
            "response_time_ms": float(slowest["response_time_ms"]),
            "request": f"{slowest['method']} {slowest['host']}{slowest['path']}"}
        facts["fastest_transaction"] = {
            "id": int(fastest["id"]), "request_frame": int(fastest["request_frame"]),
            "response_frame": int(fastest["response_frame"]),
            "response_time_ms": float(fastest["response_time_ms"]),
            "request": f"{fastest['method']} {fastest['host']}{fastest['path']}"}
        facts["average_response_time_ms"] = round(float(answered["response_time_ms"].mean()), 3)

    facts["status_code_counts"] = {
        str(int(k)): int(v) for k, v in tx["status"].dropna().value_counts().items()}
    facts["requests_per_host"] = {k: int(v) for k, v in tx["host"].value_counts().items()}
    facts["requests_per_method"] = {k: int(v) for k, v in tx["method"].value_counts().items()}
    facts["http_errors"] = [
        {"id": int(r["id"]), "status": int(r["status"]), "request_frame": int(r["request_frame"]),
         "response_frame": int(r["response_frame"]), "request": f"{r['method']} {r['host']}{r['path']}"}
        for _, r in tx[tx["status"] >= 400].iterrows()]
    facts["requests_without_response"] = [
        {"id": int(r["id"]), "request_frame": int(r["request_frame"]),
         "request": f"{r['method']} {r['host']}{r['path']}", "tcp_stream": int(r["stream"])}
        for _, r in tx[tx["response_frame"].isna()].iterrows()]
    return facts


def describe_stream(analysis: CaptureAnalysis, stream_index: int) -> dict:
    """Deterministic description of one TCP stream (used for 'what happened in stream X')."""
    row = analysis.streams[analysis.streams["stream"] == stream_index].iloc[0]
    timeline = stream_timeline(analysis, stream_index)
    flags = timeline["tcp_flags"]

    handshake = (flags.str.fullmatch("SYN").any() and flags.str.fullmatch("SYN, ACK").any())
    events = []
    if handshake:
        events.append("TCP three-way handshake (SYN, SYN-ACK, ACK) was captured")
    else:
        events.append("No complete handshake in the capture (connection started before the capture or was cut)")
    if int(row["fin"]):
        events.append(f"Connection closed with FIN ({int(row['fin'])} FIN packets)")
    if int(row["rst"]):
        rst_frames = timeline[flags.str.contains("RST")]["frame"].tolist()
        events.append(f"Connection reset with RST in frames {rst_frames}")
    if not int(row["fin"]) and not int(row["rst"]):
        events.append("No FIN/RST seen - connection was still open when the capture ended")

    tx = analysis.transactions
    stream_tx = tx[tx["stream"] == stream_index] if not tx.empty else tx

    return {
        "tcp_stream": int(stream_index),
        "client": row["client"], "server": row["server"],
        "application_protocol": row["app_protocol"],
        "tls_server_name_sni": row["sni"],
        "packets": int(row["packets"]), "bytes": int(row["bytes"]),
        "client_payload_bytes": int(row["client_payload_bytes"]),
        "server_payload_bytes": int(row["server_payload_bytes"]),
        "first_frame": int(row["first_frame"]), "last_frame": int(row["last_frame"]),
        "start_s": round(float(row["start_rel"]), 6), "duration_s": round(float(row["duration"]), 6),
        "events": events,
        "http_transaction_ids": [int(i) for i in stream_tx["id"]] if not stream_tx.empty else [],
        "packets_truncated": len(timeline) > MAX_STREAM_PACKETS_IN_CONTEXT,
        "packet_list": [
            {"frame": int(p.frame), "rel_time": round(float(p.rel_time), 6),
             "direction": p.direction, "flags": p.tcp_flags,
             "payload_len": int(p.payload_len), "info": p.info}
            for p in timeline.head(MAX_STREAM_PACKETS_IN_CONTEXT).itertuples()
        ],
    }


def build_context(analysis: CaptureAnalysis, selected_stream: int | None = None,
                  include_facts: bool = True) -> dict:
    """Everything the model is allowed to know about the capture."""
    s = analysis.summary
    tx = analysis.transactions
    streams = analysis.streams

    tls = streams[streams["app_protocol"] == "TLS"] if not streams.empty else streams
    context = {
        "capture_summary": {
            "file": s["file"], "packet_count": s["packet_count"],
            "start_time": s["start"], "end_time": s["end"], "duration_s": s["duration_s"],
            "total_bytes": s["total_bytes"], "protocol_packet_counts": s["protocols"],
            "tcp_stream_count": s["tcp_streams"], "likely_local_host": s["likely_local_host"],
            "top_endpoints": s["top_endpoints"], "top_conversations": s["top_conversations"],
        },
        "http_transactions_truncated": len(tx) > MAX_TRANSACTIONS_IN_CONTEXT,
        "http_transactions": [_transaction_for_context(r)
                              for _, r in tx.head(MAX_TRANSACTIONS_IN_CONTEXT).iterrows()],
        "https_tls_streams": [
            {"tcp_stream": int(r["stream"]), "client": r["client"], "server": r["server"],
             "sni": r["sni"], "packets": int(r["packets"]), "bytes": int(r["bytes"]),
             "first_frame": int(r["first_frame"])}
            for _, r in tls.sort_values("bytes", ascending=False)
                           .head(MAX_TLS_STREAMS_IN_CONTEXT).iterrows()
        ],
    }
    if include_facts:
        context["precomputed_facts"] = compute_facts(analysis)
    if selected_stream is not None:
        context["selected_stream"] = describe_stream(analysis, selected_stream)
    return context


# ---------------------------------------------------------------------------
# Calling Gemini and verifying the answer
# ---------------------------------------------------------------------------

@dataclass
class AiAnswer:
    answer: str
    evidence: list[dict] = field(default_factory=list)
    confidence: str = "low"
    caveats: str = ""
    raw_text: str = ""
    verification: list[dict] = field(default_factory=list)   # filled by verify_evidence
    warnings: list[str] = field(default_factory=list)


def ask_gemini(question: str, context: dict, api_key: str,
               model: str = DEFAULT_MODEL, mask_pii: bool = True) -> AiAnswer:
    """Send the question + extracted context to Gemini and parse the JSON reply."""
    from google import genai               # imported here so the dashboard works without it
    from google.genai import types

    context_json = json.dumps(context, ensure_ascii=False, default=str)
    if mask_pii:
        context_json = mask_personal_data(context_json)

    prompt = (f"CONTEXT (extracted from the capture):\n{context_json}\n\n"
              f"QUESTION:\n{question}")

    client = genai.Client(api_key=api_key,
                          http_options=types.HttpOptions(
                              timeout=REQUEST_TIMEOUT_S * 1000,
                              # Google often answers "503 overloaded" on the free
                              # tier; these fail fast, so retry up to 3 times with
                              # a short pause (1-3 s) before showing an error.
                              retry_options=types.HttpRetryOptions(
                                  attempts=4, initial_delay=1.0, max_delay=3.0)))
    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.0,                       # deterministic, factual answers
            response_mime_type="application/json",
        ),
    )
    return parse_model_reply(response.text or "")


def parse_model_reply(text: str) -> AiAnswer:
    """Parse the JSON returned by the model (robust to ```json fences)."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").removeprefix("json").strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return AiAnswer(answer=text, raw_text=text,
                        warnings=["The model did not return valid JSON; showing raw text."])
    return AiAnswer(
        answer=str(data.get("answer", "")),
        evidence=[e for e in data.get("evidence", []) if isinstance(e, dict)],
        confidence=str(data.get("confidence", "low")).lower(),
        caveats=str(data.get("caveats", "") or ""),
        raw_text=text,
    )


def verify_evidence(result: AiAnswer, analysis: CaptureAnalysis) -> AiAnswer:
    """
    Check every frame the model cited against the real packet table:
    - does the frame exist?
    - does the cited timestamp match the frame's real time?
    Also look for frame numbers mentioned in the answer text but not in evidence.
    """
    packets = analysis.packets.set_index("frame")
    cited = set()

    for ev in result.evidence:
        try:
            frame = int(ev.get("frame"))
        except (TypeError, ValueError):
            result.verification.append({"frame": ev.get("frame"), "status": "❌ invalid frame",
                                        "real_time_s": None, "real_info": ""})
            continue
        cited.add(frame)
        if frame not in packets.index:
            result.verification.append({"frame": frame, "status": "❌ frame does not exist",
                                        "real_time_s": None, "real_info": ""})
            continue
        pkt = packets.loc[frame]
        status = "✅ verified"
        ts = ev.get("timestamp_s")
        if isinstance(ts, (int, float)) and abs(ts - pkt["rel_time"]) > TIMESTAMP_TOLERANCE_S:
            status = f"⚠️ timestamp mismatch (model said {ts})"
        result.verification.append({
            "frame": frame, "status": status,
            "real_time_s": round(float(pkt["rel_time"]), 6),
            "real_info": f"{pkt['protocol']}  {pkt['src']} → {pkt['dst']}  {pkt['info']}",
        })

    mentioned = {int(n) for n in re.findall(r"(?i)frames?\s*#?\s*(\d+)", result.answer)}
    unknown = sorted(n for n in mentioned - cited if n not in packets.index)
    if unknown:
        result.warnings.append(f"The answer mentions frames that do not exist: {unknown}")
    if not result.evidence:
        result.warnings.append("The model gave no evidence - treat the answer as unverified.")
    if any(v["status"].startswith("❌") for v in result.verification):
        result.warnings.append("Some cited evidence is invalid - the answer may be hallucinated.")
        result.confidence = "low"
    return result


def get_api_key() -> str | None:
    """Read the Gemini key from the environment / .env file (never hard-coded)."""
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
