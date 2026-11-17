"""
Tests that compare the automatic analysis with values we found manually in
Wireshark (parts A + B of the assignment). Run with:  python -m pytest -v
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ai_assistant import (build_context, mask_personal_data, parse_model_reply,  # noqa: E402
                          verify_evidence)
from pcap_analyzer import analyze_pcap, parse_tls_sni, reassemble, Segment  # noqa: E402

CAPTURES = ROOT / "captures"


@pytest.fixture(scope="module")
def get_forms():
    """Recording 3: browsing to http://httpbin.org/forms/post."""
    return analyze_pcap(CAPTURES / "הקלטה 3.pcapng")


@pytest.fixture(scope="module")
def recording_1():
    """Recording 1: general browsing (includes large packets)."""
    return analyze_pcap(CAPTURES / "הקלטה 1.pcapng")


@pytest.fixture(scope="module")
def post_form():
    """Recording 4: submitting the form (POST /post), including one failed attempt."""
    return analyze_pcap(CAPTURES / "הקלטה 4.pcapng")


def test_get_request_and_response_frames(get_forms):
    tx = get_forms.transactions.iloc[0]
    assert (tx["method"], tx["host"], tx["uri"]) == ("GET", "httpbin.org", "/forms/post")
    assert tx["request_frame"] == 221
    assert tx["response_frame"] == 228           # Wireshark shows the reassembled response here
    assert tx["status"] == 200
    assert tx["response_segments"] == 2          # part 11: response spans 2 TCP segments
    assert tx["content_type"].startswith("text/html")


def test_favicon_404(get_forms):
    tx = get_forms.transactions.iloc[1]
    assert (tx["uri"], tx["status"], tx["request_frame"], tx["response_frame"]) == \
        ("/favicon.ico", 404, 233, 235)


def test_post_form_parameters(post_form):
    answered = post_form.transactions.dropna(subset=["response_frame"])
    tx = answered[answered["method"] == "POST"].iloc[0]
    assert tx["request_frame"] == 62 and tx["response_frame"] == 65
    assert tx["form_params"]["size"] == "large"
    assert tx["form_params"]["topping"] == ["cheese", "onion"]


def test_post_without_response_is_reported(post_form):
    unanswered = post_form.transactions[post_form.transactions["response_frame"].isna()]
    assert unanswered["request_frame"].tolist() == [34]   # that connection was reset (RST)


def test_reassembly_handles_out_of_order_and_retransmission():
    segs = [Segment(seq=110, payload=b"world", frame=2, time=2.0),   # arrives first
            Segment(seq=100, payload=b"hello12345", frame=3, time=3.0),
            Segment(seq=100, payload=b"hello12345", frame=4, time=4.0)]  # retransmission
    data, chunks = reassemble(segs)
    assert data == b"hello12345world"
    assert [c[2] for c in chunks] == [3, 2]


def test_tls_sni_is_extracted(post_form):
    snis = set(post_form.streams["sni"].dropna())
    assert "translate.googleapis.com" in snis
    assert parse_tls_sni(b"not tls") is None


def test_personal_data_is_masked():
    text = "custemail=student%40gmail.com&custtel=0521234567 mail a@b.com"
    masked = mask_personal_data(text)
    assert "gmail" not in masked and "0521234567" not in masked and "a@b.com" not in masked


def test_context_contains_no_raw_packets(get_forms):
    ctx = build_context(get_forms, selected_stream=23)
    assert ctx["precomputed_facts"]["slowest_transaction"]["request_frame"] == 221
    assert ctx["selected_stream"]["tcp_stream"] == 23


def test_largest_packet_fact(recording_1):
    facts = build_context(recording_1)["precomputed_facts"]
    assert facts["largest_packet"]["frame"] == 7169
    assert facts["largest_packet"]["length_bytes"] == 40078
    assert len(facts["top_5_largest_packets"]) == 5


def test_hallucinated_evidence_is_detected(get_forms):
    reply = ('{"answer": "The slowest was frame 221 (see frame 99999)",'
             ' "evidence": [{"frame": 228, "timestamp_s": 0.0, "description": "x"},'
             '              {"frame": 99999, "timestamp_s": null, "description": "fake"}],'
             ' "confidence": "high", "caveats": ""}')
    result = verify_evidence(parse_model_reply(reply), get_forms)
    statuses = [v["status"] for v in result.verification]
    assert statuses[0].startswith("⚠️")          # wrong timestamp for a real frame
    assert statuses[1].startswith("❌")          # frame does not exist
    assert result.confidence == "low"
