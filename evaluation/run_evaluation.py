"""
Runs questions whose answers we already know (from the manual Wireshark part)
through the AI assistant, with and without the pre-computed facts, and saves
the answers + evidence verification to evaluation/results.json.

Usage:  python evaluation/run_evaluation.py [model-name]
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8")

from dotenv import load_dotenv  # noqa: E402

from ai_assistant import (DEFAULT_MODEL, ask_gemini, build_context, get_api_key,  # noqa: E402
                          verify_evidence)
from pcap_analyzer import analyze_pcap  # noqa: E402

load_dotenv(ROOT / ".env", override=True)
MODEL = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL

# (capture, selected stream, question, expected answer from the manual part)
CASES = [
    ("הקלטה 3.pcapng", None, "Which HTTP request was the slowest?",
     "GET /forms/post: request frame 221, response frame 228, ~141.05 ms"),
    ("הקלטה 3.pcapng", None, "Which status codes were returned?",
     "200 OK (frame 228) and 404 Not Found for /favicon.ico (frame 235)"),
    ("הקלטה 3.pcapng", None, "How many requests were sent to httpbin.org?", "2 (frames 221, 233)"),
    ("הקלטה 3.pcapng", None,
     "In which frame is the response to GET /forms/post and how many TCP segments was it built from?",
     "frame 228, 2 segments (frames 227 + 228)"),
    ("הקלטה 3.pcapng", 23, "What happened in the selected stream?",
     "stream 23: 2 GET requests (221, 233) -> 200 (228) and 404 (235)"),
    ("הקלטה 4.pcapng", None, "אילו פרמטרים נשלחו בטופס ואיפה הם מופיעים?",
     "form fields custname, custtel, custemail, size, topping, delivery, comments in the POST body (frame 62 / 34)"),
    ("הקלטה 4.pcapng", None, "Did every POST request get a response?",
     "No - POST in frame 34 (stream 9) got no response (RST, frame 46); POST in frame 62 got 200 in frame 65"),
    ("הקלטה 1.pcapng", None, "Which HTTP request was the slowest and how long did it take?",
     "GET www.msftconnecttest.com/connecttest.txt: frames 242 -> 383, 548.684 ms"),
    ("הקלטה 1.pcapng", None, "What is the average HTTP response time?",
     "(68.056+94.966+6.045+131.471+548.684)/5 = 169.844 ms"),
]


def main():
    api_key = get_api_key()
    analyses = {}
    results = []
    for capture, stream, question, expected in CASES:
        if capture not in analyses:
            analyses[capture] = analyze_pcap(ROOT / "captures" / capture)
        analysis = analyses[capture]
        for with_facts in (True, False):
            context = build_context(analysis, stream, include_facts=with_facts)
            for attempt in range(3):
                try:
                    answer = verify_evidence(ask_gemini(question, context, api_key, MODEL), analysis)
                    break
                except Exception as exc:          # rate limit -> wait and retry
                    print("  retry:", str(exc)[:120])
                    time.sleep(30)
            else:
                continue
            row = {"capture": capture, "stream": stream, "question": question,
                   "expected": expected, "with_facts": with_facts, "model": MODEL,
                   "answer": answer.answer, "confidence": answer.confidence,
                   "evidence": answer.verification, "warnings": answer.warnings}
            results.append(row)
            print(f"\n[{capture} | facts={with_facts}] {question}\n  expected: {expected}\n"
                  f"  answer:   {answer.answer}\n  evidence: "
                  f"{[(v['frame'], v['status']) for v in answer.verification]}  {answer.warnings}")
            time.sleep(4)                         # stay inside the free-tier rate limit

    out = ROOT / "evaluation" / f"results_{MODEL}.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print("\nsaved", out)


if __name__ == "__main__":
    main()
