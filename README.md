# PCAP Dashboard V1

A Python tool that takes a PCAP / PCAPNG file, extracts the data itself (packets, TCP streams, HTTP transactions),
displays it in a dashboard, and lets you ask free-form questions about it using Gemini. Every AI answer comes with
evidence (frames and timestamps), and the system **automatically verifies** that evidence against the actual packets.

## Installation

Requires Python 3.10 or later.

```bash
git clone https://github.com/bnayaamitay/pcap-dashboard.git
cd pcap-dashboard
python -m venv .venv
.venv\Scripts\activate          # Windows   (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
```

## Gemini API key

The Ask AI tab needs a Gemini API key (the rest of the dashboard works without it).

1. Create a free key in Google AI Studio: https://aistudio.google.com/apikey (sign in with a Google account → **Create API key**).
2. Copy the example file to `.env`:
   ```bash
   copy .env.example .env          # Windows   (Linux/Mac: cp .env.example .env)
   ```
3. Open `.env` and replace `your-api-key-here` with your key:
   ```
   GEMINI_API_KEY=your-api-key-here
   ```

`.env` is listed in `.gitignore`, so the key is never committed. If there is no `.env`, you can also paste the key into the sidebar field; it is used only for the current session and not saved.

## Running

```bash
streamlit run app.py
```
The browser opens at http://localhost:8501. In the sidebar, pick a recording from the `captures/` folder or upload a file.

Automated tests (compared against values we found manually in Wireshark):
```bash
python -m pytest -v
```

## Project structure

| File | Purpose |
|---|---|
| `pcap_analyzer.py` | Reading the capture, TCP reassembly, HTTP parsing, request↔response matching, TLS SNI extraction |
| `ai_assistant.py` | Building the AI context, the prompt, calling Gemini, and verifying the evidence |
| `charts.py` | Charts (Plotly) |
| `app.py` | Dashboard UI (Streamlit) |
| `tests/test_analyzer.py` | Tests against the results of the manual part |
| `captures/` | The capture files we used |

## What the dashboard shows

| Tab | Content |
|---|---|
| Header | Packet count, start/end time, duration, size |
| Overview | Traffic volume over time, protocol distribution, top endpoints and conversations |
| Packets | Packet list with filtering by protocol / IP / port |
| HTTP Transactions | Every request with its response: method, host, URI, addresses, ports, status, response time, frames. Clicking a row shows headers, parameters, and the number of TCP segments |
| TCP Streams | Every TCP connection; selecting a stream shows all its packets and a description (handshake / FIN / RST) |
| Ask AI | Free-form question, answer, confidence level, and verified evidence |
| Exposure Report | What an eavesdropper can see: data sent over plain HTTP versus what is visible even over HTTPS (IPs, sizes, SNI) |

## How the AI part works

1. **The AI does not receive the PCAP file.** Our code extracts the data and sends only structured JSON: a capture summary, the transactions table, TLS connections, and the selected stream. The stream attached to a question is determined by a number written in the question ("stream 23") or by the row selected in the TCP Streams tab.
2. **Precomputed facts** (`precomputed_facts`): the slowest request, status code counts, requests per host, and more are computed in Python, so the model doesn't need to do calculations over long tables.
3. **Structured output**: the model returns JSON with `answer`, `evidence`, `confidence`, and `caveats`.
4. **Evidence verification**: for every frame the model cites, we check that it exists and that the timestamp matches. ✅ / ⚠️ / ❌ are shown, and if any evidence is wrong the confidence drops to low.
5. **Model**: `gemini-3.5-flash-lite`, a lightweight "lite" model that is economical with tokens. If Google is overloaded (error 503), the request is automatically retried up to 3 times, and each attempt is limited to 25 seconds (configured via `DEFAULT_MODEL` in `ai_assistant.py`).
6. **Privacy**: email addresses and phone numbers are masked before sending (can be turned off in the sidebar).

## Technical notes
- Frame numbers match the No. column in Wireshark (starting at 1).
- An HTTP message split across several TCP segments is reported at the frame that completed it, as in Wireshark. Out-of-order segments and retransmissions are handled.
- Response time = the time between the request frame and the response frame (like `http.time` in Wireshark).
- Requests are matched to responses by order within the same TCP connection (this is how HTTP/1.1 works).
