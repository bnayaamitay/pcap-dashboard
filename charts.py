"""
charts.py
=========
Plotly charts used by the dashboard. All charts read only from the data frames
produced by pcap_analyzer.py.
"""

from __future__ import annotations

import math

import pandas as pd
import plotly.graph_objects as go

# A small, colour-blind-safe palette. One hue is used for "normal" data;
# red is reserved for problems (errors / missing responses) and is always
# paired with a text label, so colour is never the only signal.
COLOR_MAIN = "#2a78d6"
COLOR_SECOND = "#eb6834"
COLOR_PROBLEM = "#e34948"

BASE_LAYOUT = dict(
    margin=dict(l=10, r=10, t=40, b=10),
    hoverlabel=dict(font_size=13),
    height=340,
)


def _nice_bin_size(duration: float, target_bins: int = 80) -> float:
    """Pick a round bin size (0.1, 0.2, 0.5, 1, 2, 5 ... seconds) for ~target_bins bins."""
    raw = max(duration / target_bins, 0.001)
    magnitude = 10 ** math.floor(math.log10(raw))
    for step in (1, 2, 5, 10):
        if raw <= step * magnitude:
            return step * magnitude
    return 10 * magnitude


def traffic_over_time(packets: pd.DataFrame) -> go.Figure:
    """Bytes per time bin across the capture (an area chart, one series)."""
    duration = float(packets["rel_time"].max())
    bin_size = _nice_bin_size(duration)
    bins = (packets["rel_time"] // bin_size) * bin_size
    volume = packets.groupby(bins).agg(bytes=("length", "sum"), packets=("frame", "count"))
    # include empty bins so quiet periods are visible as zero
    full_index = pd.Index([i * bin_size for i in range(int(duration // bin_size) + 1)])
    volume = volume.reindex(full_index, fill_value=0)

    fig = go.Figure(go.Scatter(
        x=volume.index, y=volume["bytes"], mode="lines", fill="tozeroy",
        line=dict(color=COLOR_MAIN, width=2),
        customdata=volume["packets"],
        hovertemplate=("t = %{x:.2f}s<br>%{y:,} bytes<br>%{customdata} packets"
                       "<extra></extra>"),
    ))
    fig.update_layout(title=f"Traffic volume over time (bytes per {bin_size:g}s)",
                      xaxis_title="Seconds from capture start", yaxis_title="Bytes",
                      hovermode="x", **BASE_LAYOUT)
    return fig


def protocol_distribution(protocol_counts: dict, top_n: int = 10) -> go.Figure:
    """Horizontal bar chart of packets per protocol (largest first)."""
    counts = pd.Series(protocol_counts).sort_values(ascending=False)
    if len(counts) > top_n:                       # fold the tail into "Other"
        counts = pd.concat([counts.head(top_n),
                            pd.Series({"Other": counts.iloc[top_n:].sum()})])
    counts = counts[::-1]                         # largest on top
    total = counts.sum()
    fig = go.Figure(go.Bar(
        x=counts.values, y=counts.index, orientation="h",
        marker=dict(color=COLOR_MAIN, cornerradius=4),
        text=[f"{v:,} ({v / total:.0%})" for v in counts.values], textposition="outside",
        cliponaxis=False,
        hovertemplate="%{y}: %{x:,} packets<extra></extra>",
    ))
    fig.update_layout(title="Packets per protocol", xaxis_title="Packets",
                      **{**BASE_LAYOUT, "height": max(260, 32 * len(counts) + 80)})
    return fig


def response_times(transactions: pd.DataFrame) -> go.Figure:
    """One bar per HTTP transaction; errors and missing responses are flagged."""
    tx = transactions.copy()
    tx["label"] = [f"#{i} {m} {h}{(p or '')[:30]}"
                   for i, m, h, p in zip(tx["id"], tx["method"], tx["host"], tx["path"])]
    tx["is_problem"] = tx["status"].isna() | (tx["status"] >= 400)
    tx["value"] = tx["response_time_ms"].fillna(0)
    tx["note"] = [("no response" if pd.isna(s) else f"{int(s)}")
                  for s in tx["status"]]

    fig = go.Figure(go.Bar(
        x=tx["value"], y=tx["label"], orientation="h",
        marker=dict(color=[COLOR_PROBLEM if p else COLOR_MAIN for p in tx["is_problem"]],
                    cornerradius=4),
        text=[f"{v:.1f} ms · {n}" if v else n for v, n in zip(tx["value"], tx["note"])],
        textposition="outside", cliponaxis=False,
        customdata=tx[["request_frame", "response_frame"]].fillna(-1).astype(int),
        hovertemplate=("%{y}<br>%{x:.3f} ms<br>request frame %{customdata[0]}, "
                       "response frame %{customdata[1]}<extra></extra>"),
    ))
    fig.update_layout(title="HTTP response time per transaction (red = error / no response)",
                      xaxis_title="Response time (ms)",
                      yaxis=dict(autorange="reversed"),
                      **{**BASE_LAYOUT, "height": max(260, 30 * len(tx) + 90)})
    return fig


def encrypted_vs_plain(packets: pd.DataFrame, http_streams: set[int]) -> go.Figure:
    """Share of bytes that were encrypted (TLS/QUIC) vs. readable (HTTP) vs. other."""
    def category(row) -> str:
        if row.protocol in ("TLS", "QUIC"):
            return "Encrypted (TLS / QUIC)"
        # every packet with payload in an HTTP stream is readable, not only the
        # frame where Wireshark shows the HTTP message
        if row.protocol == "HTTP" or (row.tcp_stream in http_streams and row.payload_len > 0):
            return "Clear-text HTTP"
        return "Other (TCP control, DNS, ARP, ...)"

    categories = [category(r) for r in packets[["protocol", "tcp_stream", "payload_len"]]
                  .itertuples()]
    share = packets.groupby(categories)["length"].sum()
    order = ["Encrypted (TLS / QUIC)", "Clear-text HTTP", "Other (TCP control, DNS, ARP, ...)"]
    share = share.reindex(order, fill_value=0)
    total = share.sum() or 1
    fig = go.Figure(go.Bar(
        x=share.values, y=share.index, orientation="h",
        marker=dict(color=[COLOR_MAIN, COLOR_SECOND, "#8a8984"], cornerradius=4),
        text=[f"{v:,} B ({v / total:.0%})" for v in share.values],
        textposition="outside", cliponaxis=False,
        hovertemplate="%{y}: %{x:,} bytes<extra></extra>",
    ))
    fig.update_layout(title="Bytes by visibility to an eavesdropper",
                      xaxis_title="Bytes", yaxis=dict(autorange="reversed"),
                      **{**BASE_LAYOUT, "height": 230})
    return fig
