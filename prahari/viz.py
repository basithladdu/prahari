"""Draw the boot as a sequence, with findings marked.

The whole argument of this project is that boot integrity is a property of the
*order* of events, not of any single hash. So the picture is the sequence
itself: every measurement in the order the kernel made it, anomalies in red.

plotly does the drawing.
"""
import plotly.graph_objects as go

from . import tokens

COLOURS = {"ok": "#94a3b8", "sequence": "#f59e0b",
           "unknown": "#ef4444", "tampered": "#dc2626"}


def timeline(events, findings=(), out="boot.html"):
    marks = {}
    for f in findings:
        # a tampered/unknown finding outranks a sequence one at the same index
        if f.kind != "sequence" or f.position not in marks:
            marks[f.position] = f
    labels = tokens.sequence(events)

    fig = go.Figure()
    for kind in COLOURS:
        idx = [i for i in range(len(labels))
               if (marks[i].kind if i in marks else "ok") == kind]
        if not idx:
            continue
        fig.add_trace(go.Scatter(
            x=idx, y=[0] * len(idx), mode="markers", name=kind,
            marker=dict(size=14 if kind != "ok" else 8, color=COLOURS[kind],
                        symbol="x" if kind != "ok" else "circle"),
            text=[f"{i}: {labels[i]}" + (f"<br>{marks[i].detail}" if i in marks else "")
                  for i in idx],
            hoverinfo="text"))

    fig.update_layout(
        title=f"Boot sequence — {len(events)} measurements, {len(marks)} flagged",
        xaxis_title="measurement order", yaxis=dict(visible=False),
        height=280, hovermode="closest")
    fig.write_html(out)
    return out
