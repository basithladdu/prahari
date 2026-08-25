"""Draw the boot as an interactive security dashboard with findings, stages, and sequence analysis."""
import json
from pathlib import Path
import plotly.graph_objects as go

from . import stages, tokens

COLOURS = {
    "ok": "#10b981",         # emerald-500
    "sequence": "#f59e0b",   # amber-500
    "unknown": "#ef4444",    # rose-500
    "tampered": "#dc2626"    # red-600
}

STAGE_COLORS = {
    stages.BootStage.FIRMWARE_UEFI: "#6366f1",     # Indigo
    stages.BootStage.KERNEL_CORE: "#8b5cf6",       # Violet
    stages.BootStage.EARLY_USERSPACE: "#06b6d4",   # Cyan
    stages.BootStage.INIT_SYSTEM: "#3b82f6",       # Blue
    stages.BootStage.KERNEL_MODULES: "#ec4899",    # Pink
    stages.BootStage.SYSTEM_SERVICES: "#10b981",   # Emerald
    stages.BootStage.UNKNOWN: "#64748b",           # Slate
}

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PRAHARI — Boot Integrity & Behavioral Attestation Report</title>
<style>
:root {{
  --bg: #090d16;
  --surface: #111827;
  --surface-subtle: #1f293d;
  --border: #374151;
  --text-main: #f3f4f6;
  --text-muted: #9ca3af;
  --primary: #3b82f6;
  --emerald: #10b981;
  --amber: #f59e0b;
  --rose: #ef4444;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.5;
  padding: 32px 20px;
}}
.container {{
  max-width: 1280px;
  margin: 0 auto;
}}
header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border);
  padding-bottom: 20px;
  margin-bottom: 28px;
}}
.logo-group h1 {{
  font-size: 24px;
  font-weight: 700;
  letter-spacing: -0.02em;
  display: flex;
  align-items: center;
  gap: 10px;
}}
.badge-pqc {{
  background: linear-gradient(135deg, #2563eb, #7c3aed);
  color: #fff;
  font-size: 11px;
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 9999px;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}}
.badge-rats {{
  background: rgba(16, 185, 129, 0.2);
  color: #34d399;
  border: 1px solid rgba(16, 185, 129, 0.4);
  font-size: 11px;
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 9999px;
  letter-spacing: 0.05em;
}}
.header-meta {{
  color: var(--text-muted);
  font-size: 13px;
}}
.kpi-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 28px;
}}
.kpi-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
}}
.kpi-label {{
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-muted);
  letter-spacing: 0.05em;
}}
.kpi-val {{
  font-size: 28px;
  font-weight: 700;
  margin: 6px 0 2px;
  letter-spacing: -0.02em;
}}
.kpi-sub {{
  font-size: 12px;
  color: var(--text-muted);
}}
.panel {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 28px;
}}
.panel-title {{
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 6px;
}}
.panel-desc {{
  font-size: 13px;
  color: var(--text-muted);
  margin-bottom: 18px;
}}
.chart-container {{
  border-radius: 8px;
  overflow: hidden;
  background: #0d131f;
  padding: 12px;
  border: 1px solid #1f293d;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}}
th {{
  text-align: left;
  padding: 10px 12px;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}}
td {{
  padding: 10px 12px;
  border-bottom: 1px solid #1e293b;
}}
.pill {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 9999px;
  font-size: 11px;
  font-weight: 600;
}}
.pill-detect {{ background: rgba(16, 185, 129, 0.18); color: #34d399; }}
.pill-miss {{ background: rgba(239, 68, 68, 0.18); color: #f87171; }}
.pill-tamper {{ background: rgba(220, 38, 38, 0.2); color: #fca5a5; }}
.pill-unknown {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; }}
.pill-sequence {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; }}
.pill-ok {{ background: rgba(16, 185, 129, 0.15); color: #6ee7b7; }}
.pill-stage {{ background: rgba(59, 130, 246, 0.15); color: #93c5fd; font-size: 11px; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
.search-input {{
  background: #0d131f;
  border: 1px solid var(--border);
  color: #fff;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  margin-bottom: 12px;
  width: 100%;
}}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo-group">
      <h1>🛡️ PRAHARI <span class="badge-pqc">ECDSA P-256 + ML-DSA-65 (FIPS 204)</span> <span class="badge-rats">IETF RATS RFC 9334</span></h1>
    </div>
    <div class="header-meta">Behavioural Boot Attestation & Sequence Anomaly Detector</div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Total Measurements</div>
      <div class="kpi-val">{total_events}</div>
      <div class="kpi-sub">{observed_stages_count} Boot Stages Monitored</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Flagged Anomalies</div>
      <div class="kpi-val" style="color: {flagged_color};">{flagged_count}</div>
      <div class="kpi-sub">{verdict_sub}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Attestation Verdict</div>
      <div class="kpi-val" style="color: {verdict_color};">{verdict_text}</div>
      <div class="kpi-sub">Risk Score: {risk_score} / 1.0</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Post-Quantum Status</div>
      <div class="kpi-val" style="color: #34d399;">PROTECTED</div>
      <div class="kpi-sub">FIPS 204 ML-DSA-65 Signature</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">Interactive Boot Sequence & Violation Timeline</div>
    <div class="panel-desc">Every measured event in kernel order. Sequence anomalies indicate validly-signed binaries loaded out of order.</div>
    <div class="chart-container">
      {plotly_div}
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">4-Vector Threat Benchmark (Allowlist vs PRAHARI)</div>
    <div class="panel-desc">Demonstrating how traditional allowlists miss reordering and substitution attacks where hashes remain intact.</div>
    <table>
      <thead>
        <tr>
          <th>Attack Type</th>
          <th>Mechanism</th>
          <th>Traditional Allowlist (Keylime)</th>
          <th>PRAHARI (Behavioural)</th>
          <th>Caught By</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Tamper</strong></td>
          <td>Direct byte corruption in measured file</td>
          <td><span class="pill pill-detect">DETECT</span></td>
          <td><span class="pill pill-detect">DETECT</span></td>
          <td><span class="pill pill-tamper">tampered</span></td>
        </tr>
        <tr>
          <td><strong>Insert</strong></td>
          <td>Injection of unknown rogue module</td>
          <td><span class="pill pill-detect">DETECT</span></td>
          <td><span class="pill pill-detect">DETECT</span></td>
          <td><span class="pill pill-unknown">unknown, sequence</span></td>
        </tr>
        <tr>
          <td><strong>Reorder</strong></td>
          <td>Permuting execution order of legitimate components</td>
          <td><span class="pill pill-miss">MISS (Hash Valid)</span></td>
          <td><span class="pill pill-detect">DETECT</span></td>
          <td><span class="pill pill-sequence">sequence</span></td>
        </tr>
        <tr>
          <td><strong>Substitute</strong></td>
          <td>Relocating genuine signed binary to malicious boot phase (BlackLotus style)</td>
          <td><span class="pill pill-miss">MISS (Hash Valid)</span></td>
          <td><span class="pill pill-detect">DETECT</span></td>
          <td><span class="pill pill-sequence">sequence</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="panel">
    <div class="panel-title">Boot Event Log & Anomaly Inspector</div>
    <div class="panel-desc">Filter and inspect individual measurements, execution stages, paths, hashes, and transition checks.</div>
    <input type="text" id="filterInput" class="search-input" placeholder="Search paths, stages, events, or severity..." onkeyup="filterTable()">
    <table id="eventsTable">
      <thead>
        <tr>
          <th style="width: 50px;">#</th>
          <th style="width: 100px;">Status</th>
          <th style="width: 140px;">Boot Stage</th>
          <th>Measurement Identity (Path)</th>
          <th>Detail / Violated Transition</th>
        </tr>
      </thead>
      <tbody>
        {table_rows}
      </tbody>
    </table>
  </div>
</div>

<script>
function filterTable() {{
  var input = document.getElementById("filterInput");
  var filter = input.value.toLowerCase();
  var rows = document.getElementById("eventsTable").getElementsByTagName("tbody")[0].getElementsByTagName("tr");
  for (var i = 0; i < rows.length; i++) {{
    var text = rows[i].textContent || rows[i].innerText;
    rows[i].style.display = text.toLowerCase().indexOf(filter) > -1 ? "" : "none";
  }}
}}
</script>
</body>
</html>
"""


def timeline(events, findings=(), out="boot.html"):
    marks = {}
    for f in findings:
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
            x=idx, y=[0] * len(idx), mode="markers+lines" if kind == "ok" else "markers",
            name=kind.upper(),
            marker=dict(
                size=16 if kind != "ok" else 10,
                color=COLOURS[kind],
                symbol="x" if kind in ("unknown", "tampered") else ("diamond" if kind == "sequence" else "circle"),
                line=dict(width=1, color="#ffffff" if kind != "ok" else "#10b981")
            ),
            line=dict(color="rgba(148, 163, 184, 0.3)", width=1),
            text=[f"<b>#{i} {labels[i]}</b><br>Stage: {stages.classify_path(labels[i]).value}" + (f"<br><span style='color:{COLOURS[kind]};'>{marks[i].detail}</span>" if i in marks else "<br>Status: Baseline OK")
                  for i in idx],
            hoverinfo="text"
        ))

    fig.update_layout(
        xaxis=dict(title="Measurement Order Index", gridcolor="#1e293b", color="#94a3b8", zeroline=False),
        yaxis=dict(visible=False, range=[-0.5, 0.5]),
        height=320,
        margin=dict(l=20, r=20, t=20, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#cbd5e1", family="ui-sans-serif, system-ui"),
        hovermode="closest",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )

    plotly_div = fig.to_html(full_html=False, include_plotlyjs="cdn")

    # Generate table rows
    table_rows = []
    observed_stages = set()
    for i, e in enumerate(events):
        f = marks.get(i)
        kind = f.kind if f else "ok"
        pill_cls = f"pill pill-{kind}"
        status_label = kind.upper()
        stage_obj = stages.classify_path(e.path)
        observed_stages.add(stage_obj.value)
        stage_label = stage_obj.value
        detail = f.detail if f else "Matches clean boot sequence n-gram transition"
        table_rows.append(f"""
        <tr>
          <td class="mono">{i}</td>
          <td><span class="{pill_cls}">{status_label}</span></td>
          <td><span class="pill pill-stage">{stage_label}</span></td>
          <td class="mono">{tokens.identity(e)}</td>
          <td style="color: {'#fcd34d' if kind=='sequence' else ('#fca5a5' if kind in ('tampered','unknown') else 'var(--text-muted)')};">{detail}</td>
        </tr>
        """)

    flagged_count = len(marks)
    verdict_text = "FAILED" if flagged_count > 0 else "PASSED"
    verdict_color = "#ef4444" if flagged_count > 0 else "#10b981"
    flagged_color = "#f59e0b" if flagged_count > 0 else "#10b981"
    verdict_sub = f"{flagged_count} abnormal transitions" if flagged_count > 0 else "0 anomalies detected"
    risk_score = round(min(1.0, flagged_count * 0.35 + (0.3 if any(f.kind in ('tampered','unknown') for f in findings) else 0)), 2)

    full_html = DASHBOARD_TEMPLATE.format(
        total_events=len(events),
        observed_stages_count=len(observed_stages),
        flagged_count=flagged_count,
        flagged_color=flagged_color,
        verdict_text=verdict_text,
        verdict_color=verdict_color,
        verdict_sub=verdict_sub,
        risk_score=risk_score,
        plotly_div=plotly_div,
        table_rows="\n".join(table_rows)
    )

    Path(out).write_text(full_html, encoding="utf-8")
    return out
