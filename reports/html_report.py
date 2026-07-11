import html
from datetime import datetime

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#ff3b4f",
    "HIGH":     "#ff8a3c",
    "MEDIUM":   "#ffd23f",
    "LOW":      "#4fb3ff",
    "INFO":     "#8a8fa3",
}


def _summary(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _bar(counts, total):
    if total <= 0:
        return '<div class="bar"><div class="bar-empty">No findings</div></div>'
    segments = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        pct = (n / total) * 100
        segments.append(
            f'<div class="seg" style="width:{pct:.2f}%;background:{SEVERITY_COLORS[sev]}" '
            f'title="{sev}: {n}">{sev} {n}</div>'
        )
    return f'<div class="bar">{"".join(segments)}</div>'


def _finding_card(idx, f):
    sev = f.get("severity", "INFO")
    color = SEVERITY_COLORS.get(sev, "#8a8fa3")
    fields = []
    for key in ("url", "parameter", "payload", "evidence", "confidence"):
        if key in f and f[key] not in (None, ""):
            fields.append(f'<div class="row"><span class="k">{key}</span><code>{html.escape(str(f[key]))}</code></div>')
    fields_html = "".join(fields)
    return f'''
    <details class="finding" style="border-left-color:{color}">
      <summary>
        <span class="sev" style="background:{color}">{sev}</span>
        <span class="ftype">{html.escape(f.get("type", "Finding"))}</span>
      </summary>
      <div class="body">
        {fields_html}
        <p>{html.escape(f.get("description", ""))}</p>
      </div>
    </details>'''


def render_html_report(target, findings, duration_seconds=None, timings=None, endpoints=0, http_requests=None):
    counts = _summary(findings)
    total = sum(counts.values())
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    modules_used = ", ".join(f"{k}: {v}s" for k, v in (timings or {}).items()) or "—"
    dur = f"{duration_seconds}s" if duration_seconds is not None else "—"

    cards = "\n".join(_finding_card(i, f) for i, f in enumerate(findings)) or \
            '<div class="empty">No findings above the confidence threshold.</div>'

    return f'''<!doctype html>
<html><head>
<meta charset="utf-8">
<title>AWVDS Report — {html.escape(target)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif;
         background:#0b0d12; color:#e6e9ef; margin:0; padding:32px; max-width:960px; margin:0 auto; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .meta {{ color:#8a8fa3; font-size:12px; margin-bottom:24px; }}
  .card {{ background:#12151d; border:1px solid #1e2230; border-radius:10px; padding:20px; margin-bottom:20px; }}
  .bar {{ display:flex; height:28px; border-radius:6px; overflow:hidden; background:#1e2230; }}
  .seg {{ font-size:11px; color:#0b0d12; font-weight:600; display:flex; align-items:center;
         justify-content:center; letter-spacing:0.5px; }}
  .bar-empty {{ padding:6px 12px; color:#8a8fa3; font-size:12px; }}
  .stat-row {{ display:flex; gap:16px; flex-wrap:wrap; margin-top:12px; color:#8a8fa3; font-size:12px; }}
  .stat-row b {{ color:#e6e9ef; }}
  .finding {{ background:#12151d; border:1px solid #1e2230; border-left:3px solid;
              border-radius:8px; margin-bottom:8px; padding:0; }}
  .finding summary {{ padding:12px 16px; cursor:pointer; display:flex; align-items:center; gap:12px; }}
  .sev {{ font-size:10px; padding:3px 8px; border-radius:4px; color:#0b0d12; font-weight:700; letter-spacing:0.5px; }}
  .ftype {{ font-weight:500; }}
  .body {{ padding:0 16px 16px; }}
  .row {{ margin:6px 0; font-size:12px; }}
  .k {{ display:inline-block; width:90px; color:#8a8fa3; text-transform:uppercase; font-size:10px; letter-spacing:0.5px; }}
  code {{ background:#0b0d12; padding:2px 6px; border-radius:3px; font-size:12px; word-break:break-all; }}
  .body p {{ color:#c6cad3; margin:8px 0 0; }}
  .empty {{ color:#8a8fa3; text-align:center; padding:32px; }}
  .no-print {{ text-align:right; }}
  button {{ background:#1e2230; color:#e6e9ef; border:1px solid #2a2f3d; padding:6px 12px;
            border-radius:6px; cursor:pointer; font-size:12px; }}
  @media print {{ .no-print {{ display:none; }} body {{ background:white; color:black; }} }}
</style>
</head><body>
<div class="no-print"><button onclick="window.print()">Export as PDF</button></div>
<h1>AWVDS Scan Report</h1>
<div class="meta">Target: <b>{html.escape(target)}</b> · {now} · {endpoints} endpoints tested · {dur}{f" · {http_requests} HTTP requests" if http_requests is not None else ""}</div>

<div class="card">
  {_bar(counts, total)}
  <div class="stat-row">
    <span><b>{counts["CRITICAL"]}</b> critical</span>
    <span><b>{counts["HIGH"]}</b> high</span>
    <span><b>{counts["MEDIUM"]}</b> medium</span>
    <span><b>{counts["LOW"]}</b> low</span>
    <span><b>{counts["INFO"]}</b> info</span>
    <span>· phases: {html.escape(modules_used)}</span>
  </div>
</div>

{cards}
</body></html>'''
