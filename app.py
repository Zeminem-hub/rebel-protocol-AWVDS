from flask import Flask, render_template, request, jsonify, Response
import asyncio
import sys
import os

app = Flask(__name__)

# ── Add your avwds project to path ──────────────────────────
# Change this to your actual project path
AVWDS_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AVWDS_PATH)

# ── Routes ───────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json or {}
    target_url = data.get("url", "")
    depth      = max(1, min(int(data.get("depth", 2)), 3))
    no_sqli    = data.get("no_sqli", False)
    no_xss     = data.get("no_xss", False)
    no_headers = data.get("no_headers", False)
    no_files   = data.get("no_files", False)
    max_endpoints = max(1, min(int(data.get("max_endpoints", 20)), 40))

    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400

    def run():
        try:
            from core.crawler        import Crawler
            from modules.sqli        import SQLiScanner
            from modules.xss         import XSSScanner
            from modules.headers     import HeadersScanner
            from modules.sensitive_files import SensitiveFileScanner
            from modules.csrf        import CSRFScanner
            from utils.payloads      import SQL_PAYLOADS, XSS_PAYLOADS

            async def do_scan():
                findings = []
                diagnostics = []
                crawler  = Crawler(
                    target_url,
                    depth=depth,
                    timeout=6,
                    max_pages=12 if depth == 1 else 24 if depth == 2 else 35,
                    max_endpoints=max_endpoints
                )
                endpoints = await asyncio.wait_for(crawler.start(), timeout=25)
                diagnostics.extend(crawler.errors[:5])
                endpoints = endpoints[:max_endpoints]

                for ep in endpoints:
                    if not no_sqli:
                        s = SQLiScanner(SQL_PAYLOADS)
                        findings.extend(await s.scan(ep))
                    if not no_xss:
                        s = XSSScanner(XSS_PAYLOADS)
                        findings.extend(await s.scan(ep))
                    s = CSRFScanner()
                    findings.extend(await s.scan(ep))

                if not no_headers:
                    s = HeadersScanner()
                    findings.extend(await s.scan(target_url))

                if not no_files:
                    s = SensitiveFileScanner()
                    findings.extend(await s.scan(target_url))

                return findings, len(endpoints), diagnostics

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            findings, ep_count, diagnostics = loop.run_until_complete(
                asyncio.wait_for(do_scan(), timeout=90)
            )
            loop.close()
            return findings, ep_count, diagnostics, None

        except asyncio.TimeoutError:
            return [], 0, [], "Scan timed out. Try depth 1, reduce modules, or verify the target is reachable."
        except Exception as e:
            return [], 0, [], f"{type(e).__name__}: {e}"

    findings, ep_count, diagnostics, scan_error = run()

    if scan_error:
        return jsonify({"error": scan_error}), 504

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: severity_rank.get(x.get("severity", "INFO"), 4))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in summary:
            summary[sev] += 1

    return jsonify({
        "target":    target_url,
        "endpoints": ep_count,
        "total":     len(findings),
        "summary":   summary,
        "findings":  findings,
        "diagnostics": diagnostics
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, host="0.0.0.0", port=port)
