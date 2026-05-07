from flask import Flask, render_template, request, jsonify, Response
import asyncio
import sys
import os

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ── Add your avwds project to path ──────────────────────────
# Change this to your actual project path
AVWDS_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AVWDS_PATH)


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ── Routes ───────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target_url = data.get("url", "")
    depth      = int(data.get("depth", 2))
    cookies    = data.get("cookies", "").strip()
    no_sqli    = data.get("no_sqli") is True
    no_xss     = data.get("no_xss") is True
    no_headers = data.get("no_headers") is True
    no_files   = data.get("no_files") is True
    no_csrf    = data.get("no_csrf") is True
    scan_headers = {"Cookie": cookies} if cookies else {}

    if all([no_sqli, no_xss, no_headers, no_files, no_csrf]):
        no_sqli = no_xss = no_headers = no_files = no_csrf = False

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
                endpoints = []

                try:
                    crawler = Crawler(target_url, depth=depth, headers=scan_headers)
                    endpoints = await crawler.start()
                except Exception as e:
                    diagnostics.append(f"Crawler failed: {e}")

                for ep in endpoints:
                    if not no_sqli:
                        try:
                            s = SQLiScanner(SQL_PAYLOADS, headers=scan_headers)
                            findings.extend(await s.scan(ep))
                        except Exception as e:
                            diagnostics.append(f"SQLi scanner failed for {ep.get('url', 'endpoint')}: {e}")
                    if not no_xss:
                        try:
                            s = XSSScanner(XSS_PAYLOADS, headers=scan_headers)
                            findings.extend(await s.scan(ep))
                        except Exception as e:
                            diagnostics.append(f"XSS scanner failed for {ep.get('url', 'endpoint')}: {e}")
                    if not no_csrf:
                        try:
                            s = CSRFScanner()
                            findings.extend(await s.scan(ep))
                        except Exception as e:
                            diagnostics.append(f"CSRF scanner failed for {ep.get('url', 'endpoint')}: {e}")

                if not no_headers:
                    try:
                        s = HeadersScanner(headers=scan_headers)
                        findings.extend(await s.scan(target_url))
                    except Exception as e:
                        diagnostics.append(f"Headers scanner failed: {e}")

                if not no_files:
                    try:
                        s = SensitiveFileScanner(headers=scan_headers)
                        findings.extend(await s.scan(target_url))
                    except Exception as e:
                        diagnostics.append(f"Sensitive file scanner failed: {e}")

                return findings, len(endpoints), diagnostics

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            findings, ep_count, diagnostics = loop.run_until_complete(do_scan())
            loop.close()
            return findings, ep_count, diagnostics

        except Exception as e:
            return [], 0, [f"Scan failed: {e}"]

    findings, ep_count, diagnostics = run()

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
