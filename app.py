from flask import Flask, render_template, request, jsonify, Response
import asyncio
import json
import threading
import queue
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
    data = request.json
    target_url = data.get("url", "")
    depth      = int(data.get("depth", 2))
    no_sqli    = data.get("no_sqli", False)
    no_xss     = data.get("no_xss", False)
    no_headers = data.get("no_headers", False)
    no_files   = data.get("no_files", False)

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
                crawler  = Crawler(target_url, depth=depth)
                endpoints = await crawler.start()

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

                return findings, len(endpoints)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            findings, ep_count = loop.run_until_complete(do_scan())
            loop.close()
            return findings, ep_count

        except Exception as e:
            return [], 0

    findings, ep_count = run()

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
        "findings":  findings
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)