from flask import Flask, render_template, request, jsonify
import asyncio
import sys
import os
import time

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

AVWDS_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AVWDS_PATH)


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


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
    min_confidence = int(data.get("min_confidence", 50))
    scan_headers = {"Cookie": cookies} if cookies else {}

    if all([no_sqli, no_xss, no_headers, no_files, no_csrf]):
        no_sqli = no_xss = no_headers = no_files = no_csrf = False

    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400

    from utils.safety import is_safe_target
    ok, reason = is_safe_target(target_url)
    if not ok:
        return jsonify({"error": f"Target blocked: {reason}"}), 400

    def run():
        try:
            from core.crawler         import Crawler
            from modules.sqli         import SQLiScanner
            from modules.xss          import XSSScanner
            from modules.headers      import HeadersScanner
            from modules.sensitive_files import SensitiveFileScanner
            from modules.csrf         import CSRFScanner
            from utils.payloads       import SQL_PAYLOADS, XSS_PAYLOADS

            async def do_scan():
                findings = []
                diagnostics = []
                timings = {}
                endpoints = []

                t0 = time.time()
                try:
                    crawler = Crawler(target_url, depth=depth, headers=scan_headers)
                    endpoints = await crawler.start()
                except Exception as e:
                    diagnostics.append(f"Crawler failed: {e}")
                timings["crawl"] = round(time.time() - t0, 2)

                sqli = SQLiScanner(SQL_PAYLOADS, headers=scan_headers) if not no_sqli else None
                xss  = XSSScanner(XSS_PAYLOADS, headers=scan_headers) if not no_xss else None
                csrf = CSRFScanner() if not no_csrf else None
                try:
                    t_ep = time.time()
                    for ep in endpoints:
                        if sqli:
                            try:
                                findings.extend(await sqli.scan(ep))
                            except Exception as e:
                                diagnostics.append(f"SQLi scanner failed for {ep.get('url', 'endpoint')}: {e}")
                        if xss:
                            try:
                                findings.extend(await xss.scan(ep))
                            except Exception as e:
                                diagnostics.append(f"XSS scanner failed for {ep.get('url', 'endpoint')}: {e}")
                        if csrf:
                            try:
                                findings.extend(await csrf.scan(ep))
                            except Exception as e:
                                diagnostics.append(f"CSRF scanner failed for {ep.get('url', 'endpoint')}: {e}")
                    timings["per_endpoint_scans"] = round(time.time() - t_ep, 2)
                finally:
                    if sqli: await sqli.close()
                    if xss:  await xss.close()
                    if csrf: await csrf.close()

                if not no_headers:
                    t = time.time()
                    hs = HeadersScanner(headers=scan_headers)
                    try:
                        findings.extend(await hs.scan(target_url))
                    except Exception as e:
                        diagnostics.append(f"Headers scanner failed: {e}")
                    finally:
                        await hs.close()
                    timings["headers"] = round(time.time() - t, 2)

                if not no_files:
                    t = time.time()
                    fs = SensitiveFileScanner(headers=scan_headers)
                    try:
                        findings.extend(await fs.scan(target_url))
                    except Exception as e:
                        diagnostics.append(f"Sensitive file scanner failed: {e}")
                    finally:
                        await fs.close()
                    timings["sensitive_files"] = round(time.time() - t, 2)

                return findings, len(endpoints), diagnostics, timings

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            findings, ep_count, diagnostics, timings = loop.run_until_complete(do_scan())
            loop.close()
            return findings, ep_count, diagnostics, timings

        except Exception as e:
            return [], 0, [f"Scan failed: {e}"], {}

    scan_start = time.time()
    findings, ep_count, diagnostics, timings = run()
    duration = round(time.time() - scan_start, 2)

    filtered = [f for f in findings if f.get("confidence", 100) >= min_confidence]

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    filtered.sort(key=lambda x: severity_rank.get(x.get("severity", "INFO"), 4))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in filtered:
        sev = f.get("severity", "LOW")
        if sev in summary:
            summary[sev] += 1

    return jsonify({
        "target":     target_url,
        "endpoints":  ep_count,
        "total":      len(filtered),
        "hidden_low_confidence": len(findings) - len(filtered),
        "summary":    summary,
        "findings":   filtered,
        "diagnostics": diagnostics,
        "duration_seconds": duration,
        "timings":    timings,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, host="0.0.0.0", port=port)
