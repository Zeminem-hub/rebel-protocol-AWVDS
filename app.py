from flask import Flask, render_template, request, jsonify
import asyncio
import sys
import os

app = Flask(__name__)

AVWDS_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AVWDS_PATH)

# ── Routes ────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/scan", methods=["POST"])
def scan():
    data       = request.json or {}
    target_url = data.get("url", "").strip()
    depth      = max(1, min(int(data.get("depth", 2)), 3))
    no_sqli    = data.get("no_sqli",    False)
    no_xss     = data.get("no_xss",     False)
    no_headers = data.get("no_headers", False)
    no_files   = data.get("no_files",   False)
    no_csrf    = data.get("no_csrf",    False)
    no_injection = data.get("no_injection", False)
    cookies_str  = data.get("cookies", "")

    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400

    # Parse cookie string → dict
    def parse_cookies(s):
        c = {}
        for part in s.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                c[k.strip()] = v.strip()
        return c

    cookies = parse_cookies(cookies_str)

    def run_scan():
        try:
            from core.crawler            import run_crawl
            from modules.sqli            import scan_sqli
            from modules.xss             import scan_xss
            from modules.injections      import scan_injections
            from modules.headers         import scan_headers
            from modules.csrf            import scan_csrf
            from modules.sensitive_files import scan_sensitive_files

            async def do_scan():
                all_findings = []

                # ── Phase 1: Crawl ────────────────────────────
                crawler_result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: run_crawl(
                        base_url=target_url,
                        max_depth=depth,
                        max_pages=50,
                        timeout=8.0,
                        cookies=cookies,
                    )
                )

                endpoints = crawler_result["endpoints"]
                forms     = crawler_result["forms"]
                visited   = crawler_result["visited"]
                errors    = crawler_result["errors"]

                # ── Phase 2: Scan ─────────────────────────────
                timeout = 8.0
                hdrs    = {}

                if not no_sqli:
                    findings = await scan_sqli(endpoints, headers=hdrs, cookies=cookies, timeout=timeout, concurrency=5)
                    all_findings.extend(findings)

                if not no_xss:
                    findings = await scan_xss(endpoints, headers=hdrs, cookies=cookies, timeout=timeout, concurrency=5)
                    all_findings.extend(findings)

                if not no_injection:
                    findings = await scan_injections(endpoints, headers=hdrs, cookies=cookies, timeout=timeout, concurrency=5)
                    all_findings.extend(findings)

                if not no_headers:
                    findings = await scan_headers(target_url, visited_urls=visited, headers=hdrs, cookies=cookies, timeout=timeout)
                    all_findings.extend(findings)

                if not no_csrf:
                    findings = await scan_csrf(forms, base_url=target_url, headers=hdrs, cookies=cookies, timeout=timeout)
                    all_findings.extend(findings)

                if not no_files:
                    findings = await scan_sensitive_files(target_url, visited_urls=visited, headers=hdrs, cookies=cookies, timeout=timeout, concurrency=8)
                    all_findings.extend(findings)

                return all_findings, len(endpoints), errors

            # Run the async scan in a fresh event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                findings, ep_count, errors = loop.run_until_complete(
                    asyncio.wait_for(do_scan(), timeout=120)
                )
            finally:
                loop.close()

            return findings, ep_count, errors, None

        except asyncio.TimeoutError:
            return [], 0, [], "Scan timed out. Try depth 1 or disable some modules."
        except Exception as e:
            import traceback
            return [], 0, [], f"{type(e).__name__}: {e}\n{traceback.format_exc()}"

    findings, ep_count, diagnostics, scan_error = run_scan()

    if scan_error and not findings:
        return jsonify({"error": scan_error}), 500

    # Deduplicate
    seen = set(); deduped = []
    for f in findings:
        key = f"{f.get('type')}|{f.get('url')}|{f.get('parameter')}"
        if key not in seen:
            seen.add(key); deduped.append(f)

    # Sort by severity
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda x: sev_rank.get(x.get("severity", "INFO"), 4))

    # Summary counts
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in deduped:
        sev = f.get("severity", "INFO").upper()
        if sev in summary:
            summary[sev] += 1

    return jsonify({
        "target":      target_url,
        "endpoints":   ep_count,
        "total":       len(deduped),
        "summary":     summary,
        "findings":    deduped,
        "diagnostics": diagnostics[:5] if diagnostics else [],
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=True, host="0.0.0.0", port=port)
