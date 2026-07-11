from flask import Flask, render_template, request, jsonify, Response
import asyncio
import sys
import os
import time
import uuid
import threading

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

AVWDS_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AVWDS_PATH)

# In-memory scan registry. For a real deployment behind multiple workers,
# swap for SQLite or Redis. Single-worker gunicorn is fine as-is.
_scans_lock = threading.Lock()
_scans: dict[str, dict] = {}
SCAN_TTL_SECONDS = 3600


def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _reap_old_scans():
    now = time.time()
    with _scans_lock:
        stale = [k for k, v in _scans.items() if now - v.get("created_at", now) > SCAN_TTL_SECONDS]
        for k in stale:
            _scans.pop(k, None)


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


def _update(state: dict, **kwargs):
    with _scans_lock:
        state.update(kwargs)


async def _run_scan_async(state, target_url, depth, scan_headers, opts):
    from core.crawler         import Crawler
    from modules.sqli         import SQLiScanner
    from modules.xss          import XSSScanner
    from modules.headers      import HeadersScanner
    from modules.sensitive_files import SensitiveFileScanner
    from modules.csrf         import CSRFScanner
    from utils.payloads       import SQL_PAYLOADS, XSS_PAYLOADS

    findings = []
    diagnostics = []
    timings = {}
    endpoints = []

    _update(state, phase="crawler", progress=5, status="Crawling target surface")
    t = time.time()
    try:
        crawler = Crawler(target_url, depth=depth, headers=scan_headers)
        endpoints = await crawler.start()
    except Exception as e:
        diagnostics.append(f"Crawler failed: {e}")
    timings["crawl"] = round(time.time() - t, 2)
    _update(state, endpoints=len(endpoints), progress=20)

    sqli = SQLiScanner(SQL_PAYLOADS, headers=scan_headers) if not opts["no_sqli"] else None
    xss  = XSSScanner(XSS_PAYLOADS, headers=scan_headers) if not opts["no_xss"] else None
    csrf = CSRFScanner() if not opts["no_csrf"] else None
    try:
        _update(state, phase="payloads", status="Testing discovered inputs")
        t_ep = time.time()
        n = max(1, len(endpoints))
        for i, ep in enumerate(endpoints):
            if sqli:
                try: findings.extend(await sqli.scan(ep))
                except Exception as e: diagnostics.append(f"SQLi failed for {ep.get('url')}: {e}")
            if xss:
                try: findings.extend(await xss.scan(ep))
                except Exception as e: diagnostics.append(f"XSS failed for {ep.get('url')}: {e}")
            if csrf:
                try: findings.extend(await csrf.scan(ep))
                except Exception as e: diagnostics.append(f"CSRF failed for {ep.get('url')}: {e}")
            _update(state, progress=20 + int(60 * (i + 1) / n), findings_so_far=len(findings))
        timings["per_endpoint_scans"] = round(time.time() - t_ep, 2)
    finally:
        if sqli: await sqli.close()
        if xss:  await xss.close()
        if csrf: await csrf.close()

    if not opts["no_headers"]:
        _update(state, phase="posture", status="Checking security headers", progress=85)
        t = time.time()
        hs = HeadersScanner(headers=scan_headers)
        try: findings.extend(await hs.scan(target_url))
        except Exception as e: diagnostics.append(f"Headers scanner failed: {e}")
        finally: await hs.close()
        timings["headers"] = round(time.time() - t, 2)

    if not opts["no_files"]:
        _update(state, phase="posture", status="Probing sensitive paths", progress=92)
        t = time.time()
        fs = SensitiveFileScanner(headers=scan_headers)
        try: findings.extend(await fs.scan(target_url))
        except Exception as e: diagnostics.append(f"Sensitive file scanner failed: {e}")
        finally: await fs.close()
        timings["sensitive_files"] = round(time.time() - t, 2)

    return findings, len(endpoints), diagnostics, timings


def _run_scan_thread(scan_id, target_url, depth, scan_headers, opts, min_confidence):
    state = _scans[scan_id]
    started = time.time()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        findings, ep_count, diagnostics, timings = loop.run_until_complete(
            asyncio.wait_for(
                _run_scan_async(state, target_url, depth, scan_headers, opts),
                timeout=300,
            )
        )
        loop.close()
    except asyncio.TimeoutError:
        _update(state, done=True, error="Scan exceeded 5-minute timeout", progress=100, status="Timed out")
        return
    except Exception as e:
        _update(state, done=True, error=str(e), progress=100, status="Failed")
        return

    filtered = [f for f in findings if f.get("confidence", 100) >= min_confidence]
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    filtered.sort(key=lambda x: severity_rank.get(x.get("severity", "INFO"), 4))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in filtered:
        sev = f.get("severity", "LOW")
        if sev in summary:
            summary[sev] += 1

    result = {
        "target":     target_url,
        "endpoints":  ep_count,
        "total":      len(filtered),
        "hidden_low_confidence": len(findings) - len(filtered),
        "summary":    summary,
        "findings":   filtered,
        "diagnostics": diagnostics,
        "duration_seconds": round(time.time() - started, 2),
        "timings":    timings,
    }
    _update(state, done=True, progress=100, status="Scan complete", result=result, phase="report")


@app.route("/scan", methods=["POST"])
def scan_start():
    _reap_old_scans()

    data = request.json or {}
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

    from utils.rate_limit import check_and_record
    allowed, remaining = check_and_record(_client_ip(), limit=3, window_seconds=3600)
    if not allowed:
        return jsonify({"error": "Rate limit exceeded: max 3 scans per hour per IP"}), 429

    scan_id = uuid.uuid4().hex[:16]
    state = {
        "id": scan_id,
        "created_at": time.time(),
        "phase": "queued",
        "status": "Scan queued",
        "progress": 0,
        "endpoints": 0,
        "findings_so_far": 0,
        "done": False,
        "error": None,
        "result": None,
        "target": target_url,
    }
    with _scans_lock:
        _scans[scan_id] = state

    opts = {"no_sqli": no_sqli, "no_xss": no_xss, "no_headers": no_headers,
            "no_files": no_files, "no_csrf": no_csrf}

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(scan_id, target_url, depth, scan_headers, opts, min_confidence),
        daemon=True,
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "rate_limit_remaining": remaining})


@app.route("/scan/<scan_id>/status")
def scan_status(scan_id):
    with _scans_lock:
        state = _scans.get(scan_id)
        if not state:
            return jsonify({"error": "Unknown scan_id"}), 404
        return jsonify({
            "id": state["id"],
            "phase": state["phase"],
            "status": state["status"],
            "progress": state["progress"],
            "endpoints": state["endpoints"],
            "findings_so_far": state["findings_so_far"],
            "done": state["done"],
            "error": state["error"],
        })


@app.route("/scan/<scan_id>/results")
def scan_results(scan_id):
    with _scans_lock:
        state = _scans.get(scan_id)
        if not state:
            return jsonify({"error": "Unknown scan_id"}), 404
        if not state["done"]:
            return jsonify({"error": "Scan still running"}), 409
        if state["error"]:
            return jsonify({"error": state["error"]}), 500
        return jsonify(state["result"])


@app.route("/scan/<scan_id>/report.html")
def scan_report_html(scan_id):
    with _scans_lock:
        state = _scans.get(scan_id)
    if not state or not state.get("result"):
        return "Scan not ready", 404
    from reports.html_report import render_html_report
    r = state["result"]
    return Response(
        render_html_report(
            target=r["target"],
            findings=r["findings"],
            duration_seconds=r.get("duration_seconds"),
            timings=r.get("timings"),
            endpoints=r.get("endpoints", 0),
        ),
        mimetype="text/html",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, host="0.0.0.0", port=port)
