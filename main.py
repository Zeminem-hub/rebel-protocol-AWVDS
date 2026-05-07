"""
main.py — Rebel Protocol AWVDS v2.0
Entry point: crawl → scan → report.

Usage:
  python main.py --url http://target.com
  python main.py --url http://dvwa.local --depth 3 --cookies "PHPSESSID=abc; security=low"
"""
import argparse, sys, time
from core.crawler            import run_crawl
from modules.sqli            import run_sqli_scan
from modules.xss             import run_xss_scan
from modules.injections      import run_injection_scan
from modules.headers         import run_header_scan
from modules.csrf            import run_csrf_scan
from modules.sensitive_files import run_sensitive_scan
from reports.generator       import generate_report, print_summary
from utils.logger            import banner, info, warning, error, success

REBEL_BANNER = r"""
██████╗ ███████╗██████╗ ███████╗██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██║
██████╔╝█████╗  ██████╔╝█████╗  ██║
  Rebel Protocol — AWVDS v2.0
  Automated Web Vulnerability Detection System
"""

def parse_args():
    p = argparse.ArgumentParser(description="Rebel Protocol AWVDS")
    p.add_argument("--url",          required=True,              help="Target URL")
    p.add_argument("--depth",        type=int,   default=3,      help="Crawl depth")
    p.add_argument("--output",       default="reports/report.json", help="Output JSON path")
    p.add_argument("--timeout",      type=float, default=10.0,   help="Per-request timeout")
    p.add_argument("--cookies",      default="",                 help='Cookie string e.g. "PHPSESSID=abc; security=low"')
    p.add_argument("--no-sqli",      action="store_true")
    p.add_argument("--no-xss",       action="store_true")
    p.add_argument("--no-headers",   action="store_true")
    p.add_argument("--no-csrf",      action="store_true")
    p.add_argument("--no-files",     action="store_true")
    p.add_argument("--no-injection", action="store_true")
    return p.parse_args()

def parse_cookies(s):
    c = {}
    for part in s.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("="); c[k.strip()] = v.strip()
    return c

def main():
    banner(REBEL_BANNER)
    args    = parse_args()
    target  = args.url.rstrip("/")
    cookies = parse_cookies(args.cookies)

    info(f"Target  : {target}")
    info(f"Depth   : {args.depth}")
    info(f"Output  : {args.output}")
    if cookies: info(f"Cookies : {list(cookies.keys())}")

    all_findings = []
    t0 = time.monotonic()

    # ── Phase 1: Crawl ────────────────────────────────────────
    info("\n[Phase 1] Crawling target...")
    try:
        cr = run_crawl(base_url=target, max_depth=args.depth, max_pages=300,
                       timeout=args.timeout, cookies=cookies)
    except Exception as e:
        error(f"Crawl failed: {e}"); sys.exit(1)

    endpoints = cr["endpoints"]
    forms     = cr["forms"]
    visited   = cr["visited"]
    success(f"Crawl done — {len(visited)} pages | {len(endpoints)} endpoints | {len(forms)} forms")

    # ── Phase 2: Scan ─────────────────────────────────────────
    info("\n[Phase 2] Scanning for vulnerabilities...")

    scan_tasks = [
        ("SQL Injection",      args.no_sqli,      run_sqli_scan,      {"endpoints": endpoints, "cookies": cookies, "timeout": args.timeout}),
        ("XSS",                args.no_xss,        run_xss_scan,       {"endpoints": endpoints, "cookies": cookies, "timeout": args.timeout}),
        ("CMDi/Traversal/LFI", args.no_injection,  run_injection_scan, {"endpoints": endpoints, "cookies": cookies, "timeout": args.timeout}),
        ("Security Headers",   args.no_headers,    run_header_scan,    {"base_url": target, "visited_urls": visited, "cookies": cookies, "timeout": args.timeout}),
        ("CSRF",               args.no_csrf,        run_csrf_scan,      {"forms": forms, "base_url": target, "cookies": cookies, "timeout": args.timeout}),
        ("Sensitive Files",    args.no_files,       run_sensitive_scan, {"base_url": target, "visited_urls": visited, "cookies": cookies, "timeout": args.timeout}),
    ]

    for label, skip, fn, kwargs in scan_tasks:
        if not skip:
            info(f"→ {label}...")
            try: all_findings.extend(fn(**kwargs))
            except Exception as e: error(f"{label} error: {e}")

    # ── Phase 3: Report ───────────────────────────────────────
    elapsed = time.monotonic() - t0
    info(f"\n[Phase 3] Generating report... (total: {elapsed:.1f}s)")

    report = generate_report(
        target_url=target,
        findings=all_findings,
        scan_meta={"duration_seconds": round(elapsed, 2), "pages_crawled": len(visited),
                   "endpoints_tested": len(endpoints), "forms_tested": len(forms)},
        output_path=args.output,
    )
    print_summary(report)

if __name__ == "__main__":
    main()
