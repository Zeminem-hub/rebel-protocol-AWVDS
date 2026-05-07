import asyncio
import argparse
import time
import sys
from colorama import Fore, Style, init
init(autoreset=True)

from core.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.headers import HeadersScanner
from modules.sensitive_files import SensitiveFileScanner
from modules.csrf import CSRFScanner
from utils.payloads import SQL_PAYLOADS, XSS_PAYLOADS
from reports.generator import generate_report
from utils.logger import info, success, error


def banner():
    print(Fore.RED + r"""
  ██████╗ ███████╗██████╗ ███████╗██╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝██║
  ██████╔╝█████╗  ██████╔╝█████╗  ██║
  ██╔══██╗██╔══╝  ██╔══██╗██╔══╝  ██║
  ██║  ██║███████╗██████╔╝███████╗███████╗
  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝

  ██████╗ ██████╗  ██████╗ ████████╗ ██████╗  ██████╗ ██████╗ ██╗
  ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔═══██╗██╔════╝██╔═══██╗██║
  ██████╔╝██████╔╝██║   ██║   ██║   ██║   ██║██║     ██║   ██║██║
  ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██║   ██║██║     ██║   ██║██║
  ██║     ██║  ██║╚██████╔╝   ██║   ╚██████╔╝╚██████╗╚██████╔╝███████╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝
    """)
    print(Fore.YELLOW + "  " + "─" * 65)
    print(Fore.YELLOW + "   SQLi  |  XSS  |  CSRF  |  Headers  |  Sensitive Files  |  v1.0")
    print(Fore.YELLOW + "  " + "─" * 65)
    print()
    msg = "  [ Initializing Rebel Protocol... System Online ]"
    for char in msg:
        print(Fore.GREEN + char, end='', flush=True)
        time.sleep(0.03)
    print(Style.RESET_ALL + "\n")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="avwds",
        description="Rebel Protocol - Automated Web Vulnerability Detection System",
        epilog="Example: python main.py --url http://testphp.vulnweb.com"
    )
    parser.add_argument("--url", "-u", required=True,
                        help="Target URL to scan")
    parser.add_argument("--depth", "-d", type=int, default=2,
                        help="Crawl depth (default: 2)")
    parser.add_argument("--output", "-o", default="report.json",
                        help="Output report file (default: report.json)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay between requests (default: 0.5)")
    parser.add_argument("--no-sqli", action="store_true",
                        help="Skip SQL injection scan")
    parser.add_argument("--no-xss", action="store_true",
                        help="Skip XSS scan")
    parser.add_argument("--no-headers", action="store_true",
                        help="Skip headers check")
    parser.add_argument("--no-files", action="store_true",
                        help="Skip sensitive files scan")
    return parser.parse_args()


async def run_scan(args):
    banner()
    all_findings = []

    print(Fore.CYAN + f"  Target  : {args.url}")
    print(Fore.CYAN + f"  Depth   : {args.depth}")
    print(Fore.CYAN + f"  Output  : {args.output}")
    print()

    # Phase 1: Crawl
    info("Phase 1: Crawling target website...")
    crawler = Crawler(args.url, depth=args.depth)
    endpoints = await crawler.start()
    info(f"Found {len(endpoints)} testable endpoints\n")

    # Phase 2: Scan endpoints
    info("Phase 2: Running vulnerability scans...")
    for i, endpoint in enumerate(endpoints):
        info(f"Scanning {i+1}/{len(endpoints)}: {endpoint['url']}")

        if not args.no_sqli:
            sqli = SQLiScanner(SQL_PAYLOADS)
            all_findings.extend(await sqli.scan(endpoint))

        if not args.no_xss:
            xss = XSSScanner(XSS_PAYLOADS)
            all_findings.extend(await xss.scan(endpoint))

        csrf = CSRFScanner()
        all_findings.extend(await csrf.scan(endpoint))

        await asyncio.sleep(args.delay)

    # Phase 3: Headers
    if not args.no_headers:
        info("\nPhase 3: Checking security headers...")
        headers_scanner = HeadersScanner()
        all_findings.extend(await headers_scanner.scan(args.url))

    # Phase 4: Sensitive Files
    if not args.no_files:
        info("\nPhase 4: Scanning for sensitive files...")
        file_scanner = SensitiveFileScanner()
        all_findings.extend(await file_scanner.scan(args.url))

    # Phase 5: Report
    info("\nPhase 5: Generating report...")
    generate_report(args.url, all_findings, args.output)


def main():
    args = parse_args()
    asyncio.run(run_scan(args))


if __name__ == "__main__":
    main()