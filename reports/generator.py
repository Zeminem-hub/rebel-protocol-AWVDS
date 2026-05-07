import json
from datetime import datetime
from utils.logger import success

def generate_report(target_url, all_findings, output_file="report.json"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Sort by severity (most critical first)
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        all_findings,
        key=lambda x: severity_rank.get(x.get("severity", "INFO"), 4)
    )

    # Count by severity
    summary = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }
    for f in all_findings:
        sev = f.get("severity", "INFO")
        summary[sev] = summary.get(sev, 0) + 1

    # Build report structure
    report = {
        "tool": "Automated Web Vulnerability Detection System (AVWDS)",
        "target": target_url,
        "scan_date": timestamp,
        "total_findings": len(all_findings),
        "summary": summary,
        "findings": sorted_findings
    }

    # Save to JSON file
    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    # Also print a summary to terminal
    print("\n" + "="*60)
    print("           SCAN COMPLETE — SUMMARY REPORT")
    print("="*60)
    print(f"  Target  : {target_url}")
    print(f"  Date    : {timestamp}")
    print(f"  Total   : {len(all_findings)} issues found")
    print("-"*60)
    print(f"  CRITICAL: {summary['CRITICAL']}")
    print(f"  HIGH    : {summary['HIGH']}")
    print(f"  MEDIUM  : {summary['MEDIUM']}")
    print(f"  LOW     : {summary['LOW']}")
    print("="*60)
    success(f"Full report saved to: {output_file}")