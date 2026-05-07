"""generator.py — Rebel Protocol AWVDS — Structured JSON report + terminal summary."""
import json,os,datetime
from collections import defaultdict
from utils.logger import banner,info,success,vuln

SEV_ORDER={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
CWE_LINKS={"CWE-89":"https://cwe.mitre.org/data/definitions/89.html","CWE-79":"https://cwe.mitre.org/data/definitions/79.html","CWE-78":"https://cwe.mitre.org/data/definitions/78.html","CWE-22":"https://cwe.mitre.org/data/definitions/22.html","CWE-98":"https://cwe.mitre.org/data/definitions/98.html","CWE-601":"https://cwe.mitre.org/data/definitions/601.html","CWE-352":"https://cwe.mitre.org/data/definitions/352.html","CWE-200":"https://cwe.mitre.org/data/definitions/200.html","CWE-209":"https://cwe.mitre.org/data/definitions/209.html","CWE-942":"https://cwe.mitre.org/data/definitions/942.html","CWE-319":"https://cwe.mitre.org/data/definitions/319.html","CWE-693":"https://cwe.mitre.org/data/definitions/693.html"}

def _score(sev): return {"CRITICAL":9,"HIGH":7,"MEDIUM":5,"LOW":3,"INFO":1}.get(sev.upper(),0)

def _dedup(findings):
    seen=set(); out=[]
    for f in findings:
        key=f"{f.get('type')}|{f.get('url')}|{f.get('parameter')}"
        if key not in seen: seen.add(key); out.append(f)
    return out

def generate_report(target_url,findings,scan_meta=None,output_path=None):
    findings=_dedup(findings); findings.sort(key=lambda f:SEV_ORDER.get(f.get("severity","INFO").upper(),99))
    counts=defaultdict(int)
    for f in findings: counts[f.get("severity","INFO").upper()]+=1
    enriched=[]
    for f in findings:
        fe=dict(f); cwe=fe.get("cwe","")
        if cwe in CWE_LINKS: fe["cwe_link"]=CWE_LINKS[cwe]
        fe["cvss_score"]=_score(fe.get("severity","INFO")); enriched.append(fe)
    report={"tool":"Rebel Protocol AWVDS","version":"2.0.0","target":target_url,"timestamp":datetime.datetime.utcnow().isoformat()+"Z","scan_meta":scan_meta or {},"summary":{"total_findings":len(findings),"by_severity":dict(counts),"risk_score":sum(_score(f.get("severity","INFO")) for f in findings)},"findings":enriched}
    if output_path:
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".",exist_ok=True)
        with open(output_path,"w",encoding="utf-8") as fh: json.dump(report,fh,indent=2)
        success(f"Report saved → {output_path}")
    return report

def print_summary(report):
    summary=report["summary"]; findings=report["findings"]
    banner("\n"+"="*60); banner("  REBEL PROTOCOL — SCAN REPORT"); banner("="*60)
    info(f"Target   : {report['target']}"); info(f"Time     : {report['timestamp']}"); info(f"Findings : {summary['total_findings']}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        c=summary["by_severity"].get(sev,0)
        if c: vuln(sev,f"{c} {sev} finding(s)")
    if not findings: success("No vulnerabilities detected."); return
    banner("\n"+"─"*60); banner("  VULNERABILITY DETAILS"); banner("─"*60)
    for i,f in enumerate(findings,1):
        vuln(f.get("severity","INFO"),f"[{i}] {f.get('type','Unknown')}")
        print(f"    URL        : {f.get('url','N/A')}")
        print(f"    Parameter  : {f.get('parameter','N/A')}")
        print(f"    Payload    : {f.get('payload','N/A')}")
        print(f"    Evidence   : {f.get('evidence','N/A')}")
        print(f"    Confidence : {f.get('confidence',0)}%")
        cwe=f.get("cwe","")
        if cwe: print(f"    CWE        : {cwe} — {f.get('cwe_link','')}")
        print(f"    Fix        : {f.get('recommendation','N/A')}"); print()
    banner("="*60+"\n")
