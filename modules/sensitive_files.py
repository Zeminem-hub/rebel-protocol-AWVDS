"""sensitive_files.py — Rebel Protocol AWVDS — Config files, backups, error leakage, dir listing."""
import asyncio, re
import httpx
from utils.payloads import SENSITIVE_PATHS
from utils.logger import info, critical, warning

DIR_LIST=[r"Index of /",r"<title>Index of",r"Parent Directory",r"\[DIR\]"]
ERR_PATS=[r"Traceback \(most recent call last\)",r"Fatal error:.*in .* on line",r"Warning:.*in .* on line",r"ORA-\d{5}",r"pg_query\(\)",r"sqlite3\.OperationalError",r"Uncaught Exception"]
MARKERS={".env":[r"DB_PASSWORD",r"SECRET_KEY",r"API_KEY"],".git":[r"\[core\]",r"repositoryformatversion"],"phpinfo":[r"PHP Version"],"swagger":[r'"swagger"',r'"openapi"']}

def _cat(path):
    if ".env" in path: return "Environment File"
    if ".git" in path: return "VCS Exposure"
    if any(x in path for x in ["config","settings","database"]): return "Configuration File"
    if any(x in path for x in ["backup","dump",".sql",".zip"]): return "Backup File"
    if any(x in path for x in ["admin","phpmyadmin","pma"]): return "Admin Panel"
    if any(x in path for x in ["swagger","openapi","/api/"]): return "API Documentation"
    if any(x in path for x in ["phpinfo","info.php"]): return "Debug Page"
    return "Sensitive File"

async def scan_sensitive_files(base_url,visited_urls=None,headers=None,cookies=None,timeout=10.0,concurrency=10):
    headers=headers or {}; cookies=cookies or {}; findings=[]; seen=set()
    base=base_url.rstrip("/"); sem=asyncio.Semaphore(concurrency)

    async def probe(client,path):
        url=base+path
        async with sem:
            try: resp=await client.get(url,headers=headers,cookies=cookies,follow_redirects=False,timeout=timeout)
            except: return
        if resp.status_code not in (200,403): return
        body=resp.text; cat=_cat(path); sev="HIGH" if resp.status_code==200 else "INFO"
        ev=f"HTTP {resp.status_code} — {len(body)} bytes"
        for k,pats in MARKERS.items():
            if k in path.lower():
                for p in pats:
                    if re.search(p,body,re.IGNORECASE): ev+=f" | Pattern: '{p}'"
        fk=f"file:{url}"
        if fk not in seen:
            seen.add(fk)
            findings.append({"type":f"Sensitive Exposure — {cat}","url":url,"parameter":"path","payload":path,"severity":sev,"confidence":90 if resp.status_code==200 else 60,"evidence":ev,"method":"GET","cwe":"CWE-200","recommendation":f"Remove or restrict access to '{path}'."})
        for pat in DIR_LIST:
            if re.search(pat,body,re.IGNORECASE):
                dk=f"dirlist:{url}"
                if dk not in seen:
                    seen.add(dk)
                    findings.append({"type":"Directory Listing Enabled","url":url,"parameter":"path","payload":path,"severity":"MEDIUM","confidence":95,"evidence":f"Dir listing: '{pat}'","method":"GET","cwe":"CWE-548","recommendation":"Disable directory listing (Options -Indexes)."})
                break

    async def chk_err(client,url):
        async with sem:
            try: body=(await client.get(url,headers=headers,cookies=cookies,follow_redirects=True,timeout=timeout)).text
            except: return
        for pat in ERR_PATS:
            if re.search(pat,body,re.IGNORECASE):
                key=f"error:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append({"type":"Sensitive Exposure — Stack Trace","url":url,"parameter":"response_body","payload":"N/A","severity":"MEDIUM","confidence":80,"evidence":f"Error pattern: '{pat}'","method":"GET","cwe":"CWE-209","recommendation":"Disable verbose errors in production."})
                break

    async with httpx.AsyncClient(verify=False,follow_redirects=False) as client:
        tasks=[probe(client,p) for p in SENSITIVE_PATHS]
        if visited_urls: tasks+=[chk_err(client,u) for u in visited_urls[:50]]
        await asyncio.gather(*tasks,return_exceptions=True)

    for f in findings:
        (critical if f["severity"] in ("HIGH","CRITICAL") else warning)(f"{f['type']} → {f['url']}")
    info(f"Sensitive files done. {len(findings)} finding(s)."); return findings

def run_sensitive_scan(base_url,visited_urls=None,headers=None,cookies=None,timeout=10.0):
    return asyncio.run(scan_sensitive_files(base_url,visited_urls,headers,cookies,timeout))
