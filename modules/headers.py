"""headers.py — Rebel Protocol AWVDS — Security headers, CORS, insecure cookies."""
import asyncio
import httpx
from utils.payloads import SECURITY_HEADERS
from utils.logger import info

async def scan_headers(base_url,visited_urls=None,headers=None,cookies=None,timeout=10.0):
    headers=headers or {}; cookies=cookies or {}; findings=[]; seen=set()
    urls=[base_url]+([u for u in visited_urls if u!=base_url][:4] if visited_urls else [])
    async with httpx.AsyncClient(verify=False,follow_redirects=True) as client:
        for url in urls:
            try: resp=await client.get(url,headers=headers,cookies=cookies,timeout=timeout)
            except: continue
            rh=resp.headers
            for hname,meta in SECURITY_HEADERS.items():
                if hname.lower() not in {k.lower() for k in rh.keys()}:
                    key=f"missing:{hname}"
                    if key not in seen:
                        seen.add(key)
                        findings.append({"type":"Missing Security Header","url":url,"parameter":hname,"payload":"N/A","severity":meta["severity"],"confidence":99,"evidence":f"Header '{hname}' absent","method":"GET","cwe":meta["cwe"],"recommendation":meta["recommendation"]})
            acao=rh.get("access-control-allow-origin","")
            if acao=="*":
                key="cors:wildcard"
                if key not in seen:
                    seen.add(key)
                    findings.append({"type":"Weak CORS — Wildcard","url":url,"parameter":"Access-Control-Allow-Origin","payload":"N/A","severity":"MEDIUM","confidence":95,"evidence":"ACAO: * (any origin)","method":"GET","cwe":"CWE-942","recommendation":"Restrict CORS to specific trusted origins."})
            if acao and acao!="*" and rh.get("access-control-allow-credentials","").lower()=="true":
                try:
                    er=await client.get(url,headers={**headers,"Origin":"https://evil.com"},cookies=cookies,timeout=timeout)
                    if er.headers.get("access-control-allow-origin","")=="https://evil.com":
                        key="cors:reflect"
                        if key not in seen:
                            seen.add(key)
                            findings.append({"type":"CORS Misconfiguration — Origin Reflection","url":url,"parameter":"Access-Control-Allow-Origin","payload":"Origin: https://evil.com","severity":"HIGH","confidence":90,"evidence":"Server reflects arbitrary Origin with credentials=true","method":"GET","cwe":"CWE-942","recommendation":"Validate Origin against a strict whitelist."})
                except: pass
    info(f"Header scan done. {len(findings)} finding(s)."); return findings

def run_header_scan(base_url,visited_urls=None,headers=None,cookies=None,timeout=10.0):
    return asyncio.run(scan_headers(base_url,visited_urls,headers,cookies,timeout))
