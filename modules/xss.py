"""
xss.py — Rebel Protocol AWVDS
XSS: marker-based reflected + stored detection.
"""
import asyncio, html as hm
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import httpx
from utils.payloads import XSS_PAYLOADS, make_xss_marker
from utils.logger import critical, info

def _inj(url,param,val):
    parsed=urlparse(url); params=parse_qs(parsed.query,keep_blank_values=True)
    params[param]=[val]; return urlunparse(parsed._replace(query=urlencode(params,doseq=True)))

def _ref(body,marker): return marker in body and hm.escape(marker) not in body
def _likely(body,p): return p in body and hm.escape(p) not in body

async def _get(client,url,param,hdrs,cook,tout):
    findings=[]; marker=make_xss_marker(); probe=f"<sCrIpT>{marker}</sCrIpT>"
    try: body=(await client.get(_inj(url,param,probe),headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
    except: return findings
    if _ref(body,marker):
        findings.append({"type":"XSS — Reflected","url":_inj(url,param,probe),"parameter":param,"payload":probe,"severity":"HIGH","confidence":85,"evidence":f"Marker '{marker}' reflected unescaped","method":"GET","cwe":"CWE-79","recommendation":"Encode all user output. Implement CSP."})
        return findings
    for payload in XSS_PAYLOADS[:10]:
        try: body=(await client.get(_inj(url,param,payload),headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
        except: continue
        for p in ["<script>","onerror=","onload=","alert(1)"]:
            if _likely(body,p):
                findings.append({"type":"XSS — Reflected","url":_inj(url,param,payload),"parameter":param,"payload":payload,"severity":"HIGH","confidence":55,"evidence":f"'{p}' reflected unescaped","method":"GET","cwe":"CWE-79","recommendation":"Encode all user output. Implement CSP."})
                return findings
    return findings

async def _post(client,url,fd,param,refetch,hdrs,cook,tout):
    findings=[]; marker=make_xss_marker(); probe=f"<sCrIpT>{marker}</sCrIpT>"
    try: body=(await client.post(url,data={**fd,param:probe},headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
    except: return findings
    if _ref(body,marker):
        findings.append({"type":"XSS — Reflected","url":url,"parameter":param,"payload":probe,"severity":"HIGH","confidence":85,"evidence":"Marker reflected in POST response","method":"POST","cwe":"CWE-79","recommendation":"Encode all user output. Implement CSP."})
        return findings
    if refetch:
        try:
            sb=(await client.get(refetch,headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
            if _ref(sb,marker):
                findings.append({"type":"XSS — Stored","url":refetch,"parameter":param,"payload":probe,"severity":"CRITICAL","confidence":80,"evidence":f"Marker '{marker}' persisted","method":"POST (Stored)","cwe":"CWE-79","recommendation":"Sanitize stored input. Encode on output. Implement CSP."})
        except: pass
    return findings

async def scan_xss(endpoints,headers=None,cookies=None,timeout=10.0,concurrency=8):
    headers=headers or {}; cookies=cookies or {}; findings=[]; seen=set()
    sem=asyncio.Semaphore(concurrency)
    async def bnd(c):
        async with sem: return await c
    async with httpx.AsyncClient(verify=False,follow_redirects=True) as client:
        tasks=[]
        for ep in endpoints:
            url=ep["url"]; m=ep.get("method","GET").upper(); params=ep.get("params",{})
            if not params: continue
            if m=="GET":
                for p in params: tasks.append(bnd(_get(client,url,p,headers,cookies,timeout)))
            elif m=="POST":
                fd={k:(v[0] if isinstance(v,list) else v) for k,v in params.items()}
                for p in fd: tasks.append(bnd(_post(client,url,fd,p,ep.get("refetch_url",url),headers,cookies,timeout)))
        results=await asyncio.gather(*tasks,return_exceptions=True)
    for r in results:
        if isinstance(r,list):
            for f in r:
                key=f"{f['url']}|{f['parameter']}|{f['type']}"
                if key not in seen: seen.add(key); findings.append(f); critical(f"XSS → {f['url']} [{f['parameter']}]")
    info(f"XSS done. {len(findings)} finding(s)."); return findings

def run_xss_scan(endpoints,headers=None,cookies=None,timeout=10.0):
    return asyncio.run(scan_xss(endpoints,headers,cookies,timeout))
