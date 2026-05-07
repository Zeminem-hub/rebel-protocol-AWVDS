"""
injections.py — Rebel Protocol AWVDS  [NEW MODULE]
Command Injection, Path Traversal, Open Redirect, LFI.
"""
import asyncio, re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import httpx
from utils.payloads import CMDI_PAYLOADS,CMDI_PATTERNS,TRAVERSAL_PAYLOADS,TRAVERSAL_PATTERNS,REDIRECT_PAYLOADS,REDIRECT_DOMAINS,LFI_PAYLOADS,LFI_PATTERNS
from utils.logger import critical, info

def _inj(url,param,val):
    parsed=urlparse(url); params=parse_qs(parsed.query,keep_blank_values=True)
    params[param]=[val]; return urlunparse(parsed._replace(query=urlencode(params,doseq=True)))

def _match(body,pats):
    for p in pats:
        if re.search(p,body,re.IGNORECASE): return p
    return None

async def _cmdi(cl,url,param,h,c,t):
    for pl in CMDI_PAYLOADS:
        try:
            body=(await cl.get(_inj(url,param,pl),headers=h,cookies=c,follow_redirects=True,timeout=t)).text
            m=_match(body,CMDI_PATTERNS)
            if m: return [{"type":"Command Injection","url":_inj(url,param,pl),"parameter":param,"payload":pl,"severity":"CRITICAL","confidence":90,"evidence":f"Pattern: '{m}'","method":"GET","cwe":"CWE-78","recommendation":"Never pass user input to OS commands."}]
        except: pass
    return []

async def _trav(cl,url,param,h,c,t):
    for pl in TRAVERSAL_PAYLOADS:
        try:
            body=(await cl.get(_inj(url,param,pl),headers=h,cookies=c,follow_redirects=True,timeout=t)).text
            m=_match(body,TRAVERSAL_PATTERNS)
            if m: return [{"type":"Path Traversal","url":_inj(url,param,pl),"parameter":param,"payload":pl,"severity":"HIGH","confidence":85,"evidence":f"File content: '{m}'","method":"GET","cwe":"CWE-22","recommendation":"Validate and whitelist file paths server-side."}]
        except: pass
    return []

async def _redir(cl,url,param,h,c,t):
    for pl in REDIRECT_PAYLOADS:
        try:
            r=await cl.get(_inj(url,param,pl),headers=h,cookies=c,follow_redirects=False,timeout=t)
            loc=r.headers.get("location","")
            if r.status_code in (301,302,303,307,308):
                for d in REDIRECT_DOMAINS:
                    if d in loc: return [{"type":"Open Redirect","url":_inj(url,param,pl),"parameter":param,"payload":pl,"severity":"MEDIUM","confidence":80,"evidence":f"HTTP {r.status_code} → {loc}","method":"GET","cwe":"CWE-601","recommendation":"Whitelist redirect destinations server-side."}]
        except: pass
    return []

async def _lfi(cl,url,param,h,c,t):
    for pl in LFI_PAYLOADS:
        try:
            body=(await cl.get(_inj(url,param,pl),headers=h,cookies=c,follow_redirects=True,timeout=t)).text
            m=_match(body,LFI_PATTERNS)
            if m: return [{"type":"Local File Inclusion (LFI)","url":_inj(url,param,pl),"parameter":param,"payload":pl,"severity":"CRITICAL","confidence":88,"evidence":f"File content: '{m}'","method":"GET","cwe":"CWE-98","recommendation":"Never pass user input to file include statements."}]
        except: pass
    return []

async def scan_injections(endpoints,headers=None,cookies=None,timeout=10.0,concurrency=8,checks=None):
    headers=headers or {}; cookies=cookies or {}; checks=checks or ["cmdi","traversal","redirect","lfi"]
    findings=[]; seen=set(); sem=asyncio.Semaphore(concurrency)
    _map={"cmdi":_cmdi,"traversal":_trav,"redirect":_redir,"lfi":_lfi}
    async def bnd(c):
        async with sem: return await c
    async with httpx.AsyncClient(verify=False) as client:
        tasks=[]
        for ep in endpoints:
            if ep.get("method","GET").upper()!="GET" or not ep.get("params",{}): continue
            for p in ep["params"]:
                for chk in checks:
                    if chk in _map: tasks.append(bnd(_map[chk](client,ep["url"],p,headers,cookies,timeout)))
        results=await asyncio.gather(*tasks,return_exceptions=True)
    for r in results:
        if isinstance(r,list):
            for f in r:
                key=f"{f['url']}|{f.get('parameter','')}|{f['type']}"
                if key not in seen: seen.add(key); findings.append(f); critical(f"{f['type']} → {f['url']}")
    info(f"Injection scan done. {len(findings)} finding(s)."); return findings

def run_injection_scan(endpoints,headers=None,cookies=None,timeout=10.0):
    return asyncio.run(scan_injections(endpoints,headers,cookies,timeout))
