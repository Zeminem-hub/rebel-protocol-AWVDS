"""csrf.py — Rebel Protocol AWVDS — CSRF: missing token, blank bypass, SameSite."""
import asyncio
import httpx
from utils.logger import info

CSRF_NAMES=["csrf","xsrf","_token","authenticity_token","csrfmiddlewaretoken","csrf_token","anti_csrf","_csrf"]

def _has_token(inputs):
    for inp in inputs:
        name=inp.get("name","").lower()
        if any(t in name for t in CSRF_NAMES): return True
        if inp.get("type")=="hidden" and len(inp.get("value",""))>20: return True
    return False

async def scan_csrf(forms,base_url,headers=None,cookies=None,timeout=10.0):
    headers=headers or {}; cookies=cookies or {}; findings=[]; seen=set()
    async with httpx.AsyncClient(verify=False,follow_redirects=True) as client:
        for form in forms:
            if form.get("method","get").lower() not in ("post","put","delete"): continue
            url=form["url"]; inputs=form.get("inputs",[])
            if not _has_token(inputs):
                key=f"csrf:no-token:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append({"type":"CSRF — Missing Token","url":url,"parameter":"csrf_token","payload":"N/A","severity":"MEDIUM","confidence":75,"evidence":f"POST form has no CSRF token. Fields: {[i['name'] for i in inputs]}","method":"POST","cwe":"CWE-352","recommendation":"Add per-session CSRF tokens to all state-changing forms."})
            ti=next((i for i in inputs if any(t in i["name"].lower() for t in CSRF_NAMES)),None)
            if ti:
                mut={i["name"]:i["value"] for i in inputs}; mut[ti["name"]]=""
                try:
                    r=await client.post(url,data=mut,headers=headers,cookies=cookies,timeout=timeout)
                    if r.status_code==200:
                        key=f"csrf:blank:{url}"
                        if key not in seen:
                            seen.add(key)
                            findings.append({"type":"CSRF — Token Not Validated","url":url,"parameter":ti["name"],"payload":"(blank token)","severity":"HIGH","confidence":65,"evidence":"POST with blank token returned HTTP 200","method":"POST","cwe":"CWE-352","recommendation":"Reject requests with missing/invalid tokens with HTTP 403."})
                except: pass
        try:
            r=await client.get(base_url,headers=headers,cookies=cookies,timeout=timeout)
            rc=r.headers.get("set-cookie","")
            if rc and "samesite" not in rc.lower():
                key="csrf:no-samesite"
                if key not in seen:
                    seen.add(key)
                    findings.append({"type":"CSRF — Cookie Missing SameSite","url":base_url,"parameter":"Set-Cookie","payload":"N/A","severity":"LOW","confidence":90,"evidence":f"Cookie lacks SameSite: {rc[:100]}","method":"GET","cwe":"CWE-352","recommendation":"Set SameSite=Strict or Lax on session cookies."})
        except: pass
    info(f"CSRF done. {len(findings)} finding(s)."); return findings

def run_csrf_scan(forms,base_url,headers=None,cookies=None,timeout=10.0):
    return asyncio.run(scan_csrf(forms,base_url,headers,cookies,timeout))
