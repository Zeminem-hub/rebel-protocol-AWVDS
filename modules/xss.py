import httpx
from bs4 import BeautifulSoup
from utils.logger import warning

# Dangerous HTML contexts where reflection is actually exploitable
DANGEROUS_TAGS = {"script", "svg", "img", "iframe", "body", "a", "input", "details", "video"}
DANGEROUS_ATTRS = {"onerror", "onload", "onclick", "onmouseover", "href", "src", "action"}

class XSSScanner:
    def __init__(self, payloads, headers=None):
        self.payloads = payloads
        self.headers  = headers or {}
        self.findings = []

    async def scan(self, endpoint):
        for param_name in endpoint["params"]:
            for payload in self.payloads:
                test_params = dict(endpoint["params"])
                test_params[param_name] = payload

                response = await self._send_request(endpoint, test_params)
                if response is None:
                    continue

                raw = response.text

                # ── Gate 1: payload must appear somewhere in raw response ──
                if payload not in raw:
                    continue

                # ── Gate 2: check if it's actually HTML-encoded (safe) ─────
                # If < and > are escaped, it's not exploitable
                encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded_payload in raw and payload not in raw.replace(encoded_payload, ""):
                    continue  # only encoded version found — not exploitable

                # ── Gate 3: context-aware DOM analysis ────────────────────
                context, confidence = self._analyze_context(raw, payload)

                if confidence < 50:
                    continue  # Not confident enough — skip

                finding = {
                    "type": "Cross-Site Scripting (Reflected XSS)",
                    "url": endpoint["url"],
                    "parameter": param_name,
                    "payload": payload,
                    "evidence": f"Reflected unencoded in {context}",
                    "severity": "HIGH",
                    "confidence": confidence,
                    "cwe": "CWE-79",
                    "recommendation": "HTML-encode all user input before rendering. Implement Content-Security-Policy header.",
                    "description": (
                        f"Payload reflected unencoded in response for parameter '{param_name}'. "
                        f"Reflection context: {context}."
                    )
                }
                self.findings.append(finding)
                warning(
                    f"XSS | {endpoint['url']} | param={param_name} | "
                    f"context={context} | confidence={confidence}%"
                )
                break  # one confirmed finding per param is enough

        return self.findings

    def _analyze_context(self, html: str, payload: str) -> tuple[str, int]:
        """
        Parse the response DOM and check WHERE the payload lands.
        Returns (context_description, confidence_0_to_100).
        """
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            # Can't parse — fall back to raw check
            return ("raw response (unparsed)", 55 if payload in html else 0)

        # Check 1: payload inside a <script> block (high severity)
        for script in soup.find_all("script"):
            if payload in (script.string or ""):
                return ("inline <script> block", 90)

        # Check 2: payload as an attribute value in a dangerous tag/attr
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                val_str = val if isinstance(val, str) else " ".join(val)
                if payload in val_str:
                    if tag.name in DANGEROUS_TAGS or attr.lower() in DANGEROUS_ATTRS:
                        return (f"<{tag.name}> {attr}= attribute", 85)
                    else:
                        return (f"<{tag.name}> {attr}= attribute (low-risk tag)", 60)

        # Check 3: payload as raw text node inside a dangerous tag
        for tag in soup.find_all(DANGEROUS_TAGS):
            if payload in tag.get_text():
                return (f"text node inside <{tag.name}>", 75)

        # Check 4: payload in HTML comment (not directly exploitable)
        raw_lower = html.lower()
        if "<!--" in raw_lower:
            comment_start = html.find("<!--")
            comment_end   = html.find("-->", comment_start)
            if comment_start != -1 and comment_end != -1:
                comment_block = html[comment_start:comment_end]
                if payload in comment_block:
                    return ("HTML comment (low risk)", 30)

        # Check 5: payload exists in raw HTML but we couldn't pinpoint context
        # Could be inside a <textarea>, <title>, or other safe context
        if payload in html:
            # Check for safe contexts
            for safe_tag in ["textarea", "title", "style", "noscript"]:
                for tag in soup.find_all(safe_tag):
                    if payload in (tag.get_text() or ""):
                        return (f"<{safe_tag}> (typically safe context)", 20)

            return ("unknown HTML context — manual review needed", 50)

        return ("not found", 0)

    async def _send_request(self, endpoint, params):
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                headers = {"User-Agent": "Mozilla/5.0 (AVWDS Scanner)", **self.headers}
                if endpoint["method"] == "POST":
                    return await client.post(endpoint["url"], data=params, headers=headers)
                else:
                    return await client.get(endpoint["url"], params=params, headers=headers)
        except Exception:
            return None
