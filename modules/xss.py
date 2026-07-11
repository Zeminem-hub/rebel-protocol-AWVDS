import html
import httpx
from utils.logger import warning


class XSSScanner:
    def __init__(self, payloads, headers=None, client=None):
        self.payloads = payloads
        self.headers = {"User-Agent": "Mozilla/5.0 (AWVDS Scanner)", **(headers or {})}
        self.findings = []
        self._external_client = client is not None
        self.client = client or httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            headers=self.headers,
            limits=httpx.Limits(max_connections=10),
        )

    async def close(self):
        if not self._external_client:
            await self.client.aclose()

    async def scan(self, endpoint):
        for param_name in endpoint["params"]:
            for payload in self.payloads:
                test_params = dict(endpoint["params"])
                test_params[param_name] = payload
                response = await self._send_request(endpoint, test_params)
                if response is None:
                    continue

                body = response.text
                if payload in body:
                    self.findings.append({
                        "type": "Cross-Site Scripting (Reflected XSS)",
                        "url": endpoint["url"],
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "HIGH",
                        "confidence": 85,
                        "description": f"Payload was reflected verbatim in response for parameter '{param_name}'",
                    })
                    warning(f"XSS found! URL: {endpoint['url']} | Param: {param_name}")
                    continue

                # Partial encoding: some frameworks encode < > but leave quotes raw.
                # If < and > are encoded but the payload's quotes are not, and it
                # lands inside an attribute context, it may still be exploitable.
                dangerous = {"<", ">", "\"", "'"}
                present = {c for c in dangerous if c in payload}
                if not present:
                    continue
                raw_present = {c for c in present if c in body and html.escape(c) not in body[: body.find(c) + 1]}
                if ("<" not in raw_present and ">" not in raw_present) and (
                    "\"" in raw_present or "'" in raw_present
                ):
                    stripped = payload.replace("<", "").replace(">", "")
                    if stripped and stripped in body:
                        self.findings.append({
                            "type": "Cross-Site Scripting (Partial Encoding)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "MEDIUM",
                            "confidence": 55,
                            "description": (
                                f"Angle brackets encoded but quotes reflected raw for '{param_name}'. "
                                "May be exploitable inside HTML attribute contexts."
                            ),
                        })

        return self.findings

    async def _send_request(self, endpoint, params):
        try:
            if endpoint["method"] == "POST":
                return await self.client.post(endpoint["url"], data=params)
            return await self.client.get(endpoint["url"], params=params)
        except Exception:
            return None
