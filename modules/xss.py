import httpx
from utils.logger import warning

class XSSScanner:
    def __init__(self, payloads):
        self.payloads = payloads
        self.findings = []

    async def scan(self, endpoint):
        for param_name in endpoint["params"]:
            for payload in self.payloads:
                test_params = dict(endpoint["params"])
                test_params[param_name] = payload

                response = await self._send_request(endpoint, test_params)
                
                if response is None:
                    continue

                # Check if our payload appears in the response (reflected back)
                if payload in response.text:
                    finding = {
                        "type": "Cross-Site Scripting (Reflected XSS)",
                        "url": endpoint["url"],
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "HIGH",
                        "description": f"Payload was reflected in response for parameter '{param_name}'"
                    }
                    self.findings.append(finding)
                    warning(f"XSS found! URL: {endpoint['url']} | Param: {param_name}")

        return self.findings

    async def _send_request(self, endpoint, params):
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                headers = {"User-Agent": "Mozilla/5.0 (AVWDS Scanner)"}
                if endpoint["method"] == "POST":
                    return await client.post(endpoint["url"], data=params, headers=headers)
                else:
                    return await client.get(endpoint["url"], params=params, headers=headers)
        except Exception:
            return None