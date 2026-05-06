import asyncio
import html

import httpx

from utils.logger import warning


class XSSScanner:
    def __init__(self, payloads, concurrency=6):
        self.payloads = payloads
        self.concurrency = concurrency
        self.findings = []

    async def scan(self, endpoint):
        semaphore = asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(
            timeout=6,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Security Research Scanner)"}
        ) as client:
            tasks = []
            for param_name in endpoint["params"]:
                for payload in self.payloads:
                    tasks.append(self._test_payload(client, semaphore, endpoint, param_name, payload))
            await asyncio.gather(*tasks)

        return self.findings

    async def _test_payload(self, client, semaphore, endpoint, param_name, payload):
        async with semaphore:
            test_params = dict(endpoint["params"])
            test_params[param_name] = payload
            response = await self._send_request(client, endpoint, test_params)

            if response is None:
                return

            escaped_payload = html.escape(payload)
            if payload in response.text and escaped_payload not in response.text:
                finding = {
                    "type": "Cross-Site Scripting (Reflected XSS)",
                    "url": endpoint["url"],
                    "parameter": param_name,
                    "payload": payload,
                    "severity": "HIGH",
                    "description": f"Payload was reflected unescaped in response for parameter '{param_name}'"
                }
                self.findings.append(finding)
                warning(f"XSS found! URL: {endpoint['url']} | Param: {param_name}")

    async def _send_request(self, client, endpoint, params):
        try:
            if endpoint["method"] == "POST":
                return await client.post(endpoint["url"], data=params)
            return await client.get(endpoint["url"], params=params)
        except Exception:
            return None
