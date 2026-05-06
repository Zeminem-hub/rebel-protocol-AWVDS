import asyncio

import httpx

from utils.logger import critical
from utils.payloads import SENSITIVE_PATHS


class SensitiveFileScanner:
    def __init__(self):
        self.findings = []

    async def scan(self, base_url):
        base = base_url.rstrip("/")
        semaphore = asyncio.Semaphore(8)

        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
            async def probe(path):
                async with semaphore:
                    url = base + path
                    try:
                        response = await client.get(url)
                    except Exception:
                        return

                    if response.status_code == 200:
                        severity = "CRITICAL" if any(
                            marker in path for marker in [".env", ".git", "config", "sql", "backup"]
                        ) else "HIGH"
                        finding = {
                            "type": "Sensitive File Exposed",
                            "url": url,
                            "severity": severity,
                            "evidence": f"HTTP {response.status_code}",
                            "description": f"File at '{path}' is publicly accessible"
                        }
                        self.findings.append(finding)
                        critical(f"Sensitive file found: {url}")

                    elif response.status_code == 403:
                        finding = {
                            "type": "Sensitive Path Exists (Forbidden)",
                            "url": url,
                            "severity": "LOW",
                            "evidence": "HTTP 403",
                            "description": f"Path '{path}' exists but access is restricted"
                        }
                        self.findings.append(finding)

            await asyncio.gather(*(probe(path) for path in SENSITIVE_PATHS))

        return self.findings
