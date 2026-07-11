import re
import httpx
from utils.payloads import SENSITIVE_PATHS
from utils.logger import critical
from config import USER_AGENT


PUBLIC_PATHS = {"/robots.txt", "/sitemap.xml"}
INTERESTING_DISALLOW = re.compile(r"(?im)^\s*disallow:\s*(/(?:admin|backup|private|internal|api|config|db|secret|hidden)\S*)")


class SensitiveFileScanner:
    def __init__(self, headers=None, client=None):
        self.findings = []
        self.headers = {"User-Agent": USER_AGENT, **(headers or {})}
        self._external_client = client is not None
        self.client = client or httpx.AsyncClient(
            timeout=8,
            follow_redirects=False,
            headers=self.headers,
            limits=httpx.Limits(max_connections=10),
        )

    async def close(self):
        if not self._external_client:
            await self.client.aclose()

    async def scan(self, base_url):
        base = base_url.rstrip("/")

        for path in SENSITIVE_PATHS:
            url = base + path
            try:
                response = await self.client.get(url)
            except Exception:
                continue

            if response.status_code == 200:
                if path in PUBLIC_PATHS:
                    interesting = INTERESTING_DISALLOW.findall(response.text or "")
                    if interesting:
                        self.findings.append({
                            "type": "Recon: Sensitive Paths in robots/sitemap",
                            "url": url,
                            "severity": "INFO",
                            "confidence": 75,
                            "evidence": ", ".join(sorted(set(interesting))[:5]),
                            "description": f"{path} advertises restricted paths that may be worth reviewing",
                        })
                    else:
                        self.findings.append({
                            "type": "Public Metadata File",
                            "url": url,
                            "severity": "INFO",
                            "confidence": 100,
                            "evidence": "HTTP 200",
                            "description": f"{path} is present (expected for most sites; not a vulnerability)",
                        })
                    continue

                severity = "CRITICAL" if any(x in path for x in [".env", ".git", "config", "sql", "backup"]) else "HIGH"
                self.findings.append({
                    "type": "Sensitive File Exposed",
                    "url": url,
                    "severity": severity,
                    "confidence": 80,
                    "evidence": f"HTTP {response.status_code}",
                    "description": f"File at '{path}' is publicly accessible",
                })
                critical(f"Sensitive file found: {url}")

            elif response.status_code == 403 and path not in PUBLIC_PATHS:
                self.findings.append({
                    "type": "Sensitive Path Exists (Forbidden)",
                    "url": url,
                    "severity": "LOW",
                    "confidence": 60,
                    "evidence": "HTTP 403",
                    "description": f"Path '{path}' exists but access is restricted",
                })

        return self.findings
