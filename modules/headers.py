import httpx
from urllib.parse import urlparse
from utils.logger import warning, info
from config import USER_AGENT


class HeadersScanner:
    def __init__(self, headers=None, client=None, counter=None):
        self.findings = []
        self.headers = {"User-Agent": USER_AGENT, **(headers or {})}
        self.counter = counter
        self._external_client = client is not None
        self.client = client or httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            headers=self.headers,
            limits=httpx.Limits(max_connections=10),
        )
        self.required_headers = {
            "Content-Security-Policy":   ("HIGH",   "Prevents XSS attacks"),
            "Strict-Transport-Security": ("HIGH",   "Forces HTTPS"),
            "X-Frame-Options":           ("MEDIUM", "Prevents clickjacking"),
            "X-Content-Type-Options":    ("LOW",    "Prevents MIME sniffing"),
            "Referrer-Policy":           ("LOW",    "Controls referrer info"),
            "Permissions-Policy":        ("LOW",    "Controls browser features"),
        }
        self.info_disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

    async def close(self):
        if not self._external_client:
            await self.client.aclose()

    async def scan(self, url):
        local: list[dict] = []
        info(f"Checking security headers for: {url}")
        domain = urlparse(url).netloc or url
        try:
            if self.counter: self.counter.bump()
            response = await self.client.get(url)
            headers = response.headers
            present = {h.lower() for h in headers.keys()}

            for header, (severity, purpose) in self.required_headers.items():
                if header.lower() not in present:
                    local.append({
                        "type": f"Missing Security Header: {header}",
                        "url": f"https://{domain}" if not url.startswith("http") else url,
                        "severity": severity,
                        "confidence": 90,
                        "description": f"Header '{header}' is missing on {domain}. Purpose: {purpose}",
                    })
                    warning(f"Missing header: {header}")

            for header in self.info_disclosure_headers:
                if header.lower() in present:
                    value = headers.get(header, "")
                    local.append({
                        "type": f"Server Information Disclosure: {header}",
                        "url": url,
                        "severity": "LOW",
                        "confidence": 80,
                        "evidence": value,
                        "description": f"Header '{header}: {value}' reveals server technology on {domain}",
                    })
        except Exception:
            pass

        return local
