import httpx
from utils.logger import warning, info

class HeadersScanner:
    def __init__(self):
        self.findings = []
        # Header name → (severity, what it does)
        self.required_headers = {
            "Content-Security-Policy":   ("HIGH",   "Prevents XSS attacks"),
            "Strict-Transport-Security": ("HIGH",   "Forces HTTPS"),
            "X-Frame-Options":           ("MEDIUM", "Prevents clickjacking"),
            "X-Content-Type-Options":    ("LOW",    "Prevents MIME sniffing"),
            "Referrer-Policy":           ("LOW",    "Controls referrer info"),
            "Permissions-Policy":        ("LOW",    "Controls browser features"),
        }
        # Headers that reveal server info (bad)
        self.info_disclosure_headers = [
            "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"
        ]

    async def scan(self, url):
        info(f"Checking security headers for: {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url)
                headers = response.headers

                # Check missing security headers
                for header, (severity, purpose) in self.required_headers.items():
                    if header.lower() not in [h.lower() for h in headers.keys()]:
                        finding = {
                            "type": f"Missing Security Header: {header}",
                            "url": url,
                            "severity": severity,
                            "description": f"Header '{header}' is missing. Purpose: {purpose}"
                        }
                        self.findings.append(finding)
                        warning(f"Missing header: {header}")

                # Check information disclosure headers
                for header in self.info_disclosure_headers:
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        value = headers.get(header, "")
                        finding = {
                            "type": f"Server Information Disclosure: {header}",
                            "url": url,
                            "severity": "LOW",
                            "evidence": value,
                            "description": f"Header '{header}: {value}' reveals server technology"
                        }
                        self.findings.append(finding)

        except Exception as e:
            pass

        return self.findings