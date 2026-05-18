import httpx
from utils.logger import warning, info

class HeadersScanner:
    def __init__(self, headers=None):
        self.findings = []
        self.headers  = headers or {}

        # Header → (severity, description, only_on_html)
        # only_on_html=True means skip this check for JSON/binary responses
        self.security_headers = {
            "Content-Security-Policy": (
                "HIGH",
                "Prevents XSS by restricting resource loading origins",
                True   # Only relevant on HTML pages
            ),
            "Strict-Transport-Security": (
                "MEDIUM",
                "Forces HTTPS — only meaningful on HTTPS endpoints",
                False
            ),
            "X-Frame-Options": (
                "MEDIUM",
                "Prevents clickjacking by blocking iframe embedding",
                True
            ),
            "X-Content-Type-Options": (
                "LOW",
                "Prevents MIME-type sniffing attacks",
                False
            ),
            "Referrer-Policy": (
                "LOW",
                "Controls how much referrer info is sent with requests",
                False
            ),
            "Permissions-Policy": (
                "LOW",
                "Restricts browser features (camera, mic, geolocation)",
                False
            ),
        }

        # Headers that expose server internals — always informational
        self.disclosure_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
            "X-Generator",
            "X-Runtime",
            "X-Version",
        ]

    async def scan(self, url):
        info(f"Checking security headers: {url}")
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(url, headers=self.headers)
                resp_headers = response.headers
                content_type = resp_headers.get("content-type", "").lower()

                is_html     = "text/html" in content_type
                is_https    = url.startswith("https://")
                headers_lc  = {k.lower(): v for k, v in resp_headers.items()}

                # ── Check missing security headers ────────────────────────
                for header, (severity, purpose, html_only) in self.security_headers.items():
                    # Skip HTML-only headers for non-HTML responses (API endpoints, etc.)
                    if html_only and not is_html:
                        continue

                    # HSTS only matters on HTTPS
                    if header == "Strict-Transport-Security" and not is_https:
                        continue

                    if header.lower() not in headers_lc:
                        finding = {
                            "type": f"Missing Security Header: {header}",
                            "url": url,
                            "severity": severity,
                            "confidence": 95,
                            "cwe": "CWE-693",
                            "recommendation": self._get_recommendation(header),
                            "description": f"'{header}' not set. {purpose}.",
                        }
                        self.findings.append(finding)
                        warning(f"Missing header: {header} on {url}")

                # ── Check information disclosure ───────────────────────────
                for header in self.disclosure_headers:
                    if header.lower() in headers_lc:
                        value = headers_lc[header.lower()]
                        # Only flag if value is non-trivial (some servers send empty headers)
                        if value and len(value.strip()) > 0:
                            finding = {
                                "type": f"Server Information Disclosure: {header}",
                                "url": url,
                                "severity": "LOW",
                                "evidence": f"{header}: {value}",
                                "confidence": 90,
                                "cwe": "CWE-200",
                                "recommendation": f"Remove or obscure the '{header}' response header.",
                                "description": (
                                    f"Header '{header}: {value}' reveals server technology. "
                                    "This helps attackers fingerprint the stack."
                                ),
                            }
                            self.findings.append(finding)

                # ── Check HTTPS redirect (only on HTTP) ───────────────────
                if not is_https and response.status_code in (301, 302):
                    location = headers_lc.get("location", "")
                    if not location.startswith("https://"):
                        finding = {
                            "type": "Insecure HTTP Redirect",
                            "url": url,
                            "severity": "MEDIUM",
                            "evidence": f"Redirects to: {location}",
                            "confidence": 85,
                            "cwe": "CWE-319",
                            "recommendation": "Ensure all HTTP traffic redirects to HTTPS.",
                            "description": "Site redirects but not to HTTPS — traffic may be intercepted.",
                        }
                        self.findings.append(finding)

        except Exception:
            pass

        return self.findings

    def _get_recommendation(self, header):
        recs = {
            "Content-Security-Policy":    "Add CSP header: Content-Security-Policy: default-src 'self'",
            "Strict-Transport-Security":  "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "X-Frame-Options":            "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)",
            "X-Content-Type-Options":     "Add: X-Content-Type-Options: nosniff",
            "Referrer-Policy":            "Add: Referrer-Policy: strict-origin-when-cross-origin",
            "Permissions-Policy":         "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        }
        return recs.get(header, f"Add the '{header}' response header with appropriate value.")
