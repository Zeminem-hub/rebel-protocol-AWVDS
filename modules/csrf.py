import httpx
from bs4 import BeautifulSoup
from utils.logger import warning

class CSRFScanner:
    def __init__(self):
        self.findings = []
        # These token names indicate CSRF protection is present
        self.csrf_token_names = [
            "csrf", "token", "_token", "csrftoken",
            "csrf_token", "authenticity_token", "_csrf"
        ]

    async def scan(self, endpoint, page_html=None):
        # Only check POST forms — GET forms aren't CSRF vulnerable
        if endpoint["method"] != "POST":
            return []

        params = endpoint["params"]
        param_names_lower = [p.lower() for p in params.keys()]

        # Check if any param looks like a CSRF token
        has_csrf_token = any(
            token in param_names_lower
            for token in self.csrf_token_names
        )

        if not has_csrf_token:
            finding = {
                "type": "Missing CSRF Token",
                "url": endpoint["url"],
                "severity": "MEDIUM",
                "description": f"POST form at '{endpoint['url']}' has no CSRF token — vulnerable to cross-site request forgery"
            }
            self.findings.append(finding)
            warning(f"CSRF vulnerability: {endpoint['url']}")

        return self.findings