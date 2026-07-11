from utils.logger import warning


class CSRFScanner:
    def __init__(self):
        self.findings = []
        self.csrf_token_names = [
            "csrf", "token", "_token", "csrftoken",
            "csrf_token", "authenticity_token", "_csrf",
        ]

    async def close(self):
        return None

    async def scan(self, endpoint, page_html=None):
        local: list[dict] = []
        if endpoint["method"] != "POST":
            return local

        params = endpoint["params"]
        param_names_lower = [p.lower() for p in params.keys()]
        has_csrf_token = any(t in param_names_lower for t in self.csrf_token_names)

        if not has_csrf_token:
            local.append({
                "type": "Missing CSRF Token",
                "url": endpoint["url"],
                "severity": "MEDIUM",
                "confidence": 70,
                "description": f"POST form at '{endpoint['url']}' has no CSRF token — vulnerable to cross-site request forgery",
            })
            warning(f"CSRF vulnerability: {endpoint['url']}")

        return local
