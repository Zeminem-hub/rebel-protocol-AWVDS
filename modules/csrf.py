import httpx
from bs4 import BeautifulSoup
from utils.logger import warning

class CSRFScanner:
    def __init__(self):
        self.findings = []
        # Names that indicate a CSRF token is present
        self.csrf_token_names = [
            "csrf", "token", "_token", "csrftoken",
            "csrf_token", "authenticity_token", "_csrf",
            "xsrf", "xsrftoken", "_xsrf",
        ]

    async def scan(self, endpoint, session_cookies=None):
        """
        session_cookies: dict of cookies from the actual HTTP response,
        used to check SameSite policy.
        """
        # Only POST forms are CSRF-relevant
        if endpoint["method"] != "POST":
            return []

        params         = endpoint["params"]
        param_names_lc = [p.lower() for p in params.keys()]

        # ── Gate 1: CSRF token in form fields? ────────────────────────────
        has_token_field = any(
            tok in name
            for tok in self.csrf_token_names
            for name in param_names_lc
        )
        if has_token_field:
            return self.findings  # Protected — skip

        # ── Gate 2: Check SameSite cookie policy ──────────────────────────
        # If the session cookie uses SameSite=Strict or Lax, CSRF risk is low
        if session_cookies:
            for cookie_name, cookie_meta in session_cookies.items():
                samesite = str(cookie_meta.get("samesite", "")).lower()
                if samesite in ("strict", "lax"):
                    return self.findings  # SameSite protection present — skip

        # ── Gate 3: Fetch the form's page and check for meta CSRF token ───
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
                response = await client.get(endpoint.get("source", endpoint["url"]))

                # Check Content-Type: JSON-only APIs are CSRF-resistant by default
                content_type = response.headers.get("content-type", "").lower()
                if "application/json" in content_type:
                    return self.findings  # JSON endpoint — not CSRF vulnerable

                # Check for meta CSRF token (common in Django, Rails)
                html = response.text
                soup = BeautifulSoup(html, "html.parser")
                for meta in soup.find_all("meta"):
                    name = (meta.get("name") or "").lower()
                    if any(tok in name for tok in self.csrf_token_names):
                        return self.findings  # Meta token found — protected

                # Check for X-CSRF-Token or similar headers in response
                for header in response.headers:
                    if "csrf" in header.lower() or "xsrf" in header.lower():
                        return self.findings  # Header-based protection present

        except Exception:
            pass  # Network error — proceed with finding (conservative)

        # ── All gates failed: flag it ──────────────────────────────────────
        finding = {
            "type": "Missing CSRF Protection",
            "url": endpoint["url"],
            "method": "POST",
            "severity": "MEDIUM",
            "confidence": 70,
            "cwe": "CWE-352",
            "recommendation": (
                "Add a synchronizer token to all state-changing forms. "
                "Set SameSite=Strict or Lax on session cookies as a secondary defense."
            ),
            "description": (
                f"POST form at '{endpoint['url']}' has no CSRF token field, "
                "no SameSite cookie protection detected, and no meta/header token. "
                "An attacker may be able to forge cross-site requests on behalf of authenticated users."
            )
        }
        self.findings.append(finding)
        warning(f"CSRF | {endpoint['url']} | no token, no SameSite — confidence=70%")

        return self.findings
