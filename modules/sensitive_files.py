import httpx
from utils.payloads import SENSITIVE_PATHS
from utils.logger import critical, warning, info

# Content patterns that confirm a file is real, not a soft 404
FILE_CONTENT_VALIDATORS = {
    ".env": [
        "DB_PASSWORD", "APP_KEY", "APP_SECRET", "DATABASE_URL",
        "SECRET_KEY", "API_KEY", "AWS_", "MAIL_PASSWORD", "=",
    ],
    ".git/config": ["[core]", "[remote", "repositoryformatversion", "filemode"],
    ".git/HEAD":   ["ref:", "refs/heads/"],
    "config.php":  ["$db", "<?php", "define(", "password", "DB_"],
    "wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix", "<?php"],
    ".htaccess":   ["RewriteEngine", "RewriteRule", "Options", "AllowOverride"],
    "web.config":  ["<configuration>", "<connectionStrings>", "<appSettings>"],
    "backup":      [],   # Any 200 for backup files is suspicious — no extra validation
    "sql":         ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "mysqldump"],
    "swagger":     ['"swagger"', '"openapi"', '"paths"'],
    "actuator":    ['"status"', '"health"', '"upStatus"'],
    "robots.txt":  ["User-agent:", "Disallow:"],    # Always real if 200
    "sitemap.xml": ["<urlset", "<sitemap", "<?xml"],
}

class SensitiveFileScanner:
    def __init__(self, headers=None):
        self.findings     = []
        self.headers      = headers or {}
        self._soft404_len = None   # Will be set after probing a known-bad URL

    async def scan(self, base_url):
        base = base_url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=8,
            follow_redirects=False  # 301/302 ≠ found
        ) as client:
            # ── Step 0: Detect soft-404 signature ─────────────────────────
            # Fetch a URL that definitely doesn't exist, record response length
            probe_url = base + "/___nonexistent_probe_12345___"
            try:
                probe_resp = await client.get(probe_url, headers=self.headers)
                if probe_resp.status_code == 200:
                    self._soft404_len = len(probe_resp.text)
                    info(f"Soft-404 detected (length={self._soft404_len}). Will use content validation.")
            except Exception:
                pass

            for path in SENSITIVE_PATHS:
                url = base + path
                try:
                    response = await client.get(url, headers=self.headers)

                    if response.status_code == 200:
                        if not self._is_real_file(response, path):
                            continue  # Soft 404 — skip

                        severity = self._get_severity(path)
                        finding = {
                            "type": "Sensitive File Exposed",
                            "url": url,
                            "severity": severity,
                            "evidence": f"HTTP 200 — content validated as real {path.split('.')[-1].upper()} file",
                            "confidence": 88,
                            "cwe": "CWE-538",
                            "recommendation": f"Block access to '{path}' via server config or .htaccess. Remove from web root.",
                            "description": (
                                f"File at '{path}' is publicly accessible and content confirms it is genuine. "
                                "This may expose credentials, source code, or database contents."
                            )
                        }
                        self.findings.append(finding)
                        critical(f"Sensitive file: {url} [{severity}]")

                    elif response.status_code == 403:
                        # 403 = file exists but access is blocked — low severity note
                        finding = {
                            "type": "Sensitive Path Exists (Access Forbidden)",
                            "url": url,
                            "severity": "LOW",
                            "evidence": "HTTP 403 — resource exists but access is restricted",
                            "confidence": 70,
                            "cwe": "CWE-538",
                            "recommendation": "Confirm this path cannot be accessed via other means (path traversal, etc.)",
                            "description": (
                                f"'{path}' returned 403 — the file/directory exists but is blocked. "
                                "Access controls may be bypassable."
                            )
                        }
                        self.findings.append(finding)

                except Exception:
                    pass

        return self.findings

    def _is_real_file(self, response, path: str) -> bool:
        body = response.text
        body_len = len(body)

        # ── Check 1: Soft-404 length match ────────────────────────────────
        if self._soft404_len is not None:
            # Allow 5% variance for dynamic elements (timestamps, etc.)
            delta = abs(body_len - self._soft404_len)
            if delta < max(50, self._soft404_len * 0.05):
                return False  # Same length as known-404 — it's a soft 404

        # ── Check 2: Generic 404 page keywords ────────────────────────────
        body_lc = body.lower()
        generic_404_markers = [
            "page not found", "404 not found", "doesn't exist",
            "does not exist", "no page found", "error 404",
            "the page you", "could not be found",
        ]
        if any(marker in body_lc for marker in generic_404_markers):
            return False  # Looks like a custom 404 page

        # ── Check 3: Content validation per file type ─────────────────────
        for key, validators in FILE_CONTENT_VALIDATORS.items():
            if key in path.lower():
                if not validators:
                    return True   # Unconditional (backups, etc.)
                return any(v in body for v in validators)

        # ── Fallback: treat as real if none of the above triggered ────────
        # (e.g. /admin, /phpmyadmin — presence itself is notable)
        return True

    def _get_severity(self, path: str) -> str:
        critical_patterns = [".env", ".git", "config", ".sql", "backup", "wp-config"]
        high_patterns     = ["swagger", "actuator", "phpmyadmin", ".htaccess", "web.config"]

        path_lc = path.lower()
        if any(p in path_lc for p in critical_patterns):
            return "CRITICAL"
        if any(p in path_lc for p in high_patterns):
            return "HIGH"
        return "MEDIUM"
