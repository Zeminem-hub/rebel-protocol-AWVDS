import httpx
from utils.payloads import SENSITIVE_PATHS
from utils.logger import critical, warning

class SensitiveFileScanner:
    def __init__(self):
        self.findings = []

    async def scan(self, base_url):
        base = base_url.rstrip("/")
        
        async with httpx.AsyncClient(
            timeout=8,
            follow_redirects=False  # Don't follow redirects — 301/302 ≠ found
        ) as client:
            for path in SENSITIVE_PATHS:
                url = base + path
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        severity = "CRITICAL" if any(
                            x in path for x in [".env", ".git", "config", "sql", "backup"]
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
                        # 403 = file exists but forbidden — still worth noting
                        finding = {
                            "type": "Sensitive Path Exists (Forbidden)",
                            "url": url,
                            "severity": "LOW",
                            "evidence": "HTTP 403",
                            "description": f"Path '{path}' exists but access is restricted"
                        }
                        self.findings.append(finding)
                
                except Exception:
                    pass

        return self.findings