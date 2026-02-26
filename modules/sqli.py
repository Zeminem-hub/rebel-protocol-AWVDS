import httpx
import asyncio
import time
from utils.logger import critical, info

# These error messages appear when SQL injection succeeds
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_fetch",
    "warning: mysql_num_rows",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-00933",
    "ora-00907",
    "pg_query()",
    "supplied argument is not a valid mysql",
    "sqlite3::exception",
    "mssql_query()",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
]

class SQLiScanner:
    def __init__(self, payloads):
        self.payloads = payloads
        self.findings = []

    async def scan(self, endpoint):
        for param_name in endpoint["params"]:
            for payload in self.payloads:
                # Replace one param with payload, keep others normal
                test_params = dict(endpoint["params"])
                test_params[param_name] = payload

                response = await self._send_request(endpoint, test_params)
                
                if response is None:
                    continue

                # Check 1: Error-based SQLi
                response_lower = response.text.lower()
                for signature in SQL_ERROR_SIGNATURES:
                    if signature in response_lower:
                        finding = {
                            "type": "SQL Injection (Error-Based)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": signature,
                            "severity": "CRITICAL",
                            "description": f"SQL error detected when injecting into '{param_name}'"
                        }
                        self.findings.append(finding)
                        critical(f"SQL Injection found! URL: {endpoint['url']} | Param: {param_name}")
                        break

                # Check 2: Time-based blind SQLi
                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                    start_time = time.time()
                    await self._send_request(endpoint, test_params)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= 4.5:  # 5 second sleep was triggered
                        finding = {
                            "type": "SQL Injection (Time-Based Blind)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Response delayed {elapsed:.1f} seconds",
                            "severity": "CRITICAL",
                            "description": f"Time delay detected — database responded to SLEEP command"
                        }
                        self.findings.append(finding)
                        critical(f"Blind SQL Injection found! URL: {endpoint['url']} | Param: {param_name}")

        return self.findings

    async def _send_request(self, endpoint, params):
        try:
            async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
                headers = {"User-Agent": "Mozilla/5.0 (AVWDS Scanner)"}
                if endpoint["method"] == "POST":
                    return await client.post(endpoint["url"], data=params, headers=headers)
                else:
                    return await client.get(endpoint["url"], params=params, headers=headers)
        except Exception:
            return None