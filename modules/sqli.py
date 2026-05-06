import asyncio
import time

import httpx

from utils.logger import critical


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
    def __init__(self, payloads, concurrency=6):
        self.payloads = payloads
        self.concurrency = concurrency
        self.findings = []

    async def scan(self, endpoint):
        semaphore = asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(
            timeout=6,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Security Research Scanner)"}
        ) as client:
            tasks = []
            for param_name in endpoint["params"]:
                for payload in self.payloads:
                    tasks.append(self._test_payload(client, semaphore, endpoint, param_name, payload))
            await asyncio.gather(*tasks)

        return self.findings

    async def _test_payload(self, client, semaphore, endpoint, param_name, payload):
        async with semaphore:
            test_params = dict(endpoint["params"])
            test_params[param_name] = payload
            start_time = time.time()
            response = await self._send_request(client, endpoint, test_params)

            if response is None:
                return

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
                    return

            if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                elapsed = time.time() - start_time
                if elapsed >= 4.5:
                    finding = {
                        "type": "SQL Injection (Time-Based Blind)",
                        "url": endpoint["url"],
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": f"Response delayed {elapsed:.1f} seconds",
                        "severity": "CRITICAL",
                        "description": f"Time delay detected when injecting into '{param_name}'"
                    }
                    self.findings.append(finding)
                    critical(f"Blind SQL Injection found! URL: {endpoint['url']} | Param: {param_name}")

    async def _send_request(self, client, endpoint, params):
        try:
            if endpoint["method"] == "POST":
                return await client.post(endpoint["url"], data=params)
            return await client.get(endpoint["url"], params=params)
        except Exception:
            return None
