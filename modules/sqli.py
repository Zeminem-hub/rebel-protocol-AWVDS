import httpx
import time
import random
import string
from difflib import SequenceMatcher
from utils.logger import critical
from config import USER_AGENT

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


def _random_str(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


class SQLiScanner:
    def __init__(self, payloads, headers=None, client=None):
        self.payloads = payloads
        self.headers = {"User-Agent": USER_AGENT, **(headers or {})}
        self.findings = []
        self._external_client = client is not None
        self.client = client or httpx.AsyncClient(
            timeout=12,
            follow_redirects=True,
            headers=self.headers,
            limits=httpx.Limits(max_connections=10),
        )

    async def close(self):
        if not self._external_client:
            await self.client.aclose()

    async def scan(self, endpoint):
        # Baseline with a benign value
        baseline_params = dict(endpoint["params"])
        baseline_value = _random_str(6)
        for k in baseline_params:
            baseline_params[k] = baseline_value
        baseline = await self._send_request(endpoint, baseline_params)

        for param_name in endpoint["params"]:
            for payload in self.payloads:
                test_params = dict(endpoint["params"])
                test_params[param_name] = payload
                response = await self._send_request(endpoint, test_params)
                if response is None:
                    continue

                response_lower = response.text.lower()
                error_hit = False
                for signature in SQL_ERROR_SIGNATURES:
                    if signature in response_lower:
                        self.findings.append({
                            "type": "SQL Injection (Error-Based)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": signature,
                            "severity": "CRITICAL",
                            "confidence": 90,
                            "description": f"SQL error detected when injecting into '{param_name}'",
                        })
                        critical(f"SQL Injection found! URL: {endpoint['url']} | Param: {param_name}")
                        error_hit = True
                        break
                if error_hit:
                    continue

                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                    start_time = time.time()
                    await self._send_request(endpoint, test_params)
                    elapsed = time.time() - start_time
                    if elapsed >= 4.5:
                        # Confirm by sending a benign string of similar length
                        confirm_params = dict(endpoint["params"])
                        confirm_params[param_name] = _random_str(len(payload))
                        c_start = time.time()
                        await self._send_request(endpoint, confirm_params)
                        c_elapsed = time.time() - c_start
                        if c_elapsed < 3.0:
                            self.findings.append({
                                "type": "SQL Injection (Time-Based Blind)",
                                "url": endpoint["url"],
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"Response delayed {elapsed:.1f}s (baseline {c_elapsed:.1f}s)",
                                "severity": "CRITICAL",
                                "confidence": 85,
                                "description": "Time delay detected — database responded to SLEEP command",
                            })
                            critical(f"Blind SQL Injection found! URL: {endpoint['url']} | Param: {param_name}")
                    continue

                # Boolean/content-based diff vs baseline — tightened thresholds + confirmation
                if baseline is not None:
                    sim = SequenceMatcher(None, baseline.text, response.text).ratio()
                    len_delta = abs(len(baseline.text) - len(response.text))
                    if sim < 0.40 and len_delta > 500:
                        confirm_params = dict(endpoint["params"])
                        confirm_params[param_name] = _random_str(len(payload))
                        confirm = await self._send_request(endpoint, confirm_params)
                        if confirm is not None:
                            c_sim = SequenceMatcher(None, baseline.text, confirm.text).ratio()
                            c_len_delta = abs(len(baseline.text) - len(confirm.text))
                            if c_sim < 0.40 and c_len_delta > 500:
                                # Dynamic page — not SQLi
                                continue
                        self.findings.append({
                            "type": "SQL Injection (Boolean-Based)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"similarity={sim:.2f}, len_delta={len_delta}",
                            "severity": "HIGH",
                            "confidence": 55,
                            "description": f"Response for '{param_name}' diverges from baseline in a way consistent with boolean-based SQLi",
                        })

        return self.findings

    async def _send_request(self, endpoint, params):
        try:
            if endpoint["method"] == "POST":
                return await self.client.post(endpoint["url"], data=params)
            return await self.client.get(endpoint["url"], params=params)
        except Exception:
            return None
