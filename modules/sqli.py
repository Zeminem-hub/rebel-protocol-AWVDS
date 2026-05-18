import httpx
import asyncio
import time
import difflib
from utils.logger import critical, info

# These error messages appear when SQL injection succeeds (error-based)
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
    def __init__(self, payloads, headers=None):
        self.payloads = payloads
        self.headers = headers or {}
        self.findings = []

    async def scan(self, endpoint):
        for param_name in endpoint["params"]:
            # Step 1: fetch baseline response for this param
            baseline_response = await self._send_request(endpoint, endpoint["params"])
            if baseline_response is None:
                continue
            baseline_text = baseline_response.text
            baseline_len  = len(baseline_text)

            for payload in self.payloads:
                test_params = dict(endpoint["params"])
                test_params[param_name] = payload

                response = await self._send_request(endpoint, test_params)
                if response is None:
                    continue

                response_lower = response.text.lower()

                # ── Check 1: Error-based SQLi ──────────────────────────────
                matched_sig = None
                for signature in SQL_ERROR_SIGNATURES:
                    if signature in response_lower:
                        matched_sig = signature
                        break

                if matched_sig:
                    # Confirm it's not in the baseline too (avoid FP on noisy apps)
                    if matched_sig not in baseline_text.lower():
                        # Extra check: response must be meaningfully different
                        similarity = difflib.SequenceMatcher(
                            None, baseline_text[:3000], response.text[:3000]
                        ).ratio()

                        confidence = int((1 - similarity) * 60 + 40)  # 40-100 range
                        confidence = min(confidence, 95)

                        finding = {
                            "type": "SQL Injection (Error-Based)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f'DB error signature: "{matched_sig}"',
                            "severity": "CRITICAL",
                            "confidence": confidence,
                            "cwe": "CWE-89",
                            "recommendation": "Use parameterized queries / prepared statements",
                            "description": (
                                f"SQL error detected when injecting into '{param_name}'. "
                                f"Error signature confirmed absent in baseline response."
                            )
                        }
                        self.findings.append(finding)
                        critical(f"SQLi (Error-Based) | {endpoint['url']} | param={param_name} | confidence={confidence}%")
                        break  # one confirmed finding per param per payload type is enough

                # ── Check 2: Time-based blind SQLi ─────────────────────────
                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                    start = time.time()
                    timed_response = await self._send_request(endpoint, test_params)
                    elapsed = time.time() - start

                    # Only flag if delay is clearly above normal (baseline comparison)
                    baseline_start = time.time()
                    await self._send_request(endpoint, endpoint["params"])
                    baseline_elapsed = time.time() - baseline_start

                    # True positive: injected delay >> baseline response time
                    if elapsed >= 4.5 and elapsed > baseline_elapsed * 2.5:
                        confidence = 90 if elapsed >= 6 else 75
                        finding = {
                            "type": "SQL Injection (Time-Based Blind)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": (
                                f"Injected delay: {elapsed:.1f}s | "
                                f"Baseline: {baseline_elapsed:.1f}s"
                            ),
                            "severity": "CRITICAL",
                            "confidence": confidence,
                            "cwe": "CWE-89",
                            "recommendation": "Use parameterized queries / prepared statements",
                            "description": (
                                f"Response delayed {elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s — "
                                f"database responded to time-delay command in '{param_name}'."
                            )
                        }
                        self.findings.append(finding)
                        critical(
                            f"SQLi (Time-Based Blind) | {endpoint['url']} | "
                            f"param={param_name} | delay={elapsed:.1f}s | confidence={confidence}%"
                        )

                # ── Check 3: Structural diff (boolean-based indicator) ──────
                # If error signatures not found but response is radically different
                # from baseline, flag as low-confidence indicator only
                similarity = difflib.SequenceMatcher(
                    None, baseline_text[:3000], response.text[:3000]
                ).ratio()

                # Response length changed drastically AND content very different
                len_delta = abs(len(response.text) - baseline_len)
                if similarity < 0.55 and len_delta > 200:
                    # Only add if no higher-confidence finding already found for this param
                    already_found = any(
                        f["parameter"] == param_name and f["url"] == endpoint["url"]
                        and f["confidence"] >= 60
                        for f in self.findings
                    )
                    if not already_found:
                        finding = {
                            "type": "SQL Injection (Possible — Boolean Response Diff)",
                            "url": endpoint["url"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": (
                                f"Response similarity: {similarity:.0%} | "
                                f"Length delta: {len_delta} bytes"
                            ),
                            "severity": "HIGH",
                            "confidence": 40,
                            "cwe": "CWE-89",
                            "recommendation": "Manually verify — response structure changed significantly on injection",
                            "description": (
                                f"Response structure changed significantly vs baseline "
                                f"when injecting into '{param_name}'. Requires manual confirmation."
                            )
                        }
                        self.findings.append(finding)

        return self.findings

    async def _send_request(self, endpoint, params):
        try:
            async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
                headers = {"User-Agent": "Mozilla/5.0 (AVWDS Scanner)", **self.headers}
                if endpoint["method"] == "POST":
                    return await client.post(endpoint["url"], data=params, headers=headers)
                else:
                    return await client.get(endpoint["url"], params=params, headers=headers)
        except Exception:
            return None

