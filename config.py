TARGET_URL = "http://testphp.vulnweb.com"  # Change this to your target

SCAN_DEPTH = 2          # How many pages deep to crawl
TIMEOUT = 10            # Seconds before giving up on a request
USE_JS_RENDERING = False # Set True for JavaScript-heavy sites
MAX_THREADS = 5         # How many scans run simultaneously
MAX_ENDPOINTS = 40      # Cap endpoints scanned per run (crawl finds all, scan hits top N)
ENDPOINT_CONCURRENCY = 10  # How many endpoints get scanned in parallel
DELAY_BETWEEN_REQUESTS = 0.5  # Seconds between requests (be polite)

OUTPUT_FILE = "report.json"
LOG_FILE = "scan.log"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"