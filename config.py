TARGET_URL = "http://testphp.vulnweb.com"  # Change this to your target

SCAN_DEPTH = 2          # How many pages deep to crawl
TIMEOUT = 10            # Seconds before giving up on a request
USE_JS_RENDERING = False # Set True for JavaScript-heavy sites
MAX_THREADS = 5         # How many scans run simultaneously
DELAY_BETWEEN_REQUESTS = 0.5  # Seconds between requests (be polite)

OUTPUT_FILE = "report.json"
LOG_FILE = "scan.log"

USER_AGENT = "Mozilla/5.0 (AVWDS Security Scanner)"