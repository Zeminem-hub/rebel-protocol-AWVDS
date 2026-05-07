import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import asyncio
from utils.logger import info, error

class Crawler:
    def __init__(self, base_url, depth=2, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.depth = depth
        self.timeout = timeout
        self.visited_urls = set()
        self.endpoints = []   # All discovered forms & URL params

    async def start(self):
        info(f"Crawler starting on: {self.base_url}")
        await self._crawl(self.base_url, current_depth=0)
        info(f"Crawl complete. Found {len(self.endpoints)} endpoints.")
        return self.endpoints

    async def _crawl(self, url, current_depth):
        # Stop if we've been here or gone too deep
        if current_depth > self.depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        info(f"Visiting: {url}")

        html = await self._fetch_page(url)
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")
        
        # Extract forms from this page
        self._extract_forms(url, soup)
        
        # Extract URL parameters from this page
        self._extract_url_params(url)

        # Find all links and crawl them too
        tasks = []
        for tag in soup.find_all("a", href=True):
            link = urljoin(url, tag["href"])
            # Only follow links on same domain
            if self.domain in link and link not in self.visited_urls:
                # Remove fragments like #section
                link = link.split("#")[0]
                if link:
                    tasks.append(self._crawl(link, current_depth + 1))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _fetch_page(self, url):
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                headers = {"User-Agent": "Mozilla/5.0 (AVWDS Scanner)"}
                response = await client.get(url, headers=headers)
                return response.text
        except Exception as e:
            error(f"Failed to fetch {url}: {e}")
            return None

    def _extract_forms(self, page_url, soup):
        for form in soup.find_all("form"):
            action = form.get("action", page_url)
            action_url = urljoin(page_url, action)
            method = form.get("method", "GET").upper()
            
            # Get all input fields
            params = {}
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                value = input_tag.get("value", "test")
                if name:
                    params[name] = value

            if params:  # Only add if there are input fields
                endpoint = {
                    "url": action_url,
                    "method": method,
                    "params": params,
                    "source": page_url,
                    "type": "form"
                }
                self.endpoints.append(endpoint)
                info(f"Found form: {method} {action_url} with params: {list(params.keys())}")

    def _extract_url_params(self, url):
        parsed = urlparse(url)
        if parsed.query:
            # Convert query string to dict
            params = {}
            for part in parsed.query.split("&"):
                if "=" in part:
                    key, val = part.split("=", 1)
                    params[key] = val
            
            if params:
                endpoint = {
                    "url": parsed.scheme + "://" + parsed.netloc + parsed.path,
                    "method": "GET",
                    "params": params,
                    "source": url,
                    "type": "url_params"
                }
                self.endpoints.append(endpoint)