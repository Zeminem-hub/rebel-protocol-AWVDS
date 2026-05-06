import asyncio
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from utils.logger import error, info


class Crawler:
    def __init__(self, base_url, depth=2, timeout=6, max_pages=30, max_endpoints=40):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.depth = depth
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_endpoints = max_endpoints
        self.visited_urls = set()
        self.endpoints = []
        self.errors = []

    async def start(self):
        info(f"Crawler starting on: {self.base_url}")
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            limits=limits,
            headers={"User-Agent": "Mozilla/5.0 (Security Research Scanner)"}
        ) as client:
            await self._crawl(self.base_url, current_depth=0, client=client)

        info(f"Crawl complete. Found {len(self.endpoints)} endpoints.")
        return self.endpoints

    async def _crawl(self, url, current_depth, client):
        if (
            current_depth > self.depth
            or url in self.visited_urls
            or len(self.visited_urls) >= self.max_pages
            or len(self.endpoints) >= self.max_endpoints
        ):
            return

        self.visited_urls.add(url)
        info(f"Visiting: {url}")

        html = await self._fetch_page(url, client)
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")
        self._extract_forms(url, soup)
        self._extract_url_params(url)

        tasks = []
        for tag in soup.find_all("a", href=True):
            if len(self.visited_urls) + len(tasks) >= self.max_pages:
                break
            link = self._normalize_link(url, tag["href"])
            if link and link not in self.visited_urls:
                tasks.append(self._crawl(link, current_depth + 1, client))

        if tasks:
            await asyncio.gather(*tasks)

    def _normalize_link(self, page_url, href):
        link = urljoin(page_url, href).split("#")[0]
        parsed = urlparse(link)

        if parsed.scheme not in ("http", "https"):
            return None
        if parsed.netloc != self.domain:
            return None
        if parsed.path.lower().endswith((
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".pdf", ".zip", ".rar", ".7z", ".mp4", ".webm",
            ".woff", ".woff2", ".ttf"
        )):
            return None

        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme}://{parsed.netloc}{path}{query}".rstrip("/")

    async def _fetch_page(self, url, client):
        try:
            response = await client.get(url)
            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return None
            return response.text
        except Exception as exc:
            self.errors.append(f"{url}: {exc}")
            error(f"Failed to fetch {url}: {exc}")
            return None

    def _extract_forms(self, page_url, soup):
        if len(self.endpoints) >= self.max_endpoints:
            return

        for form in soup.find_all("form"):
            if len(self.endpoints) >= self.max_endpoints:
                break

            action = form.get("action", page_url)
            action_url = urljoin(page_url, action)
            method = form.get("method", "GET").upper()
            params = {}

            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                value = input_tag.get("value", "test")
                if name:
                    params[name] = value

            if params:
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
        if len(self.endpoints) >= self.max_endpoints:
            return

        parsed = urlparse(url)
        if not parsed.query:
            return

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
