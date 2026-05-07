"""
crawler.py — Rebel Protocol AWVDS
Recursive async web crawler. Discovers links, forms, query params,
hidden inputs, and API endpoints. Drop-in replacement.
"""

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import httpx
from bs4 import BeautifulSoup


def normalize_url(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", p.params, p.query, ""))


def same_domain(base: str, candidate: str) -> bool:
    return urlparse(base).netloc == urlparse(candidate).netloc


def extract_links(base_url: str, html: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    found = set()
    for tag in soup.find_all(True):
        for attr in ("href", "src", "action", "data-url", "data-href"):
            val = tag.get(attr)
            if val and not val.startswith(("javascript:", "mailto:", "#", "tel:")):
                found.add(urljoin(base_url, val.strip()))
    for script in soup.find_all("script"):
        if script.string:
            for m in re.finditer(r"""(?:fetch|axios\.(?:get|post)|url\s*[:=])\s*['"`]([^'"`]+)['"`]""", script.string):
                candidate = m.group(1)
                if candidate.startswith(("/", "http")):
                    found.add(urljoin(base_url, candidate))
    return list(found)


def extract_forms(base_url: str, html: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        url    = urljoin(base_url, action) if action else base_url
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            itype = tag.get("type", "text").lower()
            val   = tag.get("value", "")
            if tag.name == "select":
                opt = tag.find("option")
                val = opt.get("value", "") if opt else ""
            inputs.append({"name": name, "type": itype, "value": val})
        forms.append({"url": url, "method": method, "inputs": inputs})
    return forms


def extract_params(url: str) -> dict:
    return parse_qs(urlparse(url).query)


class Crawler:
    def __init__(self, base_url, max_depth=3, max_pages=200, timeout=10.0, cookies=None, extra_headers=None):
        self.base_url  = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout   = timeout
        self.cookies   = cookies or {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if extra_headers:
            self.headers.update(extra_headers)
        self.visited_urls = set()
        self.endpoints    = []
        self.forms        = []
        self.errors       = []

    async def _get(self, url):
        for attempt in range(2):
            try:
                return await self._session.get(url, headers=self.headers, cookies=self.cookies,
                                               follow_redirects=True, timeout=self.timeout)
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if attempt == 1:
                    self.errors.append(f"GET {url} → {e}")
                await asyncio.sleep(0.5)
        return None

    def _register_endpoint(self, url, method, params, source):
        key = f"{method.upper()}:{normalize_url(url)}:{sorted(params.keys())}"
        if key not in self._seen_endpoints:
            self._seen_endpoints.add(key)
            self.endpoints.append({"url": url, "method": method.upper(), "params": params, "source": source})

    async def crawl(self):
        self._seen_endpoints = set()
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as session:
            self._session = session
            queue = deque([(self.base_url, 0)])
            while queue and len(self.visited_urls) < self.max_pages:
                url, depth = queue.popleft()
                norm = normalize_url(url)
                if norm in self.visited_urls or not same_domain(self.base_url, url):
                    continue
                self.visited_urls.add(norm)
                resp = await self._get(url)
                if resp is None:
                    continue
                if "text/html" not in resp.headers.get("content-type", ""):
                    params = extract_params(url)
                    if params:
                        self._register_endpoint(url, "GET", params, "api-discovery")
                    continue
                html = resp.text
                params = extract_params(url)
                if params:
                    self._register_endpoint(url, "GET", params, "crawl")
                for form in extract_forms(url, html):
                    self.forms.append(form)
                    form_params = {inp["name"]: inp["value"] for inp in form["inputs"]}
                    self._register_endpoint(form["url"], form["method"], form_params, "form")
                self._register_endpoint(url, "GET", {}, "page")
                if depth < self.max_depth:
                    for link in extract_links(url, html):
                        if normalize_url(link) not in self.visited_urls and same_domain(self.base_url, link):
                            queue.append((link, depth + 1))
                await asyncio.sleep(0.05)
        return {"base_url": self.base_url, "visited": list(self.visited_urls),
                "endpoints": self.endpoints, "forms": self.forms, "errors": self.errors}


def run_crawl(base_url, max_depth=3, max_pages=200, timeout=10.0, cookies=None):
    return asyncio.run(Crawler(base_url, max_depth, max_pages, timeout, cookies).crawl())
