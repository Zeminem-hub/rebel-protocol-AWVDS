import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import asyncio
from utils.logger import info, error
from config import USER_AGENT


class Crawler:
    def __init__(self, base_url, depth=2, timeout=10, headers=None):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.depth = depth
        self.timeout = timeout
        self.headers = {"User-Agent": USER_AGENT, **(headers or {})}
        self.visited_urls = set()
        self.endpoints = []
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=self.headers,
            limits=httpx.Limits(max_connections=10),
        )

    async def start(self):
        info(f"Crawler starting on: {self.base_url}")
        try:
            await self._crawl(self.base_url, current_depth=0)
        finally:
            await self._client.aclose()
        info(f"Crawl complete. Found {len(self.endpoints)} endpoints.")
        return self.endpoints

    async def _crawl(self, url, current_depth):
        if current_depth > self.depth or url in self.visited_urls:
            return
        self.visited_urls.add(url)
        info(f"Visiting: {url}")

        html = await self._fetch_page(url)
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        links = soup.find_all("a", href=True)

        # If the initial page returns almost nothing interactive, retry with a
        # headless browser — SPAs and JS-rendered pages need it.
        if current_depth == 0 and len(forms) < 2 and len(links) < 5:
            info("Sparse HTML — retrying with Playwright headless Chromium")
            js_html = await self._fetch_page_js(url)
            if js_html:
                soup = BeautifulSoup(js_html, "html.parser")
                forms = soup.find_all("form")
                links = soup.find_all("a", href=True)

        self._extract_forms(url, forms)
        self._extract_url_params(url)

        tasks = []
        for tag in links:
            link = urljoin(url, tag["href"])
            if self.domain in link and link not in self.visited_urls:
                link = link.split("#")[0]
                if link:
                    tasks.append(self._crawl(link, current_depth + 1))
        if tasks:
            await asyncio.gather(*tasks)

    async def _fetch_page(self, url):
        try:
            response = await self._client.get(url)
            text = response.text
            # Cheap tag counts for debugging — helps distinguish blocked/UA-filtered
            # responses from JS-rendered pages.
            a_count = text.lower().count("<a ")
            form_count = text.lower().count("<form")
            info(f"[fetch] {response.status_code} {url} · <a>={a_count} <form>={form_count}")
            return text
        except Exception as e:
            error(f"Failed to fetch {url}: {e}")
            return None

    async def _fetch_page_js(self, url):
        try:
            from playwright.async_api import async_playwright
        except Exception as e:
            error(f"Playwright not available: {e}")
            return None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    extra_http_headers=self.headers,
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                try:
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                except Exception:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                content = await page.content()
                await browser.close()
                return content
        except Exception as e:
            error(f"Playwright fetch failed for {url}: {e}")
            return None

    def _extract_forms(self, page_url, forms):
        for form in forms:
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
                self.endpoints.append({
                    "url": action_url,
                    "method": method,
                    "params": params,
                    "source": page_url,
                    "type": "form",
                })
                info(f"Found form: {method} {action_url} with params: {list(params.keys())}")

    def _extract_url_params(self, url):
        parsed = urlparse(url)
        if parsed.query:
            params = {}
            for part in parsed.query.split("&"):
                if "=" in part:
                    key, val = part.split("=", 1)
                    params[key] = val
            if params:
                self.endpoints.append({
                    "url": parsed.scheme + "://" + parsed.netloc + parsed.path,
                    "method": "GET",
                    "params": params,
                    "source": url,
                    "type": "url_params",
                })
