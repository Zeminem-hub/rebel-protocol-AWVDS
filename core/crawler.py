import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from urllib.robotparser import RobotFileParser
import asyncio
from utils.logger import info, error, warning

class Crawler:
    def __init__(self, base_url, depth=2, timeout=10, headers=None):
        self.base_url     = base_url.rstrip("/")
        self.parsed_base  = urlparse(base_url)
        self.domain       = self.parsed_base.netloc
        self.scheme       = self.parsed_base.scheme
        self.depth        = depth
        self.timeout      = timeout
        self.headers      = headers or {}
        self.visited_urls = set()
        self.endpoints    = []
        self._endpoint_sigs = set()  # For deduplication of endpoints
        self._robot_parser  = None

    async def start(self):
        info(f"Crawler starting: {self.base_url} (depth={self.depth})")
        await self._load_robots_txt()
        await self._crawl(self.base_url, current_depth=0)
        info(f"Crawl complete. {len(self.endpoints)} unique endpoints found.")
        return self.endpoints

    # ── robots.txt ────────────────────────────────────────────────────────
    async def _load_robots_txt(self):
        robots_url = f"{self.scheme}://{self.domain}/robots.txt"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(robots_url)
                if resp.status_code == 200:
                    parser = RobotFileParser()
                    parser.parse(resp.text.splitlines())
                    self._robot_parser = parser
                    info("robots.txt loaded — disallowed paths will be skipped")
        except Exception:
            pass

    def _is_allowed(self, url: str) -> bool:
        if self._robot_parser is None:
            return True
        return self._robot_parser.can_fetch("*", url)

    # ── URL normalization ─────────────────────────────────────────────────
    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        # Sort query params for stable deduplication
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            sorted_qs = urlencode(sorted(qs.items()), doseq=True)
        else:
            sorted_qs = ""
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/") or "/",
            "",          # params
            sorted_qs,
            "",          # fragment — always strip
        ))
        return normalized

    def _is_same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc.lower() == self.domain.lower()

    # ── Core crawl ────────────────────────────────────────────────────────
    async def _crawl(self, url: str, current_depth: int):
        normalized = self._normalize_url(url)

        if current_depth > self.depth:
            return
        if normalized in self.visited_urls:
            return
        if not self._is_same_origin(url):
            return
        if not self._is_allowed(url):
            warning(f"Skipping (robots.txt disallowed): {url}")
            return

        self.visited_urls.add(normalized)
        info(f"Visiting [{current_depth}]: {url}")

        html = await self._fetch_page(url)
        if not html:
            return

        # Skip non-HTML pages (images, PDFs, etc. don't have forms)
        soup = BeautifulSoup(html, "html.parser")

        self._extract_forms(url, soup)
        self._extract_url_params(url)

        tasks = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            link = urljoin(url, href).split("#")[0]  # Strip fragment
            if self._is_same_origin(link):
                link_norm = self._normalize_url(link)
                if link_norm not in self.visited_urls:
                    tasks.append(self._crawl(link, current_depth + 1))

        if tasks:
            # Limit concurrency to avoid hammering the target
            semaphore = asyncio.Semaphore(5)
            async def guarded(coro):
                async with semaphore:
                    await coro
            await asyncio.gather(*[guarded(t) for t in tasks])

    async def _fetch_page(self, url: str):
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                default_ua = {"User-Agent": "Mozilla/5.0 (AVWDS Scanner)"}
                response   = await client.get(url, headers={**default_ua, **self.headers})

                # Only parse HTML responses
                ct = response.headers.get("content-type", "")
                if "text/html" not in ct and "text/plain" not in ct:
                    return None

                return response.text
        except Exception as e:
            error(f"Fetch failed: {url} — {e}")
            return None

    # ── Endpoint extraction ───────────────────────────────────────────────
    def _extract_forms(self, page_url: str, soup):
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            action_url = urljoin(page_url, action)
            method     = form.get("method", "GET").upper()

            params = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name  = tag.get("name")
                value = tag.get("value", "test")
                if name:
                    params[name] = value

            if not params:
                continue

            # Dedup by (url, method, frozenset of param names)
            sig = (self._normalize_url(action_url), method, frozenset(params.keys()))
            if sig in self._endpoint_sigs:
                continue
            self._endpoint_sigs.add(sig)

            endpoint = {
                "url":    action_url,
                "method": method,
                "params": params,
                "source": page_url,
                "type":   "form",
            }
            self.endpoints.append(endpoint)
            info(f"Form: {method} {action_url} | params={list(params.keys())}")

    def _extract_url_params(self, url: str):
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = {}
        for part in parsed.query.split("&"):
            if "=" in part:
                key, val = part.split("=", 1)
                params[key] = val

        if not params:
            return

        base = parsed.scheme + "://" + parsed.netloc + parsed.path
        sig  = (self._normalize_url(base), "GET", frozenset(params.keys()))
        if sig in self._endpoint_sigs:
            return
        self._endpoint_sigs.add(sig)

        endpoint = {
            "url":    base,
            "method": "GET",
            "params": params,
            "source": url,
            "type":   "url_params",
        }
        self.endpoints.append(endpoint)
