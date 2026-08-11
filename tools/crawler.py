"""
tools/crawler.py
================
Step 2 of the discovery pipeline — HTTP-based crawling.

Strategy
--------
1. Fetch the application root (``/``).
2. Parse the HTML response for:
   - ``<a href="...">`` links
   - ``<form action="...">`` targets
   - JavaScript ``fetch()`` / ``axios`` / ``XMLHttpRequest`` call patterns
   - Embedded JSON configuration blobs
   - Script ``src`` attributes (fetched and scanned for API paths)
3. Collect unique URL paths and return them as stub ``EndpointModel`` instances
   for further enrichment by later pipeline steps.

Design
------
* Uses ``BeautifulSoup`` for HTML parsing and ``re`` for JavaScript scanning.
* Stays within the same host (no external URLs).
* Never modifies state on the server (only GET requests).
* Returns stubs with minimal metadata — later tools fill in auth, schema, etc.
"""

from __future__ import annotations

import re
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from models.endpoint import DiscoveryMethod, EndpointModel, HTTPMethod
from utils.helpers import normalise_path, is_same_host, safe_json_loads
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)

# Regex patterns for finding API paths in JavaScript source
_JS_PATTERNS = [
    # fetch('/api/users') or fetch("/api/users")
    re.compile(r"""fetch\s*\(\s*['"]([/][^'"?\s]+)['"]"""),
    # axios.get('/api/users') etc.
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"]([/][^'"?\s]+)['"]"""),
    # $.ajax({ url: '/api/users' })
    re.compile(r"""url\s*:\s*['"]([/][^'"?\s]+)['"]"""),
    # XMLHttpRequest open('GET', '/api/users')
    re.compile(r"""open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([/][^'"?\s]+)['"]"""),
    # General: '/api/something' strings
    re.compile(r"""['"]([/](?:api|v\d|users|books|auth)[^'"?\s]*)['"]"""),
]

# Ignore these file extensions — they are not API paths
_SKIP_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".map", ".html", ".htm",
}


class Crawler:
    """
    Lightweight HTML + JavaScript API path crawler.

    Parameters
    ----------
    client:
        An ``HTTPClient`` instance.
    base_url:
        The base URL of the target application.
    max_pages:
        Maximum number of HTML pages to crawl (prevents runaway crawls).
    """

    def __init__(
        self,
        client: HTTPClient,
        base_url: str,
        max_pages: int = 20,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._max_pages = max_pages

    # ── Public interface ────────────────────────────────────────────────────

    def crawl(self) -> List[EndpointModel]:
        """
        Crawl the application and return discovered endpoint stubs.

        Returns
        -------
        List[EndpointModel]
            Stub endpoints discovered through crawling.
            ``discovered_by`` is set to ``DiscoveryMethod.CRAWLER``.
        """
        logger.info("HTTP crawler started", base_url=self._base_url)

        discovered_paths: Set[str] = set()
        pages_visited: Set[str] = set()
        queue: List[str] = ["/"]  # start from root

        while queue and len(pages_visited) < self._max_pages:
            path = queue.pop(0)
            if path in pages_visited:
                continue
            pages_visited.add(path)

            try:
                resp = self._client.get(path)
                if resp.status_code != 200:
                    continue

                ct = resp.content_type
                new_paths: Set[str] = set()
                new_links: List[str] = []

                if "text/html" in ct:
                    new_paths, new_links = self._parse_html(resp.text, path)
                    # Add internal links to the crawl queue
                    for link in new_links:
                        if link not in pages_visited:
                            queue.append(link)

                elif "application/javascript" in ct or "text/javascript" in ct:
                    new_paths = self._scan_javascript(resp.text)

                elif "application/json" in ct:
                    new_paths = self._scan_json(resp.text)

                discovered_paths.update(new_paths)

            except Exception as exc:
                logger.debug("Crawler failed on path", path=path, error=str(exc))

        logger.info(
            "Crawler complete",
            pages_visited=len(pages_visited),
            api_paths_found=len(discovered_paths),
        )

        return self._build_stubs(discovered_paths)

    # ── HTML parsing ─────────────────────────────────────────────────────────

    def _parse_html(
        self, html: str, current_path: str
    ) -> tuple[Set[str], List[str]]:
        """
        Parse an HTML page for API paths and crawlable links.

        Returns
        -------
        Tuple[api_paths, crawlable_links]
        """
        api_paths: Set[str] = set()
        crawlable_links: List[str] = []

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return api_paths, crawlable_links

        # ── <a href> links ──────────────────────────────────────────────────
        for tag in soup.find_all("a", href=True):
            href: str = str(tag["href"])
            resolved = self._resolve_link(href, current_path)
            if resolved:
                if self._looks_like_api_path(resolved):
                    api_paths.add(normalise_path(resolved))
                else:
                    crawlable_links.append(resolved)

        # ── <form action> targets ────────────────────────────────────────────
        for tag in soup.find_all("form", action=True):
            action: str = str(tag["action"])
            if action and not action.startswith("http"):
                api_paths.add(normalise_path("/" + action.lstrip("/")))

        # ── <script src> — fetch JS and scan it ─────────────────────────────
        for tag in soup.find_all("script"):
            # Inline scripts
            inline = tag.string or ""
            if inline:
                api_paths.update(self._scan_javascript(inline))

            # External scripts on the same host
            src = tag.get("src", "")
            if src and not src.startswith("http"):
                js_path = "/" + src.lstrip("/")
                try:
                    js_resp = self._client.get(js_path)
                    if js_resp.ok:
                        api_paths.update(self._scan_javascript(js_resp.text))
                except Exception:
                    pass

        # ── Embedded JSON-like configuration ────────────────────────────────
        for tag in soup.find_all("script", {"type": "application/json"}):
            api_paths.update(self._scan_json(tag.string or ""))

        return api_paths, crawlable_links

    # ── JavaScript scanning ─────────────────────────────────────────────────

    def _scan_javascript(self, js_text: str) -> Set[str]:
        """
        Scan JavaScript source for API endpoint path patterns.
        """
        found: Set[str] = set()
        for pattern in _JS_PATTERNS:
            for match in pattern.finditer(js_text):
                raw = match.group(1)
                if self._is_valid_api_path(raw):
                    found.add(normalise_path(raw))
        return found

    # ── JSON scanning ────────────────────────────────────────────────────────

    def _scan_json(self, text: str) -> Set[str]:
        """
        Scan a JSON blob for string values that look like API paths.
        """
        found: Set[str] = set()
        data = safe_json_loads(text)
        if data:
            self._extract_paths_from_json(data, found)
        return found

    def _extract_paths_from_json(self, data: object, found: Set[str]) -> None:
        """Recursively walk a JSON structure extracting API-looking strings."""
        if isinstance(data, dict):
            for v in data.values():
                self._extract_paths_from_json(v, found)
        elif isinstance(data, list):
            for item in data:
                self._extract_paths_from_json(item, found)
        elif isinstance(data, str) and self._is_valid_api_path(data):
            found.add(normalise_path(data))

    # ── Path helpers ─────────────────────────────────────────────────────────

    def _resolve_link(self, href: str, current_path: str) -> Optional[str]:
        """
        Resolve an href to a path string, returning None for external or
        non-HTTP links (mailto:, javascript:, etc.).
        """
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        if href.startswith("http"):
            # Only follow same-host URLs
            if not is_same_host(href, self._base_url):
                return None
            return urlparse(href).path
        if href.startswith("//"):
            return None
        return normalise_path("/" + href.lstrip("/"))

    @staticmethod
    def _looks_like_api_path(path: str) -> bool:
        """Heuristic: does the path look like an API endpoint?"""
        api_indicators = ["/api/", "/v1/", "/v2/", "/users", "/books", "/auth", "/login"]
        return any(ind in path.lower() for ind in api_indicators)

    @staticmethod
    def _is_valid_api_path(path: str) -> bool:
        """
        Check whether a string is a plausible, non-static API path.
        """
        if not path or not path.startswith("/"):
            return False
        # Skip static file extensions
        lower = path.lower()
        if any(lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
            return False
        # Must have at least one non-root segment
        parts = [p for p in path.split("/") if p]
        return len(parts) >= 1

    def _build_stubs(self, paths: Set[str]) -> List[EndpointModel]:
        """
        Convert discovered paths into minimal ``EndpointModel`` stubs.

        Only GET is assumed; method enumeration will discover others.
        """
        stubs: List[EndpointModel] = []
        for path in sorted(paths):
            stubs.append(
                EndpointModel(
                    endpoint=path,
                    method=HTTPMethod.GET,
                    description=f"Discovered via crawler at {path}",
                    discovered_by=DiscoveryMethod.CRAWLER,
                    declared_in_openapi=False,
                    supported=True,
                )
            )
            logger.debug("Crawler found path", path=path)
        return stubs
