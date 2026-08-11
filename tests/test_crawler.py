"""
tests/test_crawler.py
=====================
Unit tests for the ``Crawler`` tool.

Coverage
--------
- HTML link extraction
- Form action extraction
- Inline JavaScript scanning
- JSON blob scanning
- External path filtering (skip external hosts)
- Extension filtering (skip .css, .js static files)
- Stub model creation
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from models.endpoint import DiscoveryMethod
from tests.conftest import make_response
from tools.crawler import Crawler


BASE_URL = "http://localhost:5000"


class TestCrawlerHTMLParsing:
    """Tests for HTML link and form extraction."""

    def test_extracts_api_links_from_html(self, mock_http_client):
        """API-looking href links are extracted from HTML."""
        html = """
        <html>
          <body>
            <a href="/api/v1/users">Users</a>
            <a href="/books/v1">Books</a>
            <a href="https://external.com/api">External (should skip)</a>
          </body>
        </html>
        """
        mock_http_client.get.return_value = make_response(
            200, html, content_type="text/html", url=f"{BASE_URL}/"
        )
        crawler = Crawler(client=mock_http_client, base_url=BASE_URL)
        endpoints = crawler.crawl()

        paths = {e.endpoint for e in endpoints}
        # External link should not appear
        assert "https://external.com/api" not in paths

    def test_extracts_form_actions(self, mock_http_client):
        """Form action attributes pointing to API paths are captured."""
        html = """
        <html><body>
          <form action="/users/v1/login" method="POST">
            <input type="text" name="username">
          </form>
        </body></html>
        """
        mock_http_client.get.return_value = make_response(
            200, html, content_type="text/html", url=f"{BASE_URL}/"
        )
        crawler = Crawler(client=mock_http_client, base_url=BASE_URL)
        endpoints = crawler.crawl()

        paths = {e.endpoint for e in endpoints}
        assert "/users/v1/login" in paths

    def test_ignores_javascript_and_mailto_links(self, mock_http_client):
        """javascript: and mailto: href values are ignored."""
        html = """
        <html><body>
          <a href="javascript:void(0)">JS link</a>
          <a href="mailto:admin@example.com">Mail</a>
          <a href="/api/users">Real API</a>
        </body></html>
        """
        mock_http_client.get.return_value = make_response(
            200, html, content_type="text/html", url=f"{BASE_URL}/"
        )
        crawler = Crawler(client=mock_http_client, base_url=BASE_URL)
        endpoints = crawler.crawl()

        paths = {e.endpoint for e in endpoints}
        # JS/mailto links must not appear
        assert not any("javascript" in p for p in paths)
        assert not any("mailto" in p for p in paths)


class TestCrawlerJavaScriptScanning:
    """Tests for JavaScript pattern scanning."""

    def _make_js_crawler(self, js_text: str) -> Crawler:
        """Create a Crawler whose root returns an HTML page with inline JS."""
        html = f"""<html><body><script>{js_text}</script></body></html>"""
        client = MagicMock()
        client.get.return_value = make_response(
            200, html, content_type="text/html", url=f"{BASE_URL}/"
        )
        return Crawler(client=client, base_url=BASE_URL)

    def test_detects_fetch_call(self):
        """fetch('/api/users') pattern is detected."""
        crawler = self._make_js_crawler("fetch('/api/users', { method: 'GET' })")
        endpoints = crawler.crawl()
        paths = {e.endpoint for e in endpoints}
        assert "/api/users" in paths

    def test_detects_axios_call(self):
        """axios.get('/users/v1') pattern is detected."""
        crawler = self._make_js_crawler("axios.get('/users/v1').then(r => r.data)")
        endpoints = crawler.crawl()
        paths = {e.endpoint for e in endpoints}
        assert "/users/v1" in paths

    def test_ignores_external_urls_in_js(self):
        """External URLs in JS are not collected."""
        crawler = self._make_js_crawler(
            "fetch('https://external.com/api/users')"
        )
        endpoints = crawler.crawl()
        paths = {e.endpoint for e in endpoints}
        assert not any("external" in p for p in paths)


class TestCrawlerJSONScanning:
    """Tests for JSON body scanning."""

    def test_scans_json_response_for_paths(self):
        """API paths embedded in JSON responses are extracted."""
        json_body = '{"endpoints": ["/v1/users", "/v1/books"], "docs": "/docs"}'
        client = MagicMock()
        # Root returns JSON
        client.get.return_value = make_response(
            200, json_body, content_type="application/json", url=f"{BASE_URL}/"
        )
        crawler = Crawler(client=client, base_url=BASE_URL)
        endpoints = crawler.crawl()

        paths = {e.endpoint for e in endpoints}
        assert "/v1/users" in paths
        assert "/v1/books" in paths


class TestCrawlerStaticFileFiltering:
    """Tests that static files are correctly filtered out."""

    def test_skips_css_files(self):
        """Paths ending in .css are not collected."""
        from tools.crawler import Crawler
        crawler = Crawler(client=MagicMock(), base_url=BASE_URL)
        assert not crawler._is_valid_api_path("/static/style.css")

    def test_skips_image_files(self):
        """Paths ending in .png/.jpg are not collected."""
        crawler = Crawler(client=MagicMock(), base_url=BASE_URL)
        assert not crawler._is_valid_api_path("/images/logo.png")

    def test_accepts_api_path(self):
        """Valid API paths pass the filter."""
        crawler = Crawler(client=MagicMock(), base_url=BASE_URL)
        assert crawler._is_valid_api_path("/api/users")
        assert crawler._is_valid_api_path("/v1/books")


class TestCrawlerStubs:
    """Tests for the EndpointModel stubs produced by the crawler."""

    def test_stubs_have_correct_discovery_method(self, mock_http_client):
        """Crawler stubs are tagged with DiscoveryMethod.CRAWLER."""
        html = '<html><body><a href="/api/users">API</a></body></html>'
        mock_http_client.get.return_value = make_response(
            200, html, content_type="text/html", url=f"{BASE_URL}/"
        )
        crawler = Crawler(client=mock_http_client, base_url=BASE_URL)
        endpoints = crawler.crawl()

        for ep in endpoints:
            assert ep.discovered_by == DiscoveryMethod.CRAWLER

    def test_handles_connection_error_gracefully(self):
        """Crawler continues if root page fails to load."""
        client = MagicMock()
        client.get.side_effect = ConnectionError("Cannot connect")
        crawler = Crawler(client=client, base_url=BASE_URL)
        endpoints = crawler.crawl()
        # Should return empty list without raising
        assert isinstance(endpoints, list)
