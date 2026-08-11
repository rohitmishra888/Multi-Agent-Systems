"""
utils/http_client.py
====================
Retry-aware, timeout-enforced HTTP client wrapper built on ``httpx``.

Design goals
------------
* Single ``HTTPClient`` class injected wherever HTTP calls are needed.
* Exponential back-off with jitter on transient failures (5xx, connection errors).
* Configurable timeout and max-retry from ``settings``.
* Transparent logging of every request/response cycle.
* Returns a lightweight ``HTTPResponse`` dataclass so callers never
  depend directly on ``httpx`` internals.

Usage
-----
    from utils.http_client import HTTPClient
    client = HTTPClient()
    response = client.get("/users/v1")
    print(response.status_code, response.json())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Response wrapper
# ---------------------------------------------------------------------------

@dataclass
class HTTPResponse:
    """
    Lightweight, serialisation-friendly wrapper around an HTTP response.

    Callers receive this instead of raw ``httpx.Response`` objects,
    which decouples the rest of the codebase from the HTTP library.
    """

    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    url: str = ""
    method: str = ""
    elapsed_ms: float = 0.0

    def json(self) -> Any:
        """
        Parse the response body as JSON.

        Returns
        -------
        Any
            Parsed JSON object or raises ``ValueError`` on failure.
        """
        import json as _json
        return _json.loads(self.text)

    @property
    def ok(self) -> bool:
        """True when status code is in the 2xx range."""
        return 200 <= self.status_code < 300

    @property
    def content_type(self) -> str:
        """Normalised Content-Type without parameters."""
        ct = self.headers.get("content-type", "")
        return ct.split(";")[0].strip().lower()

    def __repr__(self) -> str:
        return (
            f"HTTPResponse(status={self.status_code}, "
            f"method={self.method!r}, url={self.url!r})"
        )


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class HTTPClient:
    """
    Session-scoped HTTP client with retry and timeout logic.

    Parameters
    ----------
    base_url:
        Root URL prepended to every relative path request.
        Defaults to ``settings.base_url``.
    timeout:
        Per-request timeout in seconds. Defaults to ``settings.REQUEST_TIMEOUT``.
    max_retries:
        Maximum retry attempts. Defaults to ``settings.MAX_RETRIES``.
    backoff_factor:
        Base wait time multiplied exponentially between retries.
        Defaults to ``settings.RETRY_BACKOFF_FACTOR``.
    headers:
        Default headers sent with every request.
    """

    # HTTP status codes that warrant a retry (transient server errors)
    _RETRYABLE_STATUS: frozenset = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
        backoff_factor: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._base_url = (base_url or settings.base_url).rstrip("/")
        self._timeout = timeout if timeout is not None else settings.REQUEST_TIMEOUT
        self._max_retries = max_retries if max_retries is not None else settings.MAX_RETRIES
        self._backoff_factor = (
            backoff_factor if backoff_factor is not None else settings.RETRY_BACKOFF_FACTOR
        )
        self._default_headers: Dict[str, str] = {
            "Accept": "application/json, text/html, */*",
            "User-Agent": "APIDiscoveryAgent/1.0 (Security Research)",
            **(headers or {}),
        }

        # Underlying httpx client (created lazily in context-manager style)
        self._client: Optional[httpx.Client] = None

    # ── Context-manager support ─────────────────────────────────────────────
    def __enter__(self) -> "HTTPClient":
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            follow_redirects=True,
            headers=self._default_headers,
        )
        return self

    def __exit__(self, *_: Any) -> None:
        if self._client:
            self._client.close()
            self._client = None

    # ── Private helpers ─────────────────────────────────────────────────────
    def _resolve_url(self, path: str) -> str:
        """Build a full URL from a potentially relative path."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self._base_url + "/" + path.lstrip("/")

    def _wrap_response(self, resp: httpx.Response, method: str) -> HTTPResponse:
        """Convert an httpx.Response into our HTTPResponse dataclass."""
        return HTTPResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            url=str(resp.url),
            method=method.upper(),
            elapsed_ms=resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0.0,
        )

    def _should_retry(self, exc: Exception, status_code: Optional[int]) -> bool:
        """Decide whether this failure is worth retrying."""
        if isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError)):
            return True
        if status_code and status_code in self._RETRYABLE_STATUS:
            return True
        return False

    def _sleep(self, attempt: int) -> None:
        """Exponential back-off sleep between retries."""
        wait = self._backoff_factor * (2 ** attempt)
        logger.debug("Retry back-off", attempt=attempt, wait_seconds=wait)
        time.sleep(wait)

    # ── Core request method ─────────────────────────────────────────────────
    def request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> HTTPResponse:
        """
        Execute an HTTP request with retry logic.

        Parameters
        ----------
        method:
            HTTP verb (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).
        path:
            Relative path or full URL.
        **kwargs:
            Additional arguments forwarded to ``httpx.Client.request``.

        Returns
        -------
        HTTPResponse
            Wrapped response object.

        Raises
        ------
        httpx.RequestError
            When all retry attempts are exhausted.
        """
        url = self._resolve_url(path)
        last_exc: Optional[Exception] = None
        last_status: Optional[int] = None

        # Ensure the client is open — supports both context-manager and
        # ad-hoc (non-context-manager) usage.
        client = self._client or httpx.Client(
            timeout=self._timeout,
            follow_redirects=True,
            headers=self._default_headers,
        )
        owns_client = self._client is None

        try:
            for attempt in range(self._max_retries + 1):
                try:
                    logger.debug(
                        "HTTP request",
                        method=method.upper(),
                        url=url,
                        attempt=attempt,
                    )
                    resp = client.request(method.upper(), url, **kwargs)
                    wrapped = self._wrap_response(resp, method)

                    logger.debug(
                        "HTTP response",
                        status=wrapped.status_code,
                        url=url,
                        elapsed_ms=f"{wrapped.elapsed_ms:.1f}",
                    )

                    # Retry only on retryable statuses when attempts remain
                    if (
                        wrapped.status_code in self._RETRYABLE_STATUS
                        and attempt < self._max_retries
                    ):
                        last_status = wrapped.status_code
                        self._sleep(attempt)
                        continue

                    return wrapped

                except httpx.RequestError as exc:
                    last_exc = exc
                    if self._should_retry(exc, None) and attempt < self._max_retries:
                        logger.warning(
                            "Request failed, retrying",
                            url=url,
                            attempt=attempt,
                            error=str(exc),
                        )
                        self._sleep(attempt)
                        continue
                    raise

            # All retries exhausted
            logger.error(
                "All retries exhausted",
                url=url,
                last_status=last_status,
                last_error=str(last_exc) if last_exc else None,
            )
            if last_exc:
                raise last_exc
            # If we got retryable statuses every time, return the last response
            return self._wrap_response(  # type: ignore[return-value]
                client.request(method.upper(), url, **kwargs), method
            )

        finally:
            if owns_client:
                client.close()

    # ── Convenience methods ─────────────────────────────────────────────────
    def get(self, path: str, **kwargs: Any) -> HTTPResponse:
        """Issue a GET request."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> HTTPResponse:
        """Issue a POST request."""
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> HTTPResponse:
        """Issue a PUT request."""
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> HTTPResponse:
        """Issue a DELETE request."""
        return self.request("DELETE", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> HTTPResponse:
        """Issue a PATCH request."""
        return self.request("PATCH", path, **kwargs)

    def options(self, path: str, **kwargs: Any) -> HTTPResponse:
        """Issue an OPTIONS request to enumerate allowed methods."""
        return self.request("OPTIONS", path, **kwargs)

    def head(self, path: str, **kwargs: Any) -> HTTPResponse:
        """Issue a HEAD request."""
        return self.request("HEAD", path, **kwargs)
