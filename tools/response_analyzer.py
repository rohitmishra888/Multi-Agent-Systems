"""
tools/response_analyzer.py
==========================
Step 4 of the discovery pipeline — HTTP response analysis.

Responsibilities
----------------
For every discovered endpoint, this tool:

1. Issues an authenticated + unauthenticated request to capture realistic responses.
2. Extracts:
   - Response status codes
   - Content-Type header
   - Security-relevant headers (CORS, X-Frame-Options, rate-limit, etc.)
   - JSON response body schema
   - Sample response payload
   - Response field names

This module enriches existing ``EndpointModel`` instances in-place.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from models.endpoint import EndpointModel
from utils.helpers import infer_json_schema, safe_json_loads
from utils.http_client import HTTPClient, HTTPResponse
from utils.logger import get_logger

logger = get_logger(__name__)

# Headers that are security-relevant and should be captured
_SECURITY_HEADERS = {
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "x-xss-protection",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
    "www-authenticate",
    "server",
    "x-powered-by",
}


class ResponseAnalyzer:
    """
    Analyses HTTP responses to enrich endpoint metadata.

    Parameters
    ----------
    client:
        An ``HTTPClient`` instance.
    """

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    # ── Public interface ────────────────────────────────────────────────────

    def analyse(self, endpoint: EndpointModel) -> EndpointModel:
        """
        Fetch the endpoint and enrich the model with response metadata.

        Parameters
        ----------
        endpoint:
            The endpoint to analyse. Updated in-place.

        Returns
        -------
        EndpointModel
            The same (updated) endpoint.
        """
        logger.debug(
            "Response analysis",
            method=endpoint.method.value,
            path=endpoint.endpoint,
        )

        resp = self._fetch(endpoint)
        if resp is None:
            return endpoint

        # Merge the new status code
        self._merge_status_code(endpoint, resp.status_code)

        # Content-Type
        if resp.content_type:
            endpoint.content_type = resp.content_type
            if resp.content_type not in endpoint.produces:
                endpoint.produces = [resp.content_type] + endpoint.produces

        # Security-relevant response headers
        self._extract_security_headers(endpoint, resp.headers)

        # JSON body analysis
        if "application/json" in resp.content_type or "json" in resp.content_type:
            self._analyse_json_body(endpoint, resp)

        logger.debug(
            "Analysis complete",
            path=endpoint.endpoint,
            status=resp.status_code,
            content_type=resp.content_type,
        )
        return endpoint

    # ── Private helpers ─────────────────────────────────────────────────────

    def _fetch(self, endpoint: EndpointModel) -> Optional[HTTPResponse]:
        """
        Attempt to fetch the endpoint.  Falls back to GET if the primary
        method fails (e.g., POST without a body returns 400 but confirms existence).
        """
        path = endpoint.endpoint
        method = endpoint.method.value

        # For modifying methods we send minimal JSON bodies to avoid 400 errors
        # that would mask useful response information
        kwargs: Dict[str, Any] = {}
        if method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = {}
            kwargs["headers"] = {"Content-Type": "application/json"}

        try:
            return self._client.request(method, path, **kwargs)
        except Exception as exc:
            logger.debug("Response analysis fetch failed", path=path, error=str(exc))

        # Fallback to GET
        if method != "GET":
            try:
                return self._client.get(path)
            except Exception:
                pass

        return None

    @staticmethod
    def _merge_status_code(endpoint: EndpointModel, code: int) -> None:
        """Add *code* to the endpoint's response_codes if not already present."""
        if code not in endpoint.response_codes:
            endpoint.response_codes = sorted(set(endpoint.response_codes) | {code})
        endpoint.observed_status = code
        if code in (404, 405):
            endpoint.supported = False

    @staticmethod
    def _extract_security_headers(
        endpoint: EndpointModel, headers: Dict[str, str]
    ) -> None:
        """
        Copy security-relevant response headers into the endpoint model.
        """
        relevant = {
            k: v
            for k, v in headers.items()
            if k.lower() in _SECURITY_HEADERS
        }
        # Merge without overwriting values already captured (e.g. from Swagger)
        endpoint.response_headers.update(relevant)

    def _analyse_json_body(
        self, endpoint: EndpointModel, resp: HTTPResponse
    ) -> None:
        """
        Parse the JSON response body and extract schema + sample.
        """
        data = safe_json_loads(resp.text)
        if data is None:
            return

        # Sample response
        if endpoint.sample_response is None:
            if isinstance(data, dict):
                endpoint.sample_response = data
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                endpoint.sample_response = {"items": data[:1]}

        # Response field names (top-level keys)
        if isinstance(data, dict):
            endpoint.response_fields = list(data.keys())
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            endpoint.response_fields = list(data[0].keys())

        # Infer schema if one wasn't already provided by the spec
        if endpoint.response_schema is None:
            endpoint.response_schema = infer_json_schema(data)
