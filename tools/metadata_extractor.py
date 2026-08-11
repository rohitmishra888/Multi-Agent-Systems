"""
tools/metadata_extractor.py
============================
Comprehensive metadata extraction for discovered endpoints.

Responsibilities
----------------
This tool acts as the integration layer that combines information from:
- The Swagger spec (if available)
- Live HTTP probing
- Path structure analysis

It extracts and normalises:
- Path parameters (from ``{param}`` segments)
- Query parameters (from OpenAPI spec or URL patterns)
- Request body schema
- Response schema
- Content types
- Description and operation ID
- Full URL

This runs **after** the core discovery steps and **before** classification,
so every endpoint has a complete metadata profile before risk scoring.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from models.endpoint import EndpointModel, ParameterModel
from utils.helpers import extract_path_params, safe_json_loads
from utils.http_client import HTTPClient, HTTPResponse
from utils.logger import get_logger

logger = get_logger(__name__)

# Common query parameter patterns by endpoint type
_KNOWN_QUERY_PARAMS: Dict[str, List[Dict[str, Any]]] = {
    "search": [
        {"name": "q", "type": "string", "description": "Search query"},
        {"name": "query", "type": "string", "description": "Search query"},
        {"name": "limit", "type": "integer", "description": "Max results"},
        {"name": "offset", "type": "integer", "description": "Pagination offset"},
    ],
    "list": [
        {"name": "page", "type": "integer", "description": "Page number"},
        {"name": "limit", "type": "integer", "description": "Items per page"},
        {"name": "sort", "type": "string", "description": "Sort field"},
        {"name": "order", "type": "string", "description": "Sort order (asc/desc)"},
    ],
}


class MetadataExtractor:
    """
    Enriches ``EndpointModel`` instances with detailed metadata.

    Parameters
    ----------
    client:
        An ``HTTPClient`` instance for live probing.
    base_url:
        The application base URL.
    """

    def __init__(self, client: HTTPClient, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    # ── Public interface ────────────────────────────────────────────────────

    def extract(self, endpoint: EndpointModel) -> EndpointModel:
        """
        Enrich an endpoint with all available metadata.

        Parameters
        ----------
        endpoint:
            Endpoint to enrich. Mutated in-place.

        Returns
        -------
        EndpointModel
            The enriched endpoint.
        """
        logger.debug(
            "Metadata extraction",
            method=endpoint.method.value,
            path=endpoint.endpoint,
        )

        # 1. Full URL
        endpoint.full_url = self._base_url + endpoint.endpoint

        # 2. Path parameters
        self._extract_path_parameters(endpoint)

        # 3. Query parameters (infer from path naming if not from spec)
        self._infer_query_parameters(endpoint)

        # 4. Request body schema (probe if not from spec)
        if endpoint.request_schema is None and endpoint.method.value in ("POST", "PUT", "PATCH"):
            self._probe_request_schema(endpoint)

        # 5. Description (generate from path if missing)
        if not endpoint.description:
            endpoint.description = self._generate_description(endpoint)

        # 6. Normalise content types
        self._normalise_content_types(endpoint)

        logger.debug(
            "Metadata extraction complete",
            path=endpoint.endpoint,
            path_params=len(endpoint.path_parameters()),
            query_params=len(endpoint.query_parameters()),
        )
        return endpoint

    # ── Path parameter extraction ────────────────────────────────────────────

    def _extract_path_parameters(self, endpoint: EndpointModel) -> None:
        """
        Extract ``{param_name}`` segments from the path and add as
        ``ParameterModel`` instances with ``location='path'``.

        Avoids duplicating parameters already present from the spec.
        """
        existing_path_params = {p.name for p in endpoint.path_parameters()}
        raw_params = extract_path_params(endpoint.endpoint)

        for param_name in raw_params:
            if param_name not in existing_path_params:
                endpoint.parameters.append(
                    ParameterModel(
                        name=param_name,
                        location="path",
                        required=True,
                        param_type="string",
                        description=f"Path parameter: {param_name}",
                    )
                )

    # ── Query parameter inference ────────────────────────────────────────────

    def _infer_query_parameters(self, endpoint: EndpointModel) -> None:
        """
        For GET endpoints whose path ends with 'search' or suggests a list,
        add common query parameters if none are present from the spec.
        """
        if endpoint.method.value != "GET":
            return
        if endpoint.query_parameters():
            return  # Already has query params from spec

        path_lower = endpoint.endpoint.lower()
        if "search" in path_lower:
            template = "search"
        elif path_lower.rstrip("/").endswith(("/v1", "/v2", "/list", "/users", "/books")):
            template = "list"
        else:
            return

        for param_def in _KNOWN_QUERY_PARAMS.get(template, []):
            endpoint.parameters.append(
                ParameterModel(
                    name=param_def["name"],
                    location="query",
                    required=False,
                    param_type=param_def["type"],
                    description=param_def.get("description"),
                )
            )

    # ── Request schema probing ───────────────────────────────────────────────

    def _probe_request_schema(self, endpoint: EndpointModel) -> None:
        """
        Attempt to infer the request body schema by sending an empty JSON body
        and examining the validation error response.

        Many APIs return a helpful 400/422 response listing required fields.
        """
        try:
            resp = self._client.request(
                endpoint.method.value,
                endpoint.endpoint,
                json={},
                headers={"Content-Type": "application/json"},
            )

            data = safe_json_loads(resp.text)
            if not isinstance(data, dict):
                return

            # Some APIs return {"detail": [{"loc": ["body", "field"], "msg": "..."}]}
            schema = self._infer_from_validation_error(data)
            if schema:
                endpoint.request_schema = schema

        except Exception as exc:
            logger.debug(
                "Request schema probe failed",
                path=endpoint.endpoint,
                error=str(exc),
            )

    @staticmethod
    def _infer_from_validation_error(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse FastAPI/pydantic-style validation errors to infer request schema.

        Example input::

            {"detail": [{"loc": ["body", "username"], "type": "missing"}]}
        """
        detail = data.get("detail", [])
        if not isinstance(detail, list):
            return None

        fields = {}
        for item in detail:
            if not isinstance(item, dict):
                continue
            loc = item.get("loc", [])
            if len(loc) >= 2 and loc[0] == "body":
                field_name = str(loc[1])
                fields[field_name] = {"type": "string"}

        if fields:
            return {
                "type": "object",
                "properties": fields,
                "required": list(fields.keys()),
            }
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _generate_description(endpoint: EndpointModel) -> str:
        """Generate a human-readable description from the method and path."""
        method = endpoint.method.value
        path = endpoint.endpoint

        # Split path into segments
        segments = [s for s in path.split("/") if s and not s.startswith("{")]
        resource = segments[-1] if segments else path

        descriptions = {
            "GET": f"Retrieve {resource.replace('-', ' ')}",
            "POST": f"Create or submit {resource.replace('-', ' ')}",
            "PUT": f"Update {resource.replace('-', ' ')}",
            "PATCH": f"Partially update {resource.replace('-', ' ')}",
            "DELETE": f"Delete {resource.replace('-', ' ')}",
        }
        return descriptions.get(method, f"{method} {path}")

    @staticmethod
    def _normalise_content_types(endpoint: EndpointModel) -> None:
        """Ensure consumes/produces lists are non-empty and deduplicated."""
        if not endpoint.consumes:
            endpoint.consumes = ["application/json"]
        if not endpoint.produces:
            endpoint.produces = ["application/json"]
        # Deduplicate preserving order
        from utils.helpers import deduplicate_preserve_order
        endpoint.consumes = deduplicate_preserve_order(endpoint.consumes)
        endpoint.produces = deduplicate_preserve_order(endpoint.produces)
