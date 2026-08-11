"""
tools/swagger_parser.py
=======================
Step 1 of the discovery pipeline — OpenAPI / Swagger specification parser.

Strategy
--------
1. Probe a list of well-known paths for an OpenAPI document
   (``/swagger.json``, ``/openapi.json``, ``/docs``, …).
2. Parse the specification using ``openapi-spec-validator`` for validation
   and then walk the document manually for maximum control.
3. Extract every path/method pair into an ``EndpointModel``.
4. Populate all available metadata: parameters, schemas, auth, tags, etc.

Design
------
* The class is stateless; call ``parse()`` to get results.
* Supports both OpenAPI 2.x (Swagger) and OpenAPI 3.x formats.
* Gracefully handles missing or malformed fields.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from models.endpoint import (
    AuthType,
    DiscoveryMethod,
    EndpointCategory,
    EndpointModel,
    HTTPMethod,
    ParameterModel,
    RiskLevel,
)
from utils.http_client import HTTPClient, HTTPResponse
from utils.logger import get_logger
from utils.helpers import safe_json_loads, normalise_path

logger = get_logger(__name__)

# HTTP methods we care about (OPTIONS and HEAD are handled by method enumeration)
_INTERESTING_METHODS = {"get", "post", "put", "delete", "patch"}


class SwaggerParser:
    """
    Probes for and parses OpenAPI/Swagger specifications.

    Parameters
    ----------
    client:
        An ``HTTPClient`` instance used for all HTTP calls.
    probe_paths:
        Ordered list of URL paths to probe for an OpenAPI document.
        Sourced from ``settings.SWAGGER_PROBE_PATHS`` by default.
    """

    def __init__(
        self,
        client: HTTPClient,
        probe_paths: Optional[List[str]] = None,
    ) -> None:
        self._client = client
        from config.settings import settings
        self._probe_paths: List[str] = probe_paths or settings.SWAGGER_PROBE_PATHS

    # ── Public interface ────────────────────────────────────────────────────

    def parse(self) -> Tuple[List[EndpointModel], Optional[str]]:
        """
        Attempt to discover and parse an OpenAPI specification.

        Returns
        -------
        Tuple[List[EndpointModel], Optional[str]]
            * A (possibly empty) list of discovered endpoints.
            * The URL from which the spec was fetched (or ``None``).
        """
        spec_data, spec_url = self._fetch_spec()
        if spec_data is None:
            logger.info("No OpenAPI specification found after probing all paths")
            return [], None

        logger.info("OpenAPI specification found", url=spec_url)
        endpoints = self._extract_endpoints(spec_data)
        logger.info(
            "OpenAPI parsing complete",
            spec_url=spec_url,
            endpoints_found=len(endpoints),
        )
        return endpoints, spec_url

    # ── Spec fetching ────────────────────────────────────────────────────────

    def _fetch_spec(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Probe each known path and return the first valid OpenAPI document found.

        Returns
        -------
        Tuple[Optional[dict], Optional[str]]
            Parsed spec dict and the URL it was fetched from.
        """
        for path in self._probe_paths:
            try:
                logger.debug("Probing OpenAPI path", path=path)
                response = self._client.get(path)

                if response.status_code not in (200, 201):
                    continue

                # Try JSON first
                spec_data = safe_json_loads(response.text)
                if spec_data and self._looks_like_openapi(spec_data):
                    logger.info("OpenAPI JSON spec found", path=path)
                    return spec_data, response.url

                # Try YAML (common for openapi.yaml)
                if "yaml" in response.content_type or path.endswith(".yaml"):
                    spec_data = self._parse_yaml(response.text)
                    if spec_data and self._looks_like_openapi(spec_data):
                        logger.info("OpenAPI YAML spec found", path=path)
                        return spec_data, response.url

                # If it's HTML (e.g. /docs renders Swagger UI), try to extract
                # the underlying spec URL from the page source
                if "text/html" in response.content_type:
                    embedded_url = self._extract_spec_url_from_html(response.text)
                    if embedded_url:
                        logger.debug("Embedded spec URL found in HTML", embedded_url=embedded_url)
                        sub_resp = self._client.get(embedded_url)
                        spec_data = safe_json_loads(sub_resp.text)
                        if spec_data and self._looks_like_openapi(spec_data):
                            return spec_data, sub_resp.url

            except Exception as exc:
                logger.debug("Error probing OpenAPI path", path=path, error=str(exc))
                continue

        return None, None

    @staticmethod
    def _looks_like_openapi(data: Any) -> bool:
        """Heuristic check: does this look like an OpenAPI document?"""
        if not isinstance(data, dict):
            return False
        return (
            "swagger" in data
            or "openapi" in data
            or "paths" in data
        )

    @staticmethod
    def _parse_yaml(text: str) -> Optional[Dict[str, Any]]:
        """Parse YAML text safely, returning None on failure."""
        try:
            import yaml
            return yaml.safe_load(text)
        except Exception:
            return None

    @staticmethod
    def _extract_spec_url_from_html(html: str) -> Optional[str]:
        """
        Try to extract the underlying OpenAPI spec URL from a Swagger UI
        HTML page (looks for ``url:`` or ``spec-url`` patterns).
        """
        # Pattern: url: "/openapi.json" or url: 'swagger.json'
        m = re.search(r'url\s*:\s*["\']([^"\']+\.(?:json|yaml))["\']', html)
        if m:
            return m.group(1)
        # Pattern: data-url="/openapi.json"
        m = re.search(r'data-url=["\']([^"\']+\.(?:json|yaml))["\']', html)
        if m:
            return m.group(1)
        return None

    # ── Endpoint extraction ─────────────────────────────────────────────────

    def _extract_endpoints(self, spec: Dict[str, Any]) -> List[EndpointModel]:
        """
        Walk the ``paths`` section of an OpenAPI spec and build endpoint models.

        Handles both OpenAPI 2.x and 3.x formats.
        """
        version = self._detect_version(spec)
        paths: Dict[str, Any] = spec.get("paths", {})
        base_path: str = spec.get("basePath", "")  # OAS2 only

        # Global security definitions
        security_definitions = spec.get(
            "securityDefinitions",  # OAS2
            spec.get("components", {}).get("securitySchemes", {}),  # OAS3
        )

        # Global consumes/produces (OAS2)
        global_consumes: List[str] = spec.get("consumes", ["application/json"])
        global_produces: List[str] = spec.get("produces", ["application/json"])

        endpoints: List[EndpointModel] = []

        for raw_path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Resolve $ref if present
            if "$ref" in path_item:
                path_item = self._resolve_ref(spec, path_item["$ref"])
                if not path_item:
                    continue

            # Path-level parameters shared by all operations
            path_level_params: List[Dict[str, Any]] = path_item.get("parameters", [])

            # Normalise the path
            full_path = normalise_path(base_path + raw_path)

            for method_str in _INTERESTING_METHODS:
                operation: Optional[Dict[str, Any]] = path_item.get(method_str)
                if not operation:
                    continue

                try:
                    ep = self._build_endpoint(
                        path=full_path,
                        method=method_str,
                        operation=operation,
                        path_level_params=path_level_params,
                        global_consumes=global_consumes,
                        global_produces=global_produces,
                        spec=spec,
                        security_definitions=security_definitions,
                        oas_version=version,
                    )
                    endpoints.append(ep)
                    logger.debug(
                        "Endpoint extracted from spec",
                        method=method_str.upper(),
                        path=full_path,
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to extract endpoint",
                        path=full_path,
                        method=method_str,
                        error=str(exc),
                    )

        return endpoints

    @staticmethod
    def _detect_version(spec: Dict[str, Any]) -> int:
        """Return the major OpenAPI version (2 or 3)."""
        if "openapi" in spec and spec["openapi"].startswith("3"):
            return 3
        return 2  # default to 2 (Swagger)

    def _build_endpoint(
        self,
        path: str,
        method: str,
        operation: Dict[str, Any],
        path_level_params: List[Dict[str, Any]],
        global_consumes: List[str],
        global_produces: List[str],
        spec: Dict[str, Any],
        security_definitions: Dict[str, Any],
        oas_version: int,
    ) -> EndpointModel:
        """
        Construct one ``EndpointModel`` from a single path+method operation block.
        """
        # Resolve operation-level parameters, merging with path-level params
        op_params_raw: List[Dict[str, Any]] = operation.get("parameters", [])
        all_params_raw = path_level_params + op_params_raw
        parameters = self._extract_parameters(all_params_raw, spec, oas_version)

        # Content types
        if oas_version == 3:
            request_body = operation.get("requestBody", {})
            consumes = list(request_body.get("content", {}).keys()) or ["application/json"]
            # Produces from responses
            responses = operation.get("responses", {})
            produces_set: set = set()
            for resp_data in responses.values():
                if isinstance(resp_data, dict):
                    produces_set.update(resp_data.get("content", {}).keys())
            produces = list(produces_set) or ["application/json"]
        else:
            consumes = operation.get("consumes", global_consumes)
            produces = operation.get("produces", global_produces)

        # Request schema
        request_schema = self._extract_request_schema(operation, spec, oas_version)
        # Response schema (primary success response)
        response_schema, response_codes, sample_response = self._extract_response_info(
            operation.get("responses", {}), spec, oas_version
        )
        # Auth
        auth_required, auth_type, jwt_required = self._detect_auth(
            operation, spec, security_definitions
        )

        # Exempt login / register / token routes from requiring prior auth (they issue tokens/users)
        is_login = bool(re.search(r"/(?:login|token|auth(?:/|$))", path, re.I))
        is_register = bool(re.search(r"/(?:register|signup)", path, re.I))
        auth_purpose = None

        if is_login or is_register:
            auth_required = False
            auth_type = AuthType.NONE
            jwt_required = False
            auth_purpose = "token_issuance" if is_login else "user_registration"

        # Tags and description
        tags = operation.get("tags", [])
        description = operation.get("description") or operation.get("summary", "")
        summary = operation.get("summary", "")
        operation_id = operation.get("operationId")

        return EndpointModel(
            endpoint=path,
            method=HTTPMethod(method.upper()),
            description=description or None,
            summary=summary or None,
            operation_id=operation_id,
            tags=tags,
            declared_in_openapi=True,
            supported=True,
            observed_status=response_codes[0] if response_codes else 200,
            authentication_required=auth_required,
            authentication_type=auth_type,
            jwt_required=jwt_required,
            auth_purpose=auth_purpose,
            parameters=parameters,
            request_schema=request_schema,
            response_schema=response_schema,
            consumes=consumes or ["application/json"],
            produces=produces or ["application/json"],
            content_type=(produces or ["application/json"])[0],
            response_codes=response_codes,
            sample_response=sample_response,
            discovered_by=DiscoveryMethod.SWAGGER,
        )

    def _extract_parameters(
        self,
        raw_params: List[Dict[str, Any]],
        spec: Dict[str, Any],
        oas_version: int,
    ) -> List[ParameterModel]:
        """Convert raw OpenAPI parameter dicts into ``ParameterModel`` instances."""
        params: List[ParameterModel] = []
        for raw in raw_params:
            try:
                # Dereference $ref
                if "$ref" in raw:
                    raw = self._resolve_ref(spec, raw["$ref"]) or {}

                name = raw.get("name", "")
                location = raw.get("in", "query")  # path, query, header, body, cookie, formData
                # normalise formData → body
                if location == "formData":
                    location = "body"

                required = raw.get("required", location == "path")
                description = raw.get("description")
                example = raw.get("example")

                # Type resolution differs between OAS2 and OAS3
                if oas_version == 3:
                    schema = raw.get("schema", {})
                    param_type = schema.get("type", "string")
                else:
                    param_type = raw.get("type", "string")
                    schema = raw.get("schema")

                params.append(
                    ParameterModel(
                        name=name,
                        location=location,
                        required=required,
                        param_type=param_type,
                        description=description,
                        example=example,
                        schema=schema,
                    )
                )
            except Exception as exc:
                logger.debug("Failed to parse parameter", raw=raw, error=str(exc))
        return params

    def _extract_request_schema(
        self,
        operation: Dict[str, Any],
        spec: Dict[str, Any],
        oas_version: int,
    ) -> Optional[Dict[str, Any]]:
        """Extract the JSON Schema for the request body."""
        if oas_version == 3:
            rb = operation.get("requestBody", {})
            content = rb.get("content", {})
            json_content = content.get("application/json", {})
            return json_content.get("schema")
        else:
            for param in operation.get("parameters", []):
                if param.get("in") == "body":
                    schema = param.get("schema")
                    if schema and "$ref" in schema:
                        schema = self._resolve_ref(spec, schema["$ref"])
                    return schema
        return None

    def _extract_response_info(
        self,
        responses: Dict[str, Any],
        spec: Dict[str, Any],
        oas_version: int,
    ) -> Tuple[Optional[Dict[str, Any]], List[int], Optional[Dict[str, Any]]]:
        """
        Extract response schema, status codes, and a sample response.

        Returns
        -------
        Tuple[schema, codes, sample]
        """
        codes: List[int] = []
        schema: Optional[Dict[str, Any]] = None
        sample: Optional[Dict[str, Any]] = None

        for code_str, resp_data in responses.items():
            # Parse the status code
            try:
                code = int(code_str)
            except (ValueError, TypeError):
                continue
            codes.append(code)

            # Resolve $ref
            if isinstance(resp_data, dict) and "$ref" in resp_data:
                resp_data = self._resolve_ref(spec, resp_data["$ref"]) or {}

            if not isinstance(resp_data, dict):
                continue

            # Only grab schema from 2xx responses
            if 200 <= code < 300 and schema is None:
                if oas_version == 3:
                    content = resp_data.get("content", {})
                    json_schema = content.get("application/json", {}).get("schema")
                    if json_schema and "$ref" in json_schema:
                        json_schema = self._resolve_ref(spec, json_schema["$ref"])
                    schema = json_schema
                    # Example
                    example = content.get("application/json", {}).get("example")
                    if isinstance(example, dict):
                        sample = example
                else:
                    raw_schema = resp_data.get("schema")
                    if raw_schema and "$ref" in raw_schema:
                        raw_schema = self._resolve_ref(spec, raw_schema["$ref"])
                    schema = raw_schema
                    example = resp_data.get("examples", {}).get("application/json")
                    if isinstance(example, dict):
                        sample = example

        return schema, sorted(set(codes)), sample

    def _detect_auth(
        self,
        operation: Dict[str, Any],
        spec: Dict[str, Any],
        security_definitions: Dict[str, Any],
    ) -> Tuple[bool, AuthType, bool]:
        """
        Determine authentication requirements from the operation's security field.

        Returns
        -------
        Tuple[auth_required, auth_type, jwt_required]
        """
        # Operations can override global security with an empty list (no auth)
        security = operation.get("security")
        if security is None:
            security = spec.get("security", [])

        if not security:
            return False, AuthType.NONE, False

        # Security is a list of requirement objects
        for req in security:
            if not isinstance(req, dict):
                continue
            for scheme_name in req:
                scheme = security_definitions.get(scheme_name, {})
                scheme_type = scheme.get("type", "").lower()
                scheme_in = scheme.get("in", "").lower()
                scheme_name_lower = scheme_name.lower()
                bearer_format = scheme.get("bearerFormat", "").lower()

                if scheme_type == "apikey":
                    return True, AuthType.API_KEY, False
                if scheme_type == "http":
                    http_scheme = scheme.get("scheme", "").lower()
                    if http_scheme == "bearer":
                        is_jwt = bearer_format == "jwt" or "jwt" in scheme_name_lower
                        return True, AuthType.JWT if is_jwt else AuthType.BEARER, is_jwt
                    if http_scheme == "basic":
                        return True, AuthType.BASIC, False
                if scheme_type == "oauth2":
                    return True, AuthType.BEARER, False
                if "jwt" in scheme_name_lower or "bearer" in scheme_name_lower:
                    return True, AuthType.JWT, True

        # Fallback: security is present but unrecognised
        return True, AuthType.UNKNOWN, False

    @staticmethod
    def _resolve_ref(spec: Dict[str, Any], ref: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a ``$ref`` pointer within the same document.

        Only supports local JSON Pointer references (``#/...``).
        """
        if not ref.startswith("#/"):
            return None
        parts = ref.lstrip("#/").split("/")
        node: Any = spec
        for part in parts:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node if isinstance(node, dict) else None
