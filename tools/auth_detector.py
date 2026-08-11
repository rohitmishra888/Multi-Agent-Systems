"""
tools/auth_detector.py
======================
Authentication requirement analyser for discovered endpoints.

Strategy
--------
For each endpoint, the detector examines:

1. **Response status codes** — 401 and 403 strongly indicate auth is required.
2. **Response headers** — ``WWW-Authenticate`` header reveals the scheme.
3. **Response body** — JSON error messages often mention "token", "jwt",
   "unauthorized", "authentication required", etc.
4. **OpenAPI security field** — already extracted by ``SwaggerParser`` but
   can be re-validated here if the spec was available.
5. **Path heuristics** — paths containing ``/admin``, ``/profile``,
   ``/{user_id}/password`` are almost always protected.

This module is designed to *enrich* existing ``EndpointModel`` instances,
not to create new ones.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from models.endpoint import AuthType, EndpointModel
from utils.http_client import HTTPClient, HTTPResponse
from utils.logger import get_logger

logger = get_logger(__name__)

# Keywords in response body that indicate the endpoint requires authentication
_AUTH_BODY_KEYWORDS = {
    "unauthorized",
    "unauthenticated",
    "authentication required",
    "authentication failed",
    "not authenticated",
    "invalid token",
    "token required",
    "jwt",
    "bearer",
    "access denied",
    "forbidden",
    "login required",
    "please log in",
    "401",
    "403",
}

# Paths that heuristically require authentication
_PROTECTED_PATH_PATTERNS = [
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/profile", re.IGNORECASE),
    re.compile(r"/password", re.IGNORECASE),
    re.compile(r"/email", re.IGNORECASE),
    re.compile(r"/dashboard", re.IGNORECASE),
    re.compile(r"/settings", re.IGNORECASE),
    re.compile(r"/private", re.IGNORECASE),
    re.compile(r"/internal", re.IGNORECASE),
    re.compile(r"/users/v\d+/[^/]+$", re.IGNORECASE),  # /users/v1/{id}
]

# WWW-Authenticate header scheme patterns
_WWW_AUTH_PATTERNS = {
    "bearer": AuthType.BEARER,
    "jwt": AuthType.JWT,
    "basic": AuthType.BASIC,
    "apikey": AuthType.API_KEY,
    "api_key": AuthType.API_KEY,
    "api-key": AuthType.API_KEY,
}


class AuthDetector:
    """
    Detects and classifies authentication requirements for API endpoints.

    Parameters
    ----------
    client:
        An ``HTTPClient`` used to probe endpoints without auth credentials.
    """

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    # ── Public interface ────────────────────────────────────────────────────

    def detect(self, endpoint: EndpointModel) -> EndpointModel:
        """
        Analyse a single endpoint and update its authentication fields.

        If the endpoint already has ``authentication_required=True`` (from
        Swagger), we still probe to confirm the auth type.

        Parameters
        ----------
        endpoint:
            The endpoint to analyse. Mutated in-place and also returned.

        Returns
        -------
        EndpointModel
            The same endpoint with updated auth fields.
        """
        logger.debug(
            "Auth detection",
            method=endpoint.method.value,
            path=endpoint.endpoint,
        )

        # Probe with a bare GET (or the actual method) without auth credentials
        resp = self._probe(endpoint)

        if resp is not None:
            auth_required, auth_type, jwt_required = self._analyse_response(
                resp, endpoint.endpoint
            )
        else:
            # Could not reach endpoint — fall back to path heuristics
            auth_required, auth_type, jwt_required = self._heuristic_auth(
                endpoint.endpoint
            )

        # Check if route is an authentication/registration endpoint (exempt from needing prior auth)
        is_login = bool(re.search(r"/(?:login|token|auth(?:/|$))", endpoint.endpoint, re.I))
        is_register = bool(re.search(r"/(?:register|signup)", endpoint.endpoint, re.I))
        is_reset = bool(re.search(r"/(?:forgot-password|reset-password)", endpoint.endpoint, re.I))

        if is_login or is_register or is_reset:
            auth_required = False
            auth_type = AuthType.NONE
            jwt_required = False
            if is_login:
                endpoint.auth_purpose = "token_issuance"
            elif is_register:
                endpoint.auth_purpose = "user_registration"
            elif is_reset:
                endpoint.auth_purpose = "user_password_reset"
        else:
            # If swagger already marked it as auth required, keep that
            if endpoint.authentication_required:
                auth_required = True
            endpoint.auth_purpose = "resource_access" if auth_required else "public_access"

        # Update model fields
        if auth_required and endpoint.authentication_type == AuthType.NONE:
            endpoint.authentication_type = auth_type
            endpoint.jwt_required = jwt_required
        elif not auth_required:
            endpoint.authentication_type = AuthType.NONE
            endpoint.jwt_required = False

        endpoint.authentication_required = auth_required

        logger.debug(
            "Auth result",
            path=endpoint.endpoint,
            auth_required=auth_required,
            auth_type=auth_type.value,
            purpose=endpoint.auth_purpose,
        )
        return endpoint

    # ── Probing ─────────────────────────────────────────────────────────────

    def _probe(self, endpoint: EndpointModel) -> Optional[HTTPResponse]:
        """
        Issue a request to the endpoint without any credentials.

        Uses GET for most endpoints; switches to POST if the endpoint only
        accepts POST (as indicated by the ``method`` field).
        """
        path = endpoint.endpoint
        method = endpoint.method.value

        try:
            return self._client.request(method, path)
        except Exception as exc:
            logger.debug("Auth probe failed", path=path, method=method, error=str(exc))
            # Try GET as fallback
            if method != "GET":
                try:
                    return self._client.get(path)
                except Exception:
                    pass
            return None

    # ── Response analysis ────────────────────────────────────────────────────

    def _analyse_response(
        self, resp: HTTPResponse, path: str
    ) -> Tuple[bool, AuthType, bool]:
        """
        Determine auth requirements from an HTTP response.

        Priority order:
        1. WWW-Authenticate header → most reliable
        2. 401 status → auth definitely required
        3. 403 status → auth possibly required (may also be permission-based)
        4. Body keywords → supplementary signal
        5. Path heuristics → lowest priority

        Returns
        -------
        Tuple[auth_required, auth_type, jwt_required]
        """
        # ── WWW-Authenticate header ──────────────────────────────────────────
        www_auth = resp.headers.get("www-authenticate", "").lower()
        if www_auth:
            auth_type = self._parse_www_authenticate(www_auth)
            jwt_required = auth_type == AuthType.JWT or "jwt" in www_auth
            return True, auth_type, jwt_required

        # ── Status code 401 ──────────────────────────────────────────────────
        if resp.status_code == 401:
            body_auth_type = self._detect_auth_type_from_body(resp.text)
            jwt_required = body_auth_type == AuthType.JWT
            return True, body_auth_type, jwt_required

        # ── Status code 403 ──────────────────────────────────────────────────
        if resp.status_code == 403:
            body_auth_type = self._detect_auth_type_from_body(resp.text)
            jwt_required = body_auth_type == AuthType.JWT
            return True, body_auth_type, jwt_required

        # ── Body keyword analysis ────────────────────────────────────────────
        if self._body_suggests_auth(resp.text):
            body_auth_type = self._detect_auth_type_from_body(resp.text)
            jwt_required = body_auth_type == AuthType.JWT
            return True, body_auth_type, jwt_required

        # ── Path heuristics ──────────────────────────────────────────────────
        return self._heuristic_auth(path)

    @staticmethod
    def _parse_www_authenticate(header_value: str) -> AuthType:
        """Map a ``WWW-Authenticate`` header value to an ``AuthType``."""
        lower = header_value.lower()
        for pattern, auth_type in _WWW_AUTH_PATTERNS.items():
            if pattern in lower:
                return auth_type
        return AuthType.UNKNOWN

    @staticmethod
    def _body_suggests_auth(body: str) -> bool:
        """Return True if the body text contains auth-related keywords."""
        lower = body.lower()
        return any(kw in lower for kw in _AUTH_BODY_KEYWORDS)

    @staticmethod
    def _detect_auth_type_from_body(body: str) -> AuthType:
        """Infer the authentication type from response body text."""
        lower = body.lower()
        if "jwt" in lower:
            return AuthType.JWT
        if "bearer" in lower:
            return AuthType.BEARER
        if "basic" in lower:
            return AuthType.BASIC
        if "api key" in lower or "api-key" in lower or "apikey" in lower:
            return AuthType.API_KEY
        if "token" in lower:
            return AuthType.BEARER  # most REST APIs use Bearer tokens
        return AuthType.UNKNOWN

    @staticmethod
    def _heuristic_auth(path: str) -> Tuple[bool, AuthType, bool]:
        """
        Use path patterns to guess whether authentication is required.

        Returns
        -------
        Tuple[auth_required, auth_type, jwt_required]
        """
        for pattern in _PROTECTED_PATH_PATTERNS:
            if pattern.search(path):
                return True, AuthType.JWT, True  # Most REST APIs use JWT
        return False, AuthType.NONE, False
