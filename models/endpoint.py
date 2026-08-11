"""
models/endpoint.py
==================
Pydantic data model for a single discovered API endpoint.

Design rationale
----------------
* ``EndpointModel`` is the canonical representation of **one** endpoint.
* It captures everything the Security Testing Agent (Phase 2) will need:
  authentication requirements, parameters, schemas, inherent risk level, etc.
* Distinguishes between **declared OpenAPI operations** vs **probed HTTP methods**,
  and **supported methods** (status 2xx, 400, 401, 403) vs **unsupported methods** (405 Method Not Allowed).
* Keeps preliminary inherent attack-surface risk separate from Phase 2 vulnerability findings.
* All fields are serialisable to JSON/YAML cleanly.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enum types
# ---------------------------------------------------------------------------

class HTTPMethod(str, Enum):
    """Supported HTTP verbs."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class AuthType(str, Enum):
    """Authentication mechanism detected on an endpoint."""
    NONE = "None"
    BEARER = "Bearer"
    JWT = "JWT"
    BASIC = "Basic"
    API_KEY = "API Key"
    COOKIE = "Cookie"
    UNKNOWN = "Unknown"


class RiskLevel(str, Enum):
    """Preliminary inherent security risk classification (attack surface)."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class EndpointCategory(str, Enum):
    """Functional category of an endpoint."""
    AUTHENTICATION = "Authentication"
    USER_MANAGEMENT = "User Management"
    BOOK_MANAGEMENT = "Book Management"
    ADMINISTRATION = "Administration"
    PUBLIC = "Public"
    INTERNAL = "Internal"
    UNKNOWN = "Unknown"


class DiscoveryMethod(str, Enum):
    """How this endpoint was found."""
    SWAGGER = "Swagger"
    CRAWLER = "Crawler"
    GUESSER = "Guesser"
    METHOD_ENUM = "Method Enumeration"
    MANUAL = "Manual"


# ---------------------------------------------------------------------------
# Parameter model
# ---------------------------------------------------------------------------

class ParameterModel(BaseModel):
    """
    Describes a single input parameter (path, query, header, body, cookie).
    """

    name: str = Field(..., description="Parameter name.")
    location: str = Field(
        ...,
        description="Where the parameter is supplied: 'path', 'query', 'header', 'body', 'cookie'.",
    )
    required: bool = Field(default=False, description="Whether the parameter is mandatory.")
    param_type: str = Field(default="string", description="Data type (string, integer, boolean, …).")
    description: Optional[str] = Field(default=None, description="Human-readable description.")
    example: Optional[Any] = Field(default=None, description="Example value.")
    schema_: Optional[Dict[str, Any]] = Field(
        default=None,
        alias="schema",
        description="Full JSON Schema for this parameter.",
    )

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Main endpoint model
# ---------------------------------------------------------------------------

class EndpointModel(BaseModel):
    """
    Comprehensive representation of one discovered REST API endpoint.

    This model is the contract between Phase 1 (discovery) and Phase 2
    (security testing).  All fields added here remain backward-compatible.
    """

    # ── Identity ─────────────────────────────────────────────────────────────
    endpoint: str = Field(..., description="URL path, e.g. '/users/v1/login'.")
    method: HTTPMethod = Field(..., description="HTTP method.")

    # ── Description ──────────────────────────────────────────────────────────
    description: Optional[str] = Field(default=None, description="What this endpoint does.")
    summary: Optional[str] = Field(default=None, description="Short summary from OpenAPI spec.")
    operation_id: Optional[str] = Field(
        default=None, description="operationId from OpenAPI spec."
    )
    tags: List[str] = Field(default_factory=list, description="OpenAPI tags.")

    # ── Operational Support & Provenance ─────────────────────────────────────
    supported: bool = Field(
        default=True,
        description="Whether this HTTP method is supported by the server (False if status is 405 Method Not Allowed or 404).",
    )
    declared_in_openapi: bool = Field(
        default=False,
        description="Whether this operation was explicitly declared in the OpenAPI specification.",
    )
    observed_status: Optional[int] = Field(
        default=None,
        description="Primary HTTP status code observed during discovery probing.",
    )

    # ── Authentication ────────────────────────────────────────────────────────
    authentication_required: bool = Field(
        default=False, description="Whether accessing this endpoint requires authentication."
    )
    authentication_type: AuthType = Field(
        default=AuthType.NONE, description="Authentication mechanism."
    )
    jwt_required: bool = Field(
        default=False, description="Shorthand: endpoint requires a valid JWT."
    )
    auth_purpose: Optional[str] = Field(
        default=None,
        description="Role/purpose of auth on this route: 'token_issuance', 'user_registration', 'resource_access'.",
    )

    # ── Parameters ────────────────────────────────────────────────────────────
    parameters: List[ParameterModel] = Field(
        default_factory=list, description="All parameters (path, query, header, body, cookie)."
    )

    # ── Schemas ───────────────────────────────────────────────────────────────
    request_schema: Optional[Dict[str, Any]] = Field(
        default=None, description="JSON Schema of the request body."
    )
    response_schema: Optional[Dict[str, Any]] = Field(
        default=None, description="JSON Schema of the primary success response."
    )

    # ── Content types ─────────────────────────────────────────────────────────
    consumes: List[str] = Field(
        default_factory=lambda: ["application/json"],
        description="Media types the endpoint consumes.",
    )
    produces: List[str] = Field(
        default_factory=lambda: ["application/json"],
        description="Media types the endpoint produces.",
    )
    content_type: str = Field(
        default="application/json",
        description="Primary Content-Type observed in responses.",
    )

    # ── HTTP response ─────────────────────────────────────────────────────────
    response_codes: List[int] = Field(
        default_factory=list, description="HTTP status codes returned by this endpoint."
    )
    sample_request: Optional[Dict[str, Any]] = Field(
        default=None, description="Example request payload."
    )
    sample_response: Optional[Dict[str, Any]] = Field(
        default=None, description="Example response body."
    )
    response_fields: List[str] = Field(
        default_factory=list, description="Top-level field names observed in response JSON."
    )

    # ── Headers ───────────────────────────────────────────────────────────────
    request_headers: List[str] = Field(
        default_factory=list, description="Notable request headers."
    )
    response_headers: Dict[str, str] = Field(
        default_factory=dict, description="Notable response headers observed."
    )

    # ── Security Context & Inherent Risk ──────────────────────────────────────
    category: EndpointCategory = Field(
        default=EndpointCategory.UNKNOWN, description="Functional category."
    )
    risk: RiskLevel = Field(
        default=RiskLevel.UNKNOWN, description="Preliminary inherent security risk level (attack surface)."
    )
    risk_rationale: Optional[str] = Field(
        default=None, description="Explanation for the assigned inherent risk level."
    )
    sensitive_operation: bool = Field(
        default=False, description="Whether endpoint modifies user data or administrative state."
    )
    potential_idor: bool = Field(
        default=False, description="Whether endpoint accepts user object identifiers in path/query."
    )
    vulnerability_status: str = Field(
        default="NOT_TESTED",
        description="Security vulnerability status: 'NOT_TESTED' in Phase 1 discovery; updated to 'CONFIRMED' or 'REFUTED' in Phase 2.",
    )
    vulnerability_details: Optional[str] = Field(
        default=None, description="Details of confirmed vulnerability if tested."
    )

    # ── Provenance ────────────────────────────────────────────────────────────
    discovered_by: DiscoveryMethod = Field(
        default=DiscoveryMethod.MANUAL, description="How this endpoint was discovered."
    )
    full_url: Optional[str] = Field(
        default=None, description="Absolute URL observed during discovery."
    )

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("endpoint")
    @classmethod
    def _normalise_endpoint(cls, v: str) -> str:
        """Ensure the endpoint path always starts with '/'."""
        if not v.startswith("/"):
            v = "/" + v
        return v.rstrip("/") or "/"

    @field_validator("response_codes")
    @classmethod
    def _sort_codes(cls, v: List[int]) -> List[int]:
        """Keep response codes sorted and de-duplicated."""
        return sorted(set(v))

    # ── Helpers ───────────────────────────────────────────────────────────────

    @property
    def unique_key(self) -> str:
        """
        Deduplication key combining method and path.

        Returns
        -------
        str
            E.g. ``"POST:/users/v1/login"``
        """
        return f"{self.method.value}:{self.endpoint}"

    def path_parameters(self) -> List[ParameterModel]:
        """Filter parameters located in the path."""
        return [p for p in self.parameters if p.location == "path"]

    def query_parameters(self) -> List[ParameterModel]:
        """Filter parameters located in the query string."""
        return [p for p in self.parameters if p.location == "query"]

    def body_parameters(self) -> List[ParameterModel]:
        """Filter parameters located in the request body."""
        return [p for p in self.parameters if p.location == "body"]

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise to a plain dict formatted with both top-level keys
        and structured sub-objects (`discovery`, `authentication`, `security_context`).
        """
        base = self.model_dump(
            mode="json",
            exclude_none=False,
            by_alias=True,
        )

        # Build clean structured sub-objects for enhanced Phase 1 presentation
        base["discovery"] = {
            "source": self.discovered_by.value,
            "declared_in_openapi": self.declared_in_openapi,
            "supported": self.supported,
            "observed_status": self.observed_status or (self.response_codes[0] if self.response_codes else None),
        }

        base["authentication"] = {
            "required": self.authentication_required,
            "type": self.authentication_type.value,
            "purpose": self.auth_purpose or ("resource_access" if self.authentication_required else "public_or_unauthenticated"),
        }

        base["security_context"] = {
            "category": self.category.value,
            "inherent_risk": self.risk.value,
            "risk_type": "attack_surface_heuristic",
            "vulnerability_status": self.vulnerability_status,
            "vulnerability_details": self.vulnerability_details,
            "risk_rationale": self.risk_rationale,
            "sensitive_operation": self.sensitive_operation,
            "potential_idor": self.potential_idor,
        }

        return base

    def __repr__(self) -> str:
        return (
            f"EndpointModel({self.method.value} {self.endpoint}, "
            f"supported={self.supported}, risk={self.risk.value}, auth={self.authentication_required})"
        )
