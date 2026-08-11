"""
tests/conftest.py
==================
Shared pytest fixtures for the Phase 1 API Discovery test suite.

Fixtures provided
-----------------
- ``mock_http_client``     : A mock ``HTTPClient`` with configurable responses
- ``sample_swagger_spec``  : Minimal valid OpenAPI 2.0 spec dict
- ``sample_oas3_spec``     : Minimal valid OpenAPI 3.0 spec dict
- ``sample_endpoints``     : A list of pre-built ``EndpointModel`` instances
- ``temp_output_dir``      : A temporary directory for output file tests
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from models.endpoint import (
    AuthType,
    DiscoveryMethod,
    EndpointCategory,
    EndpointModel,
    HTTPMethod,
    ParameterModel,
    RiskLevel,
)
from utils.http_client import HTTPResponse


# ---------------------------------------------------------------------------
# HTTP mock helpers
# ---------------------------------------------------------------------------

def make_response(
    status_code: int = 200,
    text: str = "{}",
    content_type: str = "application/json",
    headers: Dict[str, str] | None = None,
    url: str = "http://localhost:5000/",
    method: str = "GET",
) -> HTTPResponse:
    """Build a mock HTTPResponse with sane defaults."""
    return HTTPResponse(
        status_code=status_code,
        headers=headers or {"content-type": content_type},
        text=text,
        url=url,
        method=method,
        elapsed_ms=10.0,
    )


@pytest.fixture
def mock_http_client():
    """
    Return a MagicMock that behaves like an ``HTTPClient``.

    Tests can configure return values via::

        mock_http_client.get.return_value = make_response(200, '{"key": "val"}')
    """
    client = MagicMock()
    # Default: 404 for everything
    default = make_response(404, '{"detail": "Not found"}')
    client.get.return_value = default
    client.post.return_value = default
    client.put.return_value = default
    client.delete.return_value = default
    client.patch.return_value = default
    client.options.return_value = default
    client.head.return_value = default
    client.request.return_value = default
    return client


# ---------------------------------------------------------------------------
# OpenAPI spec fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_swagger_spec() -> Dict[str, Any]:
    """Minimal valid Swagger 2.0 specification with two endpoints."""
    return {
        "swagger": "2.0",
        "info": {"title": "VAmPI", "version": "1.0"},
        "basePath": "",
        "paths": {
            "/users/v1": {
                "get": {
                    "operationId": "list_users",
                    "tags": ["users"],
                    "summary": "List all users",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "schema": {
                                "type": "array",
                                "items": {"$ref": "#/definitions/User"},
                            },
                        }
                    },
                }
            },
            "/users/v1/login": {
                "post": {
                    "operationId": "login_user",
                    "tags": ["users"],
                    "summary": "Login",
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                },
                                "required": ["username", "password"],
                            },
                        }
                    ],
                    "responses": {
                        "200": {"description": "JWT token returned"},
                        "400": {"description": "Bad request"},
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
        },
        "definitions": {
            "User": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                },
            }
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "bearerFormat": "JWT",
            }
        },
    }


@pytest.fixture
def sample_oas3_spec() -> Dict[str, Any]:
    """Minimal valid OpenAPI 3.0 specification."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "VAmPI OAS3", "version": "1.0"},
        "paths": {
            "/books/v1": {
                "get": {
                    "summary": "List books",
                    "tags": ["books"],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "object"},
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "summary": "Create a book",
                    "tags": ["books"],
                    "security": [{"BearerAuth": []}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "user": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Book created"},
                        "401": {"description": "Unauthorized"},
                    },
                },
            }
        },
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
    }


# ---------------------------------------------------------------------------
# Endpoint fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_endpoints() -> List[EndpointModel]:
    """A representative set of endpoint models for catalogue/classifier tests."""
    return [
        EndpointModel(
            endpoint="/users/v1",
            method=HTTPMethod.GET,
            description="List users",
            authentication_required=False,
            authentication_type=AuthType.NONE,
            category=EndpointCategory.USER_MANAGEMENT,
            risk=RiskLevel.LOW,
            discovered_by=DiscoveryMethod.SWAGGER,
            response_codes=[200],
        ),
        EndpointModel(
            endpoint="/users/v1/login",
            method=HTTPMethod.POST,
            description="User login",
            authentication_required=False,
            authentication_type=AuthType.NONE,
            category=EndpointCategory.AUTHENTICATION,
            risk=RiskLevel.HIGH,
            discovered_by=DiscoveryMethod.SWAGGER,
            response_codes=[200, 400, 401],
        ),
        EndpointModel(
            endpoint="/users/v1/register",
            method=HTTPMethod.POST,
            description="User registration",
            authentication_required=False,
            authentication_type=AuthType.NONE,
            category=EndpointCategory.AUTHENTICATION,
            risk=RiskLevel.HIGH,
            discovered_by=DiscoveryMethod.SWAGGER,
            response_codes=[200, 400],
        ),
        EndpointModel(
            endpoint="/users/v1/{user_id}",
            method=HTTPMethod.GET,
            description="Get user by ID",
            authentication_required=True,
            authentication_type=AuthType.JWT,
            jwt_required=True,
            category=EndpointCategory.USER_MANAGEMENT,
            risk=RiskLevel.MEDIUM,
            parameters=[
                ParameterModel(name="user_id", location="path", required=True)
            ],
            discovered_by=DiscoveryMethod.SWAGGER,
            response_codes=[200, 401, 404],
        ),
        EndpointModel(
            endpoint="/users/v1/{user_id}",
            method=HTTPMethod.DELETE,
            description="Delete user",
            authentication_required=True,
            authentication_type=AuthType.JWT,
            jwt_required=True,
            category=EndpointCategory.USER_MANAGEMENT,
            risk=RiskLevel.HIGH,
            discovered_by=DiscoveryMethod.SWAGGER,
            response_codes=[200, 401, 404],
        ),
        EndpointModel(
            endpoint="/books/v1",
            method=HTTPMethod.GET,
            description="List books",
            authentication_required=False,
            authentication_type=AuthType.NONE,
            category=EndpointCategory.BOOK_MANAGEMENT,
            risk=RiskLevel.LOW,
            discovered_by=DiscoveryMethod.SWAGGER,
            response_codes=[200],
        ),
        EndpointModel(
            endpoint="/admin",
            method=HTTPMethod.GET,
            description="Admin panel",
            authentication_required=False,  # Misconfiguration!
            authentication_type=AuthType.NONE,
            category=EndpointCategory.ADMINISTRATION,
            risk=RiskLevel.CRITICAL,
            discovered_by=DiscoveryMethod.GUESSER,
            response_codes=[200],
        ),
    ]


# ---------------------------------------------------------------------------
# File system fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Return a temporary directory for output file tests."""
    out = tmp_path / "reports"
    out.mkdir()
    return out
