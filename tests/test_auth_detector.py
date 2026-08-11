"""
tests/test_auth_detector.py
============================
Unit tests for the ``AuthDetector`` tool.

Coverage
--------
- 401 response → auth required
- WWW-Authenticate: Bearer → Bearer auth type
- WWW-Authenticate: Basic → Basic auth type
- JWT keyword in response body
- Path heuristics (/admin, /password)
- 200 response with no auth keywords → no auth
- Existing swagger auth not overwritten
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from models.endpoint import AuthType, EndpointModel, HTTPMethod
from tests.conftest import make_response
from tools.auth_detector import AuthDetector


class TestAuthDetectorViaStatusCode:
    """Tests for auth detection via HTTP status codes."""

    def test_401_marks_auth_required(self, mock_http_client):
        """A 401 response sets authentication_required=True."""
        mock_http_client.request.return_value = make_response(
            401, '{"error": "Unauthorized"}', headers={"content-type": "application/json"}
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(endpoint="/users/v1/profile", method=HTTPMethod.GET)

        result = detector.detect(ep)

        assert result.authentication_required is True

    def test_403_marks_auth_required(self, mock_http_client):
        """A 403 Forbidden response sets authentication_required=True."""
        mock_http_client.request.return_value = make_response(
            403, '{"error": "Forbidden"}', headers={"content-type": "application/json"}
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(endpoint="/admin", method=HTTPMethod.GET)

        result = detector.detect(ep)

        assert result.authentication_required is True

    def test_200_public_endpoint_no_auth(self, mock_http_client):
        """A 200 response with no auth signals leaves auth as not required."""
        mock_http_client.request.return_value = make_response(
            200, '{"books": []}', headers={"content-type": "application/json"}
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(endpoint="/books/v1", method=HTTPMethod.GET)

        result = detector.detect(ep)

        assert result.authentication_required is False


class TestAuthDetectorViaHeaders:
    """Tests for auth detection via WWW-Authenticate header."""

    def test_www_authenticate_bearer(self, mock_http_client):
        """WWW-Authenticate: Bearer → AuthType.BEARER."""
        mock_http_client.request.return_value = make_response(
            401,
            '{"error": "Unauthorized"}',
            headers={
                "content-type": "application/json",
                "www-authenticate": "Bearer realm='example'",
            },
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(endpoint="/protected", method=HTTPMethod.GET)

        result = detector.detect(ep)

        assert result.authentication_required is True
        assert result.authentication_type in (AuthType.BEARER, AuthType.JWT)

    def test_www_authenticate_basic(self, mock_http_client):
        """WWW-Authenticate: Basic → AuthType.BASIC."""
        mock_http_client.request.return_value = make_response(
            401,
            "Unauthorized",
            headers={
                "content-type": "text/plain",
                "www-authenticate": "Basic realm='admin'",
            },
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(endpoint="/admin/panel", method=HTTPMethod.GET)

        result = detector.detect(ep)

        assert result.authentication_required is True
        assert result.authentication_type == AuthType.BASIC


class TestAuthDetectorViaBody:
    """Tests for auth detection via response body keywords."""

    def test_jwt_keyword_in_body(self, mock_http_client):
        """'JWT' in response body → AuthType.JWT."""
        mock_http_client.request.return_value = make_response(
            401,
            '{"message": "JWT token required"}',
            headers={"content-type": "application/json"},
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(endpoint="/users/v1/1", method=HTTPMethod.GET)

        result = detector.detect(ep)

        assert result.authentication_required is True
        assert result.authentication_type == AuthType.JWT

    def test_token_required_in_body(self, mock_http_client):
        """'token required' in body → auth required."""
        mock_http_client.request.return_value = make_response(
            401,
            '{"message": "token required"}',
            headers={"content-type": "application/json"},
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(endpoint="/users/v1/1/email", method=HTTPMethod.PUT)

        result = detector.detect(ep)

        assert result.authentication_required is True


class TestAuthDetectorPathHeuristics:
    """Tests for path-based authentication heuristics."""

    def test_password_path_heuristic(self):
        """Paths containing /password are heuristically marked as auth-required."""
        client = MagicMock()
        # Simulate connection error so we fall back to heuristics
        client.request.side_effect = ConnectionError("offline")
        client.get.side_effect = ConnectionError("offline")

        detector = AuthDetector(client=client)
        ep = EndpointModel(endpoint="/users/v1/john/password", method=HTTPMethod.PUT)

        result = detector.detect(ep)

        assert result.authentication_required is True

    def test_admin_path_heuristic(self):
        """Paths containing /admin are heuristically marked as auth-required."""
        client = MagicMock()
        client.request.side_effect = ConnectionError("offline")
        client.get.side_effect = ConnectionError("offline")

        detector = AuthDetector(client=client)
        ep = EndpointModel(endpoint="/admin/users", method=HTTPMethod.GET)

        result = detector.detect(ep)

        assert result.authentication_required is True


class TestAuthDetectorPreservesSwaggerAuth:
    """Tests that Swagger-sourced auth is not overwritten with 'no auth'."""

    def test_swagger_auth_preserved_on_200(self, mock_http_client):
        """
        If Swagger says auth is required, a 200 response doesn't change that.
        (Some endpoints return 200 with partial data even without auth.)
        """
        mock_http_client.request.return_value = make_response(
            200, '{"data": "public"}', headers={"content-type": "application/json"}
        )
        detector = AuthDetector(client=mock_http_client)
        ep = EndpointModel(
            endpoint="/users/v1/1",
            method=HTTPMethod.GET,
            authentication_required=True,   # Set by Swagger
            authentication_type=AuthType.JWT,
        )

        result = detector.detect(ep)

        # Swagger-supplied auth must not be cleared
        assert result.authentication_required is True
