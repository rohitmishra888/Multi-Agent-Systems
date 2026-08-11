"""
tests/test_swagger_parser.py
============================
Unit tests for the ``SwaggerParser`` tool.

Coverage
--------
- Successful OpenAPI 2.0 spec parsing
- Successful OpenAPI 3.0 spec parsing
- Probe path iteration when spec not found
- Parameter extraction
- Authentication detection
- Response code extraction
- $ref resolution
"""

from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from models.endpoint import AuthType, DiscoveryMethod, HTTPMethod
from tests.conftest import make_response
from tools.swagger_parser import SwaggerParser


class TestSwaggerParserProbing:
    """Tests for the OpenAPI spec discovery/probing logic."""

    def test_returns_empty_when_all_probes_404(self, mock_http_client):
        """When every probe path returns 404, parse() returns ([], None)."""
        mock_http_client.get.return_value = make_response(404, "Not found")
        parser = SwaggerParser(client=mock_http_client, probe_paths=["/swagger.json", "/openapi.json"])

        endpoints, url = parser.parse()

        assert endpoints == []
        assert url is None

    def test_finds_swagger_json(self, mock_http_client, sample_swagger_spec):
        """Parser finds a spec at /swagger.json and returns endpoints."""
        spec_json = json.dumps(sample_swagger_spec)

        def mock_get(path, **_kwargs):
            if path == "/swagger.json":
                return make_response(200, spec_json, url="http://localhost:5000/swagger.json")
            return make_response(404)

        mock_http_client.get.side_effect = mock_get
        parser = SwaggerParser(client=mock_http_client, probe_paths=["/swagger.json"])

        endpoints, url = parser.parse()

        assert url is not None
        assert len(endpoints) >= 1
        assert "swagger.json" in url

    def test_skips_non_json_200_response(self, mock_http_client):
        """A 200 response with HTML body is not treated as an OpenAPI spec."""
        mock_http_client.get.return_value = make_response(
            200, "<html><body>Hello</body></html>", content_type="text/html"
        )
        parser = SwaggerParser(client=mock_http_client, probe_paths=["/docs"])

        endpoints, url = parser.parse()

        assert endpoints == []
        assert url is None


class TestSwaggerParserOAS2:
    """Tests for OpenAPI 2.0 (Swagger) spec parsing."""

    def _make_parser(self, spec: Dict[str, Any]) -> SwaggerParser:
        """Helper: create a parser with the spec loaded."""
        client = MagicMock()
        spec_json = json.dumps(spec)
        client.get.return_value = make_response(200, spec_json, url="http://localhost:5000/swagger.json")
        return SwaggerParser(client=client, probe_paths=["/swagger.json"])

    def test_extracts_get_endpoint(self, sample_swagger_spec):
        """GET /users/v1 is extracted correctly."""
        parser = self._make_parser(sample_swagger_spec)
        endpoints, _ = parser.parse()

        get_users = next(
            (e for e in endpoints if e.endpoint == "/users/v1" and e.method == HTTPMethod.GET),
            None,
        )
        assert get_users is not None
        assert get_users.discovered_by == DiscoveryMethod.SWAGGER

    def test_extracts_post_endpoint(self, sample_swagger_spec):
        """POST /users/v1/login is extracted correctly."""
        parser = self._make_parser(sample_swagger_spec)
        endpoints, _ = parser.parse()

        post_login = next(
            (e for e in endpoints if e.endpoint == "/users/v1/login" and e.method == HTTPMethod.POST),
            None,
        )
        assert post_login is not None

    def test_extracts_response_codes(self, sample_swagger_spec):
        """Response codes are extracted from the spec."""
        parser = self._make_parser(sample_swagger_spec)
        endpoints, _ = parser.parse()

        post_login = next(
            (e for e in endpoints if e.endpoint == "/users/v1/login"),
            None,
        )
        assert post_login is not None
        assert 200 in post_login.response_codes
        assert 401 in post_login.response_codes

    def test_extracts_body_parameter(self, sample_swagger_spec):
        """Body parameters are extracted from POST operations."""
        parser = self._make_parser(sample_swagger_spec)
        endpoints, _ = parser.parse()

        post_login = next(
            (e for e in endpoints if e.endpoint == "/users/v1/login"),
            None,
        )
        assert post_login is not None
        assert post_login.request_schema is not None
        assert "username" in post_login.request_schema.get("properties", {})

    def test_extracts_operation_id(self, sample_swagger_spec):
        """operationId is preserved from the spec."""
        parser = self._make_parser(sample_swagger_spec)
        endpoints, _ = parser.parse()

        get_users = next((e for e in endpoints if e.endpoint == "/users/v1"), None)
        assert get_users is not None
        assert get_users.operation_id == "list_users"

    def test_base_path_prepended(self):
        """basePath is prepended to each path when present."""
        spec = {
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "basePath": "/api",
            "paths": {
                "/users": {
                    "get": {
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
        client = MagicMock()
        client.get.return_value = make_response(
            200, json.dumps(spec), url="http://localhost:5000/swagger.json"
        )
        parser = SwaggerParser(client=client, probe_paths=["/swagger.json"])
        endpoints, _ = parser.parse()

        assert any(e.endpoint == "/api/users" for e in endpoints)


class TestSwaggerParserOAS3:
    """Tests for OpenAPI 3.0 spec parsing."""

    def _make_parser(self, spec: Dict[str, Any]) -> SwaggerParser:
        client = MagicMock()
        spec_json = json.dumps(spec)
        client.get.return_value = make_response(200, spec_json, url="http://localhost:5000/openapi.json")
        return SwaggerParser(client=client, probe_paths=["/openapi.json"])

    def test_extracts_get_books(self, sample_oas3_spec):
        """GET /books/v1 is extracted from OAS3 spec."""
        parser = self._make_parser(sample_oas3_spec)
        endpoints, _ = parser.parse()

        get_books = next(
            (e for e in endpoints if e.endpoint == "/books/v1" and e.method == HTTPMethod.GET),
            None,
        )
        assert get_books is not None

    def test_extracts_post_books_with_auth(self, sample_oas3_spec):
        """POST /books/v1 with Bearer JWT auth is detected."""
        parser = self._make_parser(sample_oas3_spec)
        endpoints, _ = parser.parse()

        post_books = next(
            (e for e in endpoints if e.endpoint == "/books/v1" and e.method == HTTPMethod.POST),
            None,
        )
        assert post_books is not None
        assert post_books.authentication_required is True
        assert post_books.authentication_type in (AuthType.BEARER, AuthType.JWT)

    def test_extracts_request_body_schema(self, sample_oas3_spec):
        """Request body schema is extracted from OAS3 requestBody."""
        parser = self._make_parser(sample_oas3_spec)
        endpoints, _ = parser.parse()

        post_books = next(
            (e for e in endpoints if e.method == HTTPMethod.POST),
            None,
        )
        assert post_books is not None
        assert post_books.request_schema is not None


class TestRefResolution:
    """Tests for JSON $ref resolution."""

    def test_resolves_definition_ref(self, sample_swagger_spec):
        """Definitions referenced via $ref are correctly resolved."""
        spec = {
            "swagger": "2.0",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/test": {
                    "get": {
                        "responses": {
                            "200": {
                                "schema": {"$ref": "#/definitions/MyModel"}
                            }
                        }
                    }
                }
            },
            "definitions": {
                "MyModel": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}},
                }
            },
        }
        client = MagicMock()
        client.get.return_value = make_response(200, json.dumps(spec), url="http://x/swagger.json")
        parser = SwaggerParser(client=client, probe_paths=["/swagger.json"])
        endpoints, _ = parser.parse()

        ep = next((e for e in endpoints if e.endpoint == "/test"), None)
        assert ep is not None
        # Response schema should be resolved (not a $ref dict)
        if ep.response_schema:
            assert "$ref" not in ep.response_schema
