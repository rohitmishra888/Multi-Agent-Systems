"""
tests/test_metadata_extractor.py
=================================
Unit tests for the ``MetadataExtractor`` tool.

Coverage
--------
- Path parameter extraction from {param} segments
- Full URL construction
- Description generation
- Content type normalisation
- Query parameter inference for list endpoints
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from models.endpoint import EndpointModel, HTTPMethod, ParameterModel
from tests.conftest import make_response
from tools.metadata_extractor import MetadataExtractor


BASE_URL = "http://localhost:5000"


@pytest.fixture
def extractor(mock_http_client) -> MetadataExtractor:
    return MetadataExtractor(client=mock_http_client, base_url=BASE_URL)


class TestPathParameterExtraction:
    """Tests for extracting {param} segments as ParameterModel instances."""

    def test_extracts_single_path_param(self, extractor):
        ep = EndpointModel(endpoint="/users/v1/{user_id}", method=HTTPMethod.GET)
        result = extractor.extract(ep)

        path_params = result.path_parameters()
        assert len(path_params) == 1
        assert path_params[0].name == "user_id"
        assert path_params[0].location == "path"
        assert path_params[0].required is True

    def test_extracts_multiple_path_params(self, extractor):
        ep = EndpointModel(
            endpoint="/users/v1/{user_id}/books/{book_id}",
            method=HTTPMethod.GET,
        )
        result = extractor.extract(ep)

        param_names = {p.name for p in result.path_parameters()}
        assert "user_id" in param_names
        assert "book_id" in param_names

    def test_no_path_params_for_static_path(self, extractor):
        ep = EndpointModel(endpoint="/users/v1", method=HTTPMethod.GET)
        result = extractor.extract(ep)

        assert result.path_parameters() == []

    def test_does_not_duplicate_params_from_swagger(self, extractor):
        """If Swagger already added a path param, don't add it again."""
        ep = EndpointModel(
            endpoint="/users/v1/{user_id}",
            method=HTTPMethod.GET,
            parameters=[
                ParameterModel(
                    name="user_id",
                    location="path",
                    required=True,
                    description="From Swagger",
                )
            ],
        )
        result = extractor.extract(ep)

        # Should still be exactly one 'user_id' param
        user_id_params = [p for p in result.path_parameters() if p.name == "user_id"]
        assert len(user_id_params) == 1


class TestFullURLConstruction:
    """Tests for full URL population."""

    def test_full_url_set(self, extractor):
        ep = EndpointModel(endpoint="/users/v1", method=HTTPMethod.GET)
        result = extractor.extract(ep)
        assert result.full_url == f"{BASE_URL}/users/v1"

    def test_full_url_with_path_param(self, extractor):
        ep = EndpointModel(endpoint="/users/v1/{user_id}", method=HTTPMethod.GET)
        result = extractor.extract(ep)
        assert result.full_url == f"{BASE_URL}/users/v1/{{user_id}}"


class TestDescriptionGeneration:
    """Tests for auto-generated descriptions."""

    def test_get_generates_retrieve_description(self, extractor):
        ep = EndpointModel(endpoint="/books/v1", method=HTTPMethod.GET)
        result = extractor.extract(ep)
        assert result.description is not None
        assert "retrieve" in result.description.lower() or "v1" in result.description.lower()

    def test_post_generates_create_description(self, extractor):
        ep = EndpointModel(endpoint="/books/v1", method=HTTPMethod.POST)
        result = extractor.extract(ep)
        assert result.description is not None

    def test_existing_description_not_overwritten(self, extractor):
        """A description set by Swagger is preserved."""
        ep = EndpointModel(
            endpoint="/books/v1",
            method=HTTPMethod.GET,
            description="List all books (from spec)",
        )
        result = extractor.extract(ep)
        assert result.description == "List all books (from spec)"


class TestContentTypeNormalisation:
    """Tests for consumes/produces normalisation."""

    def test_empty_consumes_gets_default(self, extractor):
        ep = EndpointModel(endpoint="/books/v1", method=HTTPMethod.POST, consumes=[])
        result = extractor.extract(ep)
        assert "application/json" in result.consumes

    def test_empty_produces_gets_default(self, extractor):
        ep = EndpointModel(endpoint="/books/v1", method=HTTPMethod.GET, produces=[])
        result = extractor.extract(ep)
        assert "application/json" in result.produces

    def test_duplicates_removed_from_produces(self, extractor):
        ep = EndpointModel(
            endpoint="/books/v1",
            method=HTTPMethod.GET,
            produces=["application/json", "application/json", "text/html"],
        )
        result = extractor.extract(ep)
        # Duplicates removed
        assert result.produces.count("application/json") == 1


class TestQueryParameterInference:
    """Tests for inferred query parameters."""

    def test_search_endpoint_gets_query_params(self, extractor):
        ep = EndpointModel(endpoint="/books/v1/search", method=HTTPMethod.GET)
        result = extractor.extract(ep)

        query_params = result.query_parameters()
        param_names = {p.name for p in query_params}
        # Should have at least 'q' or 'query'
        assert param_names & {"q", "query", "limit", "offset"}

    def test_non_get_endpoint_no_inferred_params(self, extractor):
        ep = EndpointModel(endpoint="/books/v1", method=HTTPMethod.POST)
        result = extractor.extract(ep)
        # POST endpoints don't get inferred query params
        query_params = result.query_parameters()
        assert len(query_params) == 0
