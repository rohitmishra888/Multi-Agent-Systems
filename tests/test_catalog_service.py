"""
tests/test_catalog_service.py
==============================
Unit tests for the ``CatalogService``.

Coverage
--------
- JSON catalogue file creation
- YAML catalogue file creation
- Statistics computation
- Summary line generation
- Catalogue loading from JSON
- Catalogue loading from YAML
- Empty endpoint list
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from models.catalog import APICatalog
from models.endpoint import (
    AuthType,
    DiscoveryMethod,
    EndpointCategory,
    EndpointModel,
    HTTPMethod,
    RiskLevel,
)
from services.catalog_service import CatalogService


class TestCatalogServiceFileCreation:
    """Tests that JSON and YAML files are created correctly."""

    def test_creates_json_file(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        json_file = temp_output_dir / "catalog.json"
        assert json_file.exists()

    def test_creates_yaml_file(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        yaml_file = temp_output_dir / "catalog.yaml"
        assert yaml_file.exists()

    def test_json_is_valid(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        with (temp_output_dir / "catalog.json").open() as f:
            data = json.load(f)

        assert "endpoints" in data
        assert "metadata" in data
        assert "statistics" in data

    def test_yaml_is_valid(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        with (temp_output_dir / "catalog.yaml").open() as f:
            data = yaml.safe_load(f)

        assert "endpoints" in data
        assert "metadata" in data

    def test_endpoint_count_in_json(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        with (temp_output_dir / "catalog.json").open() as f:
            data = json.load(f)

        assert len(data["endpoints"]) == len(sample_endpoints)

    def test_creates_output_dir_if_missing(self, sample_endpoints, tmp_path):
        """Output directory is created automatically if it doesn't exist."""
        new_dir = tmp_path / "nested" / "reports"
        assert not new_dir.exists()

        svc = CatalogService(output_dir=new_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        assert new_dir.exists()
        assert (new_dir / "catalog.json").exists()

    def test_overwrites_existing_file(self, sample_endpoints, temp_output_dir):
        """Running build_and_save twice overwrites (idempotent)."""
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        # Write again with one fewer endpoint
        svc.build_and_save(sample_endpoints[:3])

        with (temp_output_dir / "catalog.json").open() as f:
            data = json.load(f)
        assert len(data["endpoints"]) == 3


class TestCatalogStatistics:
    """Tests for statistics computation."""

    def test_total_endpoint_count(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        catalog = svc.build_and_save(sample_endpoints)

        assert catalog.statistics.total_endpoints == len(sample_endpoints)

    def test_by_method_counts(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        catalog = svc.build_and_save(sample_endpoints)

        # Count manually
        expected_gets = sum(1 for e in sample_endpoints if e.method == HTTPMethod.GET)
        assert catalog.statistics.by_method.get("GET", 0) == expected_gets

    def test_authenticated_count(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        catalog = svc.build_and_save(sample_endpoints)

        expected_auth = sum(1 for e in sample_endpoints if e.authentication_required)
        assert catalog.statistics.authenticated_endpoints == expected_auth

    def test_empty_endpoints(self, temp_output_dir):
        """Empty endpoint list produces a catalogue with zero-count statistics."""
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        catalog = svc.build_and_save([])

        assert catalog.statistics.total_endpoints == 0


class TestCatalogLoading:
    """Tests for loading saved catalogues."""

    def test_load_json_round_trip(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        loaded = CatalogService.load_json(temp_output_dir / "catalog.json")

        assert isinstance(loaded, APICatalog)
        assert len(loaded.endpoints) == len(sample_endpoints)

    def test_load_yaml_round_trip(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        loaded = CatalogService.load_yaml(temp_output_dir / "catalog.yaml")

        assert isinstance(loaded, APICatalog)
        assert len(loaded.endpoints) == len(sample_endpoints)

    def test_load_json_raises_on_missing_file(self, temp_output_dir):
        with pytest.raises(FileNotFoundError):
            CatalogService.load_json(temp_output_dir / "nonexistent.json")

    def test_load_yaml_raises_on_missing_file(self, temp_output_dir):
        with pytest.raises(FileNotFoundError):
            CatalogService.load_yaml(temp_output_dir / "nonexistent.yaml")

    def test_endpoint_methods_preserved(self, sample_endpoints, temp_output_dir):
        """HTTP methods are correctly preserved through serialisation."""
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        svc.build_and_save(sample_endpoints)

        loaded = CatalogService.load_json(temp_output_dir / "catalog.json")
        loaded_methods = {e.method for e in loaded.endpoints}
        original_methods = {e.method for e in sample_endpoints}

        assert loaded_methods == original_methods


class TestCatalogSummaryLines:
    """Tests for summary line generation."""

    def test_summary_contains_total(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        catalog = svc.build_and_save(sample_endpoints)

        summary = "\n".join(catalog.summary_lines())
        assert "Endpoints Found" in summary

    def test_summary_contains_risk_levels(self, sample_endpoints, temp_output_dir):
        svc = CatalogService(output_dir=temp_output_dir, target_url="http://localhost:5000")
        catalog = svc.build_and_save(sample_endpoints)

        summary = "\n".join(catalog.summary_lines())
        # At least one risk level should appear
        assert any(level in summary for level in ["HIGH", "MEDIUM", "LOW", "CRITICAL"])
