"""
services/catalog_service.py
============================
Builds, validates, and persists the API catalogue to disk.

Responsibilities
----------------
1. Accept a list of ``EndpointModel`` instances from the discovery pipeline.
2. Construct an ``APICatalog`` with scan metadata and computed statistics.
3. Write ``catalog.json`` and ``catalog.yaml`` to the configured output directory.
4. Provide a summary for console display.

Design
------
* Pure service — no HTTP calls, no side effects beyond file I/O.
* Output directory is created automatically if it doesn't exist.
* Existing files are overwritten on each run (idempotent).
* Both output formats are self-contained — either can be consumed
  independently by Phase 2.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import yaml

from models.catalog import APICatalog, CatalogStats, ScanMetadata
from models.endpoint import EndpointModel
from utils.logger import get_logger

logger = get_logger(__name__)

# File names within the output directory
_CATALOG_JSON = "catalog.json"
_CATALOG_YAML = "catalog.yaml"


class CatalogService:
    """
    Builds and persists the API catalogue.

    Parameters
    ----------
    output_dir:
        Directory where catalog files are written.
        Created automatically if it doesn't exist.
    target_url:
        The URL that was scanned (stored in catalogue metadata).
    scanner_version:
        Version string embedded in the catalogue.
    """

    def __init__(
        self,
        output_dir: Path,
        target_url: str,
        scanner_version: str = "1.0.0",
    ) -> None:
        self._output_dir = output_dir
        self._target_url = target_url
        self._scanner_version = scanner_version

    # ── Public interface ────────────────────────────────────────────────────

    def build_and_save(
        self,
        endpoints: List[EndpointModel],
        scan_started_at: Optional[datetime] = None,
        openapi_found: bool = False,
        openapi_url: Optional[str] = None,
        notes: Optional[List[str]] = None,
    ) -> APICatalog:
        """
        Build the catalogue from discovered endpoints and write it to disk.

        Parameters
        ----------
        endpoints:
            All discovered endpoints (already deduplicated and enriched).
        scan_started_at:
            UTC datetime when the scan began.
        openapi_found:
            Whether an OpenAPI/Swagger spec was successfully parsed.
        openapi_url:
            The URL from which the spec was retrieved.
        notes:
            Free-text notes from the scan run.

        Returns
        -------
        APICatalog
            The complete, persisted catalogue.
        """
        logger.info("Building API catalogue", endpoint_count=len(endpoints))

        # Ensure output directory exists
        self._output_dir.mkdir(parents=True, exist_ok=True)

        # Build catalogue
        metadata = ScanMetadata(
            target_url=self._target_url,
            scan_started_at=scan_started_at or datetime.now(timezone.utc),
            scan_completed_at=datetime.now(timezone.utc),
            scanner_version=self._scanner_version,
            openapi_found=openapi_found,
            openapi_url=openapi_url,
            notes=notes or [],
        )

        statistics = CatalogStats.from_endpoints(endpoints)

        catalog = APICatalog(
            metadata=metadata,
            statistics=statistics,
            endpoints=endpoints,
        )

        # Write outputs
        json_path = self._write_json(catalog)
        yaml_path = self._write_yaml(catalog)

        logger.info(
            "Catalogue saved",
            json_path=str(json_path),
            yaml_path=str(yaml_path),
            endpoints=len(endpoints),
        )

        return catalog

    # ── File writers ─────────────────────────────────────────────────────────

    def _write_json(self, catalog: APICatalog) -> Path:
        """
        Serialise the catalogue to JSON and write to disk.

        Returns
        -------
        Path
            The path of the written file.
        """
        out_path = self._output_dir / _CATALOG_JSON
        catalog_dict = catalog.to_dict()

        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(catalog_dict, fh, indent=2, ensure_ascii=False, default=str)

        logger.info("JSON catalogue written", path=str(out_path))
        return out_path

    def _write_yaml(self, catalog: APICatalog) -> Path:
        """
        Serialise the catalogue to YAML and write to disk.

        Returns
        -------
        Path
            The path of the written file.
        """
        out_path = self._output_dir / _CATALOG_YAML
        catalog_dict = catalog.to_dict()

        with out_path.open("w", encoding="utf-8") as fh:
            yaml.dump(
                catalog_dict,
                fh,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
                indent=2,
            )

        logger.info("YAML catalogue written", path=str(out_path))
        return out_path

    # ── Path accessors ────────────────────────────────────────────────────────

    @property
    def json_path(self) -> Path:
        """Full path to the JSON catalogue file."""
        return self._output_dir / _CATALOG_JSON

    @property
    def yaml_path(self) -> Path:
        """Full path to the YAML catalogue file."""
        return self._output_dir / _CATALOG_YAML

    # ── Loading ───────────────────────────────────────────────────────────────

    @classmethod
    def load_json(cls, path: Path) -> APICatalog:
        """
        Load a previously saved catalogue from a JSON file.

        Used by Phase 2 to consume the Phase 1 output.

        Parameters
        ----------
        path:
            Path to ``catalog.json``.

        Returns
        -------
        APICatalog
            Deserialised catalogue.

        Raises
        ------
        FileNotFoundError
            When the file does not exist.
        ValueError
            When the file contents are not valid JSON or fail schema validation.
        """
        if not path.exists():
            raise FileNotFoundError(f"Catalogue not found: {path}")

        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        return APICatalog.model_validate(data)

    @classmethod
    def load_yaml(cls, path: Path) -> APICatalog:
        """
        Load a previously saved catalogue from a YAML file.

        Parameters
        ----------
        path:
            Path to ``catalog.yaml``.

        Returns
        -------
        APICatalog
        """
        if not path.exists():
            raise FileNotFoundError(f"Catalogue not found: {path}")

        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        return APICatalog.model_validate(data)
