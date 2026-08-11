"""
services/discovery_service.py
==============================
Orchestrates the five-step API discovery pipeline.

Pipeline Execution Order
------------------------
Step 1  — OpenAPI/Swagger parsing          (SwaggerParser)
Step 2  — HTTP crawling                   (Crawler)
Step 3  — Endpoint guessing               (EndpointGuesser)
Step 4  — HTTP response analysis          (ResponseAnalyzer)
Step 5  — HTTP method enumeration         (MethodEnumerator)

Post-pipeline enrichment
------------------------
After the core 5 steps, each discovered endpoint is further enriched:
- Metadata extraction                     (MetadataExtractor)
- Authentication detection                (AuthDetector)
- Classification (category + risk)        (Classifier)

Finally, all results are merged and deduplicated by (method, path) key.

Design
------
* Each step is implemented as a separate tool class (SRP).
* The service is injectable: tools are created internally but can be
  overridden via constructor arguments for testing.
* All errors in individual steps are caught and logged; the pipeline
  continues even if a step fails.
* Returns a deduplicated list of fully enriched ``EndpointModel`` instances.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from models.endpoint import EndpointModel
from tools.auth_detector import AuthDetector
from tools.classifier import Classifier
from tools.crawler import Crawler
from tools.endpoint_guesser import EndpointGuesser
from tools.metadata_extractor import MetadataExtractor
from tools.method_enumerator import MethodEnumerator
from tools.response_analyzer import ResponseAnalyzer
from tools.swagger_parser import SwaggerParser
from utils.helpers import endpoint_key
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)


class DiscoveryService:
    """
    Orchestrates the complete API discovery workflow.

    Parameters
    ----------
    base_url:
        Target application base URL.
    client:
        Pre-configured ``HTTPClient``. If None, a new one is created.
    swagger_parser:
        Override for testing.
    crawler:
        Override for testing.
    guesser:
        Override for testing.
    response_analyzer:
        Override for testing.
    method_enumerator:
        Override for testing.
    metadata_extractor:
        Override for testing.
    auth_detector:
        Override for testing.
    classifier:
        Override for testing.
    skip_method_enumeration:
        Set True to skip Step 5 (useful for quick scans).
    """

    def __init__(
        self,
        base_url: str,
        client: Optional[HTTPClient] = None,
        swagger_parser: Optional[SwaggerParser] = None,
        crawler: Optional[Crawler] = None,
        guesser: Optional[EndpointGuesser] = None,
        response_analyzer: Optional[ResponseAnalyzer] = None,
        method_enumerator: Optional[MethodEnumerator] = None,
        metadata_extractor: Optional[MetadataExtractor] = None,
        auth_detector: Optional[AuthDetector] = None,
        classifier: Optional[Classifier] = None,
        skip_method_enumeration: bool = False,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or HTTPClient(base_url=self._base_url)

        # Tool instances — allow injection for testing
        self._swagger_parser = swagger_parser or SwaggerParser(client=self._client)
        self._crawler = crawler or Crawler(client=self._client, base_url=self._base_url)
        self._guesser = guesser or EndpointGuesser(client=self._client)
        self._response_analyzer = response_analyzer or ResponseAnalyzer(client=self._client)
        self._method_enumerator = method_enumerator or MethodEnumerator(client=self._client)
        self._metadata_extractor = metadata_extractor or MetadataExtractor(
            client=self._client, base_url=self._base_url
        )
        self._auth_detector = auth_detector or AuthDetector(client=self._client)
        self._classifier = classifier or Classifier()
        self._skip_method_enum = skip_method_enumeration

        # Discovery result state
        self._openapi_url: Optional[str] = None
        self._openapi_found: bool = False
        self._notes: List[str] = []

    # ── Public interface ────────────────────────────────────────────────────

    def run(self) -> List[EndpointModel]:
        """
        Execute the full discovery pipeline.

        Returns
        -------
        List[EndpointModel]
            Deduplicated, fully enriched endpoint models.
        """
        start_time = time.time()
        logger.info("Discovery pipeline started", target=self._base_url)

        # Accumulate raw (unenriched) endpoints from all discovery strategies
        raw_endpoints: List[EndpointModel] = []

        # ── Step 1: Swagger / OpenAPI ─────────────────────────────────────────
        swagger_endpoints = self._step_swagger()
        raw_endpoints.extend(swagger_endpoints)

        # ── Step 2: Crawler ───────────────────────────────────────────────────
        crawler_endpoints = self._step_crawler()
        raw_endpoints.extend(crawler_endpoints)

        # ── Step 3: Endpoint Guesser ──────────────────────────────────────────
        guesser_endpoints = self._step_guesser()
        raw_endpoints.extend(guesser_endpoints)

        # ── Preliminary deduplication (path-level) ────────────────────────────
        # At this stage we deduplicate by path only (method enumeration may
        # expand these into multiple methods in Step 5)
        unique_by_path = self._deduplicate_by_path(raw_endpoints)
        logger.info(
            "Pre-enrichment deduplication complete",
            raw_count=len(raw_endpoints),
            unique_paths=len(unique_by_path),
        )

        # ── Step 4: Response Analysis ─────────────────────────────────────────
        analysed = self._step_response_analysis(unique_by_path)

        # ── Step 5: Method Enumeration ────────────────────────────────────────
        if not self._skip_method_enum:
            all_method_endpoints = self._step_method_enumeration(analysed)
        else:
            all_method_endpoints = analysed

        # ── Metadata Extraction ───────────────────────────────────────────────
        enriched = self._step_metadata_extraction(all_method_endpoints)

        # ── Auth Detection ────────────────────────────────────────────────────
        auth_enriched = self._step_auth_detection(enriched)

        # ── Classification ────────────────────────────────────────────────────
        classified = self._step_classification(auth_enriched)

        # ── Final deduplication by (method, path) key ─────────────────────────
        final = self._deduplicate_by_method_path(classified)

        elapsed = time.time() - start_time
        logger.info(
            "Discovery pipeline complete",
            total_endpoints=len(final),
            elapsed_seconds=f"{elapsed:.2f}",
            openapi_found=self._openapi_found,
        )
        return final

    @property
    def openapi_url(self) -> Optional[str]:
        """The URL from which the OpenAPI spec was retrieved (or None)."""
        return self._openapi_url

    @property
    def openapi_found(self) -> bool:
        """Whether an OpenAPI specification was successfully parsed."""
        return self._openapi_found

    @property
    def notes(self) -> List[str]:
        """Human-readable notes accumulated during the scan."""
        return list(self._notes)

    # ── Step implementations ────────────────────────────────────────────────

    def _step_swagger(self) -> List[EndpointModel]:
        """Execute Step 1: OpenAPI/Swagger discovery."""
        logger.info("Step 1: OpenAPI/Swagger discovery")
        try:
            endpoints, spec_url = self._swagger_parser.parse()
            if spec_url:
                self._openapi_url = spec_url
                self._openapi_found = True
                self._notes.append(f"OpenAPI spec found at: {spec_url}")
                logger.info("Swagger parsing success", endpoints=len(endpoints), spec_url=spec_url)
            else:
                self._notes.append("No OpenAPI/Swagger spec found — falling back to crawling and guessing.")
                logger.info("No OpenAPI spec found")
            return endpoints
        except Exception as exc:
            logger.error("Step 1 failed", error=str(exc))
            self._notes.append(f"Swagger step error: {exc}")
            return []

    def _step_crawler(self) -> List[EndpointModel]:
        """Execute Step 2: HTTP crawling."""
        logger.info("Step 2: HTTP crawling")
        try:
            endpoints = self._crawler.crawl()
            logger.info("Crawler complete", endpoints_found=len(endpoints))
            return endpoints
        except Exception as exc:
            logger.error("Step 2 (Crawler) failed", error=str(exc))
            self._notes.append(f"Crawler error: {exc}")
            return []

    def _step_guesser(self) -> List[EndpointModel]:
        """Execute Step 3: Endpoint guessing."""
        logger.info("Step 3: Endpoint guessing")
        try:
            endpoints = self._guesser.guess()
            logger.info("Guesser complete", endpoints_found=len(endpoints))
            return endpoints
        except Exception as exc:
            logger.error("Step 3 (Guesser) failed", error=str(exc))
            self._notes.append(f"Guesser error: {exc}")
            return []

    def _step_response_analysis(self, endpoints: List[EndpointModel]) -> List[EndpointModel]:
        """Execute Step 4: Response analysis for each endpoint."""
        logger.info("Step 4: Response analysis", endpoint_count=len(endpoints))
        analysed: List[EndpointModel] = []
        for ep in endpoints:
            try:
                enriched = self._response_analyzer.analyse(ep)
                analysed.append(enriched)
            except Exception as exc:
                logger.warning(
                    "Response analysis failed for endpoint",
                    path=ep.endpoint,
                    error=str(exc),
                )
                analysed.append(ep)
        return analysed

    def _step_method_enumeration(self, endpoints: List[EndpointModel]) -> List[EndpointModel]:
        """Execute Step 5: HTTP method enumeration."""
        logger.info("Step 5: Method enumeration", endpoint_count=len(endpoints))
        expanded: List[EndpointModel] = []
        for ep in endpoints:
            try:
                method_variants = self._method_enumerator.enumerate(ep)
                expanded.extend(method_variants)
            except Exception as exc:
                logger.warning(
                    "Method enumeration failed for endpoint",
                    path=ep.endpoint,
                    error=str(exc),
                )
                expanded.append(ep)
        logger.info(
            "Method enumeration complete",
            before=len(endpoints),
            after=len(expanded),
        )
        return expanded

    def _step_metadata_extraction(self, endpoints: List[EndpointModel]) -> List[EndpointModel]:
        """Enrich each endpoint with full metadata."""
        logger.info("Metadata extraction", endpoint_count=len(endpoints))
        enriched: List[EndpointModel] = []
        for ep in endpoints:
            try:
                enriched.append(self._metadata_extractor.extract(ep))
            except Exception as exc:
                logger.warning(
                    "Metadata extraction failed",
                    path=ep.endpoint,
                    error=str(exc),
                )
                enriched.append(ep)
        return enriched

    def _step_auth_detection(self, endpoints: List[EndpointModel]) -> List[EndpointModel]:
        """Run authentication detection for each endpoint."""
        logger.info("Auth detection", endpoint_count=len(endpoints))
        result: List[EndpointModel] = []
        for ep in endpoints:
            try:
                result.append(self._auth_detector.detect(ep))
            except Exception as exc:
                logger.warning(
                    "Auth detection failed",
                    path=ep.endpoint,
                    error=str(exc),
                )
                result.append(ep)
        return result

    def _step_classification(self, endpoints: List[EndpointModel]) -> List[EndpointModel]:
        """Classify category and risk for each endpoint."""
        logger.info("Classification", endpoint_count=len(endpoints))
        classified: List[EndpointModel] = []
        for ep in endpoints:
            try:
                classified.append(self._classifier.classify(ep))
            except Exception as exc:
                logger.warning(
                    "Classification failed",
                    path=ep.endpoint,
                    error=str(exc),
                )
                classified.append(ep)
        return classified

    # ── Deduplication helpers ────────────────────────────────────────────────

    @staticmethod
    def _deduplicate_by_path(endpoints: List[EndpointModel]) -> List[EndpointModel]:
        """
        Deduplicate by path only, preferring Swagger-sourced entries.

        Used *before* method enumeration to avoid probing duplicated paths.
        """
        seen: Dict[str, EndpointModel] = {}
        for ep in endpoints:
            path = ep.endpoint
            if path not in seen:
                seen[path] = ep
            else:
                # Swagger takes priority over guesses/crawl
                from models.endpoint import DiscoveryMethod
                if ep.discovered_by == DiscoveryMethod.SWAGGER:
                    seen[path] = ep
        return list(seen.values())

    @staticmethod
    def _deduplicate_by_method_path(endpoints: List[EndpointModel]) -> List[EndpointModel]:
        """
        Final deduplication by (method, path) composite key.

        Swagger-sourced entries take priority over guesses.
        """
        from models.endpoint import DiscoveryMethod

        seen: Dict[str, EndpointModel] = {}
        priority_order = [
            DiscoveryMethod.SWAGGER,
            DiscoveryMethod.CRAWLER,
            DiscoveryMethod.METHOD_ENUM,
            DiscoveryMethod.GUESSER,
            DiscoveryMethod.MANUAL,
        ]

        for ep in endpoints:
            key = ep.unique_key
            if key not in seen:
                seen[key] = ep
            else:
                # Replace if current entry has higher priority
                existing = seen[key]
                try:
                    ep_priority = priority_order.index(ep.discovered_by)
                    existing_priority = priority_order.index(existing.discovered_by)
                    if ep_priority < existing_priority:
                        seen[key] = ep
                except ValueError:
                    pass

        return sorted(seen.values(), key=lambda e: (e.endpoint, e.method.value))
