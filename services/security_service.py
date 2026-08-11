"""
services/security_service.py
=============================
Security Testing Pipeline Orchestrator — Phase 2

The ``SecurityService`` loads the Phase 1 ``APICatalog``, runs all six OWASP
security test modules in sequence, collects findings, and builds the final
``SecurityReport``.

Pipeline
--------
1. Load catalog from Phase 1 (APICatalog)
2. Initialise DB (ensure VAmPI has seed data via /createdb)
3. Run AuthTester            (API2 — Broken Authentication / JWT)
4. Run BOLATester            (API1 — Broken Object Level Authorization)
5. Run InjectionTester       (API8 — SQL Injection)
6. Run DataExposureTester    (API3 — Excessive Data Exposure)
7. Run MassAssignmentTester  (API6 — Mass Assignment)
8. Run RateLimitTester       (API4 — Rate Limiting)
9. Aggregate findings → SecurityReport
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from models.catalog import APICatalog
from models.vulnerability import SecurityReport, VulnerabilityFinding
from tools.auth_tester import AuthTester
from tools.bola_tester import BOLATester
from tools.data_exposure_tester import DataExposureTester
from tools.injection_tester import InjectionTester
from tools.mass_assignment_tester import MassAssignmentTester
from tools.rate_limit_tester import RateLimitTester
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)


class SecurityService:
    """
    Orchestrates the Phase 2 security testing pipeline.

    Parameters
    ----------
    catalog:
        The ``APICatalog`` produced by Phase 1 discovery.
    http_client:
        Shared ``HTTPClient`` for all test modules.
    base_url:
        Base URL of the target application.
    """

    def __init__(
        self,
        catalog: APICatalog,
        http_client: HTTPClient,
        base_url: str,
    ) -> None:
        self._catalog = catalog
        self._client = http_client
        self._base_url = base_url.rstrip("/")
        self._report: Optional[SecurityReport] = None

    # ── Public interface ────────────────────────────────────────────────────

    def run(self) -> SecurityReport:
        """
        Execute the complete security testing pipeline.

        Returns
        -------
        SecurityReport
            Complete security assessment report.
        """
        report_id = f"VAMPI-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        self._report = SecurityReport(
            report_id=report_id,
            target_url=self._base_url,
            catalog_source=str(self._catalog.metadata.target_url or "reports/catalog.json"),
        )

        logger.info(
            "Security testing pipeline started",
            report_id=report_id,
            target=self._base_url,
            endpoints_in_catalog=self._catalog.statistics.total_endpoints,
        )

        # Seed VAmPI database
        self._seed_database()

        # Run all test modules
        all_findings: List[VulnerabilityFinding] = []

        modules = [
            ("API2 — Authentication & JWT", AuthTester),
            ("API1 — Broken Object Level Auth (BOLA)", BOLATester),
            ("API8 — SQL Injection", InjectionTester),
            ("API3 — Excessive Data Exposure", DataExposureTester),
            ("API6 — Mass Assignment", MassAssignmentTester),
            ("API4 — Rate Limiting", RateLimitTester),
        ]

        for step, (module_name, TesterClass) in enumerate(modules, start=1):
            logger.info(
                "Security test module starting",
                step=f"{step}/{len(modules)}",
                module=module_name,
            )
            try:
                tester = TesterClass(self._client, self._base_url)
                findings = tester.run()
                all_findings.extend(findings)
                logger.info(
                    "Security test module complete",
                    module=module_name,
                    findings=len(findings),
                )
            except Exception as exc:
                logger.error(
                    "Security test module failed",
                    module=module_name,
                    error=str(exc),
                )

        # Add all findings to report
        for finding in all_findings:
            self._report.add_finding(finding)

        # Update endpoint test count from catalog
        self._report.statistics.total_endpoints_tested = self._catalog.statistics.total_endpoints
        self._report.statistics.total_tests_run = len(modules)

        # Finalise report (compute stats, generate summary)
        self._report.finalise()

        logger.info(
            "Security testing pipeline complete",
            total_findings=len(all_findings),
            confirmed=self._report.statistics.confirmed_vulnerabilities,
            risk_posture=self._report.statistics.risk_posture,
        )

        return self._report

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _seed_database(self) -> None:
        """
        Ensure VAmPI's database is initialised by hitting /createdb.
        VAmPI requires this before any user/book operations can succeed.
        """
        try:
            resp = self._client.get("/createdb")
            logger.info(
                "SecurityService: VAmPI database seeded",
                status=resp.status_code,
            )
        except Exception as exc:
            logger.warning(
                "SecurityService: database seed failed",
                error=str(exc),
            )
