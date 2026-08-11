"""
agents/crew.py
==============
CrewAI Crew configuration for the complete API Security Testing Platform.

This module assembles and runs both Phase 1 (Discovery) and Phase 2 (Security
Testing) crews in a sequential pipeline:

    Phase 1: API Discovery Specialist
        → Discovers all endpoints → produces catalog.json

    Phase 2: Security Testing Specialist
        → Loads catalog → runs OWASP tests → produces security_report.json + HTML

Both phases support two execution modes:
- **Direct mode** (``--no-llm``): pipeline runs deterministically without an LLM.
- **LLM mode**: CrewAI orchestrates agents using any LLM via LiteLLM.

Supported LLM providers (configure in .env):
- Google Gemini:  set GEMINI_API_KEY  (model: gemini/gemini-2.5-flash)
- OpenAI:         set OPENAI_API_KEY  (model: gpt-4o-mini)

Usage
-----
From ``main.py``:

    crew = SecurityPlatformCrew(base_url=..., output_dir=..., use_llm=True)
    crew.run(phase=1)         # Phase 1 only
    crew.run(phase=2)         # Phase 2 only (requires catalog.json)
    crew.run(phase=0)         # Both phases (default)
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from crewai import Crew, LLM, Process

from agents.discovery_agent import (
    _discovered,
    create_discovery_agent,
    create_discovery_task,
)
from config.settings import settings
from models.catalog import APICatalog
from models.endpoint import EndpointModel
from models.vulnerability import SecurityReport
from reports.report_generator import ReportGenerator
from services.catalog_service import CatalogService
from services.discovery_service import DiscoveryService
from services.security_service import SecurityService
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)


class SecurityPlatformCrew:
    """
    Assembles and runs the complete two-phase API security testing platform.

    Parameters
    ----------
    base_url:
        Target application URL. Defaults to ``settings.base_url``.
    output_dir:
        Directory for all output files. Defaults to ``settings.output_dir``.
    use_llm:
        If True, use CrewAI LLM orchestration.
        Requires GEMINI_API_KEY or OPENAI_API_KEY to be set in .env.
        If False, run both pipelines directly (no LLM required).
    skip_method_enum:
        If True, skip HTTP method enumeration in Phase 1 (faster).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        output_dir: Optional[Path] = None,
        use_llm: bool = True,
        skip_method_enum: bool = False,
    ) -> None:
        self._base_url = (base_url or settings.base_url).rstrip("/")
        self._output_dir = output_dir or settings.output_dir
        self._use_llm = use_llm
        self._skip_method_enum = skip_method_enum
        self._scan_started_at: datetime = datetime.now(timezone.utc)
        self._llm: Optional[LLM] = self._build_llm() if use_llm else None

    # ── LLM factory ─────────────────────────────────────────────────────────

    @staticmethod
    def _build_llm() -> Optional[LLM]:
        """
        Build a CrewAI LLM instance from .env settings.

        Priority
        --------
        1. Gemini via langchain-google-genai (GEMINI_API_KEY set)
        2. OpenAI                            (OPENAI_API_KEY set)
        3. None                              → falls back to direct pipeline
        """
        # ── Gemini AI Studio ──────────────────────────────────────────────
        if settings.GEMINI_API_KEY:
            os.environ["GOOGLE_API_KEY"] = settings.GEMINI_API_KEY
            os.environ["GEMINI_API_KEY"] = settings.GEMINI_API_KEY

            raw_model = settings.LLM_MODEL
            bare_model = raw_model.replace("gemini/", "")
            litellm_model = f"gemini/{bare_model}"

            logger.info(
                "LLM configured",
                provider="Gemini AI Studio",
                model=litellm_model,
            )
            # Pass the model string — CrewAI LLM routes via LiteLLM
            # GOOGLE_API_KEY env var is what LiteLLM uses for gemini/ provider
            return LLM(
                model=litellm_model,
                api_key=settings.GEMINI_API_KEY,
                temperature=0.1,
                max_tokens=8192,
                extra_headers={},
            )

        # ── OpenAI ────────────────────────────────────────────────────────
        if settings.OPENAI_API_KEY:
            os.environ["OPENAI_API_KEY"] = settings.OPENAI_API_KEY
            model = settings.OPENAI_MODEL_NAME
            logger.info("LLM configured", provider="OpenAI", model=model)
            return LLM(
                model=model,
                api_key=settings.OPENAI_API_KEY,
                temperature=0.1,
            )

        logger.warning(
            "No LLM API key found (GEMINI_API_KEY or OPENAI_API_KEY). "
            "Falling back to direct pipeline mode. "
            "Set one of these in your .env file to enable LLM-orchestrated mode."
        )
        return None


    @property
    def _llm_available(self) -> bool:
        """True if an LLM is configured and ready."""
        return self._llm is not None

    # ── Public interface ────────────────────────────────────────────────────

    def run(self, phase: int = 0) -> dict:
        """
        Execute the requested phase(s).

        Parameters
        ----------
        phase:
            0 = Both phases (default)
            1 = Phase 1 only (discovery)
            2 = Phase 2 only (security testing, loads existing catalog)

        Returns
        -------
        dict
            Dictionary with output paths for both phases.
        """
        mode = "LLM-orchestrated" if (self._use_llm and self._llm_available) else "Direct pipeline"
        logger.info(
            "Security Platform starting",
            target=self._base_url,
            mode=mode,
            llm_model=self._llm.model if self._llm else "N/A",
        )

        results: dict = {}
        self._scan_started_at = datetime.now(timezone.utc)

        if phase in (0, 1):
            catalog_path = self._run_phase1()
            results["catalog_json"] = str(catalog_path)
            results["catalog_yaml"] = str(catalog_path).replace(".json", ".yaml")

        if phase in (0, 2):
            catalog_json = Path(results.get("catalog_json", str(self._output_dir / "catalog.json")))
            json_path, html_path = self._run_phase2(catalog_json)
            results["security_report_json"] = str(json_path)
            results["security_report_html"] = str(html_path)

        logger.info("Run complete", **{k: v for k, v in results.items()})
        return results

    # ── Phase 1 ─────────────────────────────────────────────────────────────

    def _run_phase1(self) -> Path:
        """Execute Phase 1: API Discovery. Returns path to catalog.json."""
        logger.info(
            "Phase 1 — API Discovery starting",
            target=self._base_url,
            llm=self._llm.model if self._llm else "none",
        )

        service = DiscoveryService(base_url=self._base_url)

        if self._use_llm and self._llm_available:
            endpoints = self._run_discovery_with_llm(service)
        else:
            if self._use_llm and not self._llm_available:
                logger.warning(
                    "No LLM configured — falling back to direct pipeline. "
                    "Set GEMINI_API_KEY or OPENAI_API_KEY in .env."
                )
            endpoints = self._run_discovery_directly(service)

        catalog_svc = CatalogService(
            output_dir=self._output_dir,
            target_url=self._base_url,
        )
        catalog = catalog_svc.build_and_save(
            endpoints=endpoints,
            scan_started_at=self._scan_started_at,
            openapi_found=service.openapi_found,
            openapi_url=service.openapi_url,
            notes=service.notes,
        )

        for line in catalog.summary_lines():
            print(line)

        logger.info(
            "Phase 1 complete",
            json_catalog=str(catalog_svc.json_path),
            yaml_catalog=str(catalog_svc.yaml_path),
        )

        return catalog_svc.json_path

    def _run_discovery_with_llm(self, service: DiscoveryService):
        """Run Phase 1 with LLM orchestration via CrewAI."""
        logger.info(
            "Running in LLM-orchestrated mode",
            model=self._llm.model if self._llm else "none",
        )

        agent = create_discovery_agent(service)
        # Inject the configured LLM into the agent
        if self._llm:
            agent.llm = self._llm

        task = create_discovery_task(agent, self._base_url)

        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )

        try:
            crew.kickoff()
        except Exception as exc:
            logger.error(
                "CrewAI LLM run failed, falling back to direct pipeline",
                error=str(exc),
            )
            return self._run_discovery_directly(service)

        llm_endpoints = list(_discovered)
        if len(llm_endpoints) < 3:
            logger.warning(
                "LLM gathered few endpoints, supplementing with direct pipeline",
                llm_count=len(llm_endpoints),
            )
            direct_endpoints = service.run()
            llm_keys = {e.unique_key for e in llm_endpoints}
            for ep in direct_endpoints:
                if ep.unique_key not in llm_keys:
                    llm_endpoints.append(ep)

        return llm_endpoints

    def _run_discovery_directly(self, service: DiscoveryService):
        """Run Phase 1 without LLM orchestration."""
        logger.info("Running in direct pipeline mode (no LLM)")
        return service.run()

    # ── Phase 2 ─────────────────────────────────────────────────────────────

    def _run_phase2(self, catalog_json_path: Path) -> tuple[Path, Path]:
        """
        Execute Phase 2: Security Testing.

        Returns paths to security_report.json and security_report.html.
        """
        print()
        print("=" * 50)
        print("Phase 2 — Security Testing Specialist")
        print("=" * 50)

        logger.info(
            "Phase 2 — Security Testing starting",
            catalog=str(catalog_json_path),
            target=self._base_url,
            llm=self._llm.model if self._llm else "none",
        )

        # Load Phase 1 catalog
        catalog = CatalogService.load_json(catalog_json_path)
        logger.info("Phase 1 catalog loaded", endpoints=catalog.statistics.total_endpoints)

        http_client = HTTPClient(base_url=self._base_url)

        if self._use_llm and self._llm_available:
            report = self._run_security_with_llm(catalog, http_client, catalog_json_path)
        else:
            report = self._run_security_directly(catalog, http_client)

        # Generate reports
        generator = ReportGenerator(report=report, output_dir=str(self._output_dir))
        json_path, html_path = generator.generate_all()

        print()
        for line in report.summary_lines():
            print(line)

        logger.info(
            "Phase 2 complete",
            json_report=str(json_path),
            html_report=str(html_path),
        )

        return json_path, html_path

    def _run_security_directly(
        self,
        catalog: APICatalog,
        http_client: HTTPClient,
    ) -> SecurityReport:
        """Run Phase 2 without LLM orchestration."""
        logger.info("Phase 2: Running in direct pipeline mode (no LLM)")
        service = SecurityService(catalog, http_client, self._base_url)
        return service.run()

    def _run_security_with_llm(
        self,
        catalog: APICatalog,
        http_client: HTTPClient,
        catalog_path: Path,
    ) -> SecurityReport:
        """Run Phase 2 with LLM orchestration via CrewAI."""
        logger.info(
            "Phase 2: Running in LLM-orchestrated mode",
            model=self._llm.model if self._llm else "none",
        )

        from agents.security_agent import (
            create_security_agent,
            create_security_task,
            init_security_tools,
        )

        init_security_tools(catalog, http_client, self._base_url)

        agent = create_security_agent()
        # Inject the configured LLM
        if self._llm:
            agent.llm = self._llm

        task = create_security_task(agent, str(catalog_path), self._base_url)

        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )

        try:
            crew.kickoff()
        except Exception as exc:
            logger.error(
                "Phase 2 LLM run failed, falling back to direct pipeline",
                error=str(exc),
            )
            return self._run_security_directly(catalog, http_client)

        # After LLM orchestration, run the deterministic pipeline too for
        # complete HTTP evidence collection (LLM output supplements it)
        service = SecurityService(catalog, http_client, self._base_url)
        return service.run()


# ---------------------------------------------------------------------------
# Backward compatibility alias
# ---------------------------------------------------------------------------

class DiscoveryCrew(SecurityPlatformCrew):
    """
    Backward-compatible alias for ``SecurityPlatformCrew``.
    Retained so Phase 1 tests that import ``DiscoveryCrew`` still work.
    """

    def run(self, phase: int = 1) -> Path:  # type: ignore[override]
        """Run Phase 1 only and return the catalog.json path."""
        result = super().run(phase=1)
        return Path(result["catalog_json"])
