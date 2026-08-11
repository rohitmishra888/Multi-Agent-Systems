"""
main.py
=======
Entry point for the Multi-Agent API Security Testing Platform.

Supports three operational modes:
    Phase 0 (default): Discovery → Security Testing (both phases)
    Phase 1:           API Discovery only (produces catalog.json)
    Phase 2:           Security Testing only (loads existing catalog.json)

Usage
-----
    python main.py                       # Run both phases (no LLM)
    python main.py --no-llm              # Force direct pipeline mode
    python main.py --phase 1             # Discovery only
    python main.py --phase 2             # Security testing only
    python main.py --target http://...   # Override BASE_URL
    python main.py --output ./reports    # Override output directory
    python main.py --log-level DEBUG     # Verbose logging

The script:
1. Loads configuration from .env
2. Validates connectivity to the target
3. Runs Phase 1 (discovery) → produces catalog.json + catalog.yaml
4. Runs Phase 2 (security) → produces security_report.json + security_report.html
5. Prints a comprehensive summary of all findings
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="api-security-platform",
        description=(
            "Multi-Agent AI Security Testing Platform\n"
            "Phase 1: API Discovery Specialist\n"
            "Phase 2: Security Testing Specialist (OWASP API Top 10)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target application URL (overrides BASE_URL in .env).",
        metavar="URL",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for all report files (overrides OUTPUT_DIRECTORY in .env).",
        metavar="DIR",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM orchestration; run both pipelines directly (no API key required).",
    )
    parser.add_argument(
        "--phase",
        type=int,
        choices=[0, 1, 2],
        default=0,
        help=(
            "Which phase to run: "
            "0=both (default), "
            "1=discovery only, "
            "2=security testing only (requires existing catalog.json)."
        ),
    )
    parser.add_argument(
        "--skip-method-enum",
        action="store_true",
        help="Skip HTTP method enumeration in Phase 1 (faster but less thorough).",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override the log level.",
    )
    return parser.parse_args()


def check_connectivity(base_url: str) -> bool:
    """
    Verify that the target application is reachable before starting the scan.

    Parameters
    ----------
    base_url:
        Target URL.

    Returns
    -------
    bool
        True if the target is reachable.
    """
    from utils.http_client import HTTPClient

    logger.info("Checking target connectivity", url=base_url)
    try:
        with HTTPClient(base_url=base_url) as client:
            resp = client.get("/")
            logger.info("Target reachable", url=base_url, status=resp.status_code)
            return True
    except Exception as exc:
        logger.error("Target unreachable", url=base_url, error=str(exc))
        return False


def print_banner() -> None:
    """Print the startup banner."""
    banner = r"""
  ___  ___ ___   ___  _                                     
 / _ \/ _ \_ _  |   \(_)___  __ ___ ___ _____ ___ _ _  _  
| (_) |  _/| |  | |) | (_-< / _/ _ \ V / -_) '_| || | || |
 \___/|_| |___| |___/|_/__/ \__\___/\_/\___|_|  \_, |\_, |
                                                 |__/ |__/  

Multi-Agent AI Security Testing Platform
Phase 1: API Discovery Specialist
Phase 2: Security Testing Specialist (OWASP API Top 10)
==========================================
"""
    print(banner)


def main() -> int:
    """
    Main entry point.

    Returns
    -------
    int
        Exit code (0 = success, 1 = failure).
    """
    print_banner()
    args = parse_args()

    # Apply CLI overrides
    target_url = args.target or settings.base_url
    output_dir = Path(args.output) if args.output else settings.output_dir
    use_llm = not args.no_llm
    phase = args.phase

    # Override log level if requested
    if args.log_level:
        import logging
        logging.getLogger().setLevel(getattr(logging, args.log_level))

    logger.info(
        "Application startup",
        target=target_url,
        output_dir=str(output_dir),
        use_llm=use_llm,
        phase=phase,
        log_level=settings.LOG_LEVEL,
    )

    # ── Print run configuration ───────────────────────────────────────────────
    phase_labels = {0: "Both phases (Discovery + Security Testing)", 1: "Phase 1 only (Discovery)", 2: "Phase 2 only (Security Testing)"}
    print(f"\n[*] Target : {target_url}")
    print(f"[*] Output : {output_dir}")
    print(f"[*] Mode   : {'LLM-orchestrated' if use_llm else 'Direct pipeline'}")
    print(f"[*] Phase  : {phase_labels.get(phase, str(phase))}")
    print()

    # ── Connectivity check ────────────────────────────────────────────────────
    # For phase 2 only, we still need target to be up for security tests
    if not check_connectivity(target_url):
        print(
            f"\n[!] ERROR: Cannot reach target at {target_url}\n"
            "    Ensure VAmPI is running:\n"
            "    docker run -p 5000:5000 erev0s/vampi\n",
            file=sys.stderr,
        )
        return 1

    print("[+] Target is reachable. Starting...\n")

    # ── Run platform ──────────────────────────────────────────────────────────
    start_time = time.time()

    try:
        from agents.crew import SecurityPlatformCrew

        crew = SecurityPlatformCrew(
            base_url=target_url,
            output_dir=output_dir,
            use_llm=use_llm,
            skip_method_enum=args.skip_method_enum,
        )
        results = crew.run(phase=phase)

    except KeyboardInterrupt:
        logger.warning("Run interrupted by user")
        print("\n[!] Run interrupted.")
        return 1

    except Exception as exc:
        logger.exception("Run failed with unexpected error", error=str(exc))
        print(f"\n[!] Run failed: {exc}", file=sys.stderr)
        return 1

    # ── Completion summary ────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print(f"\n[+] Completed in {elapsed:.1f}s")
    print()

    if "catalog_json" in results:
        print(f"[+] Phase 1 — Discovery Catalog:")
        print(f"    JSON : {results['catalog_json']}")
        print(f"    YAML : {results.get('catalog_yaml', 'N/A')}")

    if "security_report_json" in results:
        print()
        print(f"[+] Phase 2 — Security Assessment Report:")
        print(f"    JSON : {results['security_report_json']}")
        print(f"    HTML : {results['security_report_html']}")
        print()
        print(f"    Open the HTML report in your browser for the full assessment.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
