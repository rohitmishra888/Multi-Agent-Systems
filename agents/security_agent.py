"""
agents/security_agent.py
=========================
Phase 2 — Security Testing Specialist Agent

CrewAI agent definition for the Security Testing Specialist.

The agent uses the Phase 1 catalog as its starting point and exposes six
@tool functions — one per OWASP test module — that the LLM can call during
its reasoning loop. In ``--no-llm`` mode, the tools are called directly by
the ``SecurityService`` pipeline.

Agent persona
-------------
Role: API Security Tester
Goal: Test all discovered API endpoints for OWASP API Top 10 vulnerabilities
      and produce a comprehensive, evidence-backed security assessment report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from crewai import Agent, Task
from crewai.tools import tool

from models.catalog import APICatalog
from models.vulnerability import SecurityReport
from services.security_service import SecurityService
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level shared state (used by @tool functions)
# ---------------------------------------------------------------------------

_service: Optional[SecurityService] = None
_report: Optional[SecurityReport] = None
_catalog: Optional[APICatalog] = None
_client: Optional[HTTPClient] = None
_base_url: str = "http://localhost:5000"


def init_security_tools(
    catalog: APICatalog,
    client: HTTPClient,
    base_url: str,
) -> None:
    """
    Initialise the shared state that @tool functions use.

    Must be called before the agent is created or the crew is kicked off.
    """
    global _service, _catalog, _client, _base_url
    _catalog = catalog
    _client = client
    _base_url = base_url
    _service = SecurityService(catalog, client, base_url)
    logger.info("SecurityAgent tools initialised", base_url=base_url)


# ---------------------------------------------------------------------------
# CrewAI @tool definitions
# ---------------------------------------------------------------------------

@tool("test_authentication_security")
def test_authentication_security(endpoint: str = "/users/v1/login") -> str:
    """
    Test API authentication security for OWASP API2 vulnerabilities.

    Executes:
    - JWT algorithm 'none' bypass
    - Malformed token acceptance
    - Missing authentication token handling
    - SQL injection in login credentials
    - JWT payload sensitive data inspection
    - User enumeration via error messages

    Args:
        endpoint: The login endpoint to test (default: /users/v1/login)

    Returns:
        JSON string with authentication test results and any findings.
    """
    global _client, _base_url
    if not _client:
        return json.dumps({"error": "Security tools not initialised"})

    try:
        from tools.auth_tester import AuthTester
        tester = AuthTester(_client, _base_url)
        findings = tester.run()
        return json.dumps({
            "module": "Authentication Testing (OWASP API2)",
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.vuln_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss": f.cvss_score,
                    "confirmed": f.confirmed,
                    "endpoint": f.endpoint,
                }
                for f in findings
            ],
        }, indent=2)
    except Exception as exc:
        logger.error("test_authentication_security failed", error=str(exc))
        return json.dumps({"error": str(exc)})


@tool("test_object_level_authorization")
def test_object_level_authorization(user_endpoint: str = "/users/v1/{username}") -> str:
    """
    Test for Broken Object Level Authorization (BOLA/IDOR) — OWASP API1.

    Executes:
    - Cross-user profile read using another user's JWT
    - Cross-user account deletion
    - Cross-user email update (IDOR)
    - Cross-user password change
    - Unauthenticated access to user listings

    Args:
        user_endpoint: The user profile endpoint pattern to test.

    Returns:
        JSON string with BOLA test results and any findings.
    """
    global _client, _base_url
    if not _client:
        return json.dumps({"error": "Security tools not initialised"})

    try:
        from tools.bola_tester import BOLATester
        tester = BOLATester(_client, _base_url)
        findings = tester.run()
        return json.dumps({
            "module": "Broken Object Level Authorization (OWASP API1)",
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.vuln_id, "title": f.title,
                    "severity": f.severity.value, "cvss": f.cvss_score,
                    "confirmed": f.confirmed, "endpoint": f.endpoint,
                }
                for f in findings
            ],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool("test_sql_injection")
def test_sql_injection(target_endpoints: str = "all") -> str:
    """
    Test API endpoints for SQL injection vulnerabilities — OWASP API8.

    Executes injection tests against:
    - PUT /users/v1/{username}/email (primary VAmPI SQL injection point)
    - POST /users/v1/login (username/password parameters)
    - GET /users/v1/{username} (path parameter injection)
    - POST /users/v1/register (registration parameters)

    Args:
        target_endpoints: Comma-separated endpoints to test, or 'all' for all.

    Returns:
        JSON string with injection test results.
    """
    global _client, _base_url
    if not _client:
        return json.dumps({"error": "Security tools not initialised"})

    try:
        from tools.injection_tester import InjectionTester
        tester = InjectionTester(_client, _base_url)
        findings = tester.run()
        return json.dumps({
            "module": "SQL Injection (OWASP API8)",
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.vuln_id, "title": f.title,
                    "severity": f.severity.value, "cvss": f.cvss_score,
                    "confirmed": f.confirmed, "endpoint": f.endpoint,
                    "poc_preview": f.proof_of_concept[:200] if f.proof_of_concept else "",
                }
                for f in findings
            ],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool("test_data_exposure")
def test_data_exposure(check_endpoints: str = "all") -> str:
    """
    Test API endpoints for excessive data exposure — OWASP API3.

    Checks:
    - GET /users/v1 for password/admin field exposure
    - GET /users/v1/{username} for sensitive fields in profile
    - GET /users/v1/_debug for debug data exposure
    - Response headers for missing security headers
    - Error messages for information disclosure

    Args:
        check_endpoints: Comma-separated endpoints or 'all'.

    Returns:
        JSON string with data exposure findings.
    """
    global _client, _base_url
    if not _client:
        return json.dumps({"error": "Security tools not initialised"})

    try:
        from tools.data_exposure_tester import DataExposureTester
        tester = DataExposureTester(_client, _base_url)
        findings = tester.run()
        return json.dumps({
            "module": "Excessive Data Exposure (OWASP API3)",
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.vuln_id, "title": f.title,
                    "severity": f.severity.value, "cvss": f.cvss_score,
                    "confirmed": f.confirmed, "endpoint": f.endpoint,
                }
                for f in findings
            ],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool("test_mass_assignment")
def test_mass_assignment(registration_endpoint: str = "/users/v1/register") -> str:
    """
    Test for mass assignment vulnerabilities — OWASP API6.

    Tests POST /users/v1/register with:
    - admin: true
    - isAdmin: true
    - role: 'admin'
    - Various privilege escalation payloads

    Then verifies if admin flag is present in profile after registration.

    Args:
        registration_endpoint: The user registration endpoint to test.

    Returns:
        JSON string with mass assignment test results.
    """
    global _client, _base_url
    if not _client:
        return json.dumps({"error": "Security tools not initialised"})

    try:
        from tools.mass_assignment_tester import MassAssignmentTester
        tester = MassAssignmentTester(_client, _base_url)
        findings = tester.run()
        return json.dumps({
            "module": "Mass Assignment (OWASP API6)",
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.vuln_id, "title": f.title,
                    "severity": f.severity.value, "cvss": f.cvss_score,
                    "confirmed": f.confirmed, "endpoint": f.endpoint,
                }
                for f in findings
            ],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool("test_rate_limiting")
def test_rate_limiting(requests_count: int = 20) -> str:
    """
    Test API endpoints for missing rate limiting — OWASP API4.

    Sends rapid sequential requests to:
    - POST /users/v1/login (brute-force/credential stuffing)
    - POST /users/v1/register (account creation spam)
    - GET /users/v1 (bulk data scraping)

    Checks for HTTP 429 responses and rate-limit headers.

    Args:
        requests_count: Number of rapid requests to send (default: 20).

    Returns:
        JSON string with rate limiting test results.
    """
    global _client, _base_url
    if not _client:
        return json.dumps({"error": "Security tools not initialised"})

    try:
        from tools.rate_limit_tester import RateLimitTester
        tester = RateLimitTester(_client, _base_url)
        findings = tester.run()
        return json.dumps({
            "module": "Rate Limiting (OWASP API4)",
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.vuln_id, "title": f.title,
                    "severity": f.severity.value, "cvss": f.cvss_score,
                    "confirmed": f.confirmed, "endpoint": f.endpoint,
                }
                for f in findings
            ],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool("get_security_summary")
def get_security_summary() -> str:
    """
    Retrieve the current security testing summary from all tests run so far.

    Returns the aggregate findings count, severity breakdown, and risk posture.
    Use this after running all test modules to get an overview before generating
    the final report.

    Returns:
        JSON string with summary statistics.
    """
    global _report
    if not _report:
        return json.dumps({"status": "No security tests run yet"})

    s = _report.statistics
    return json.dumps({
        "risk_posture": s.risk_posture,
        "total_findings": s.total_findings,
        "confirmed_vulnerabilities": s.confirmed_vulnerabilities,
        "highest_cvss": s.highest_cvss,
        "by_severity": s.by_severity,
        "by_owasp_category": s.by_owasp_category,
    }, indent=2)


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------

def create_security_agent() -> Agent:
    """
    Create and return the configured Security Testing Specialist agent.

    Returns
    -------
    Agent
        A fully configured CrewAI agent ready for task assignment.
    """
    agent = Agent(
        role="API Security Tester",
        goal=(
            "Test all discovered API endpoints for OWASP API Top 10 vulnerabilities "
            "and produce a comprehensive security assessment with CVSS v3.1 scores, "
            "proof-of-concept evidence, and prioritised remediation recommendations. "
            "Be methodical: test authentication first, then authorisation, injection, "
            "data exposure, mass assignment, and rate limiting."
        ),
        backstory=(
            "You are a Senior API Security Engineer and penetration tester with 12 years "
            "of experience in OWASP API security testing, red teaming, and vulnerability "
            "research. You have discovered critical vulnerabilities in Fortune 500 companies "
            "and authored security advisories for BOLA, mass assignment, and JWT bypass "
            "vulnerabilities. You approach each test systematically, gather concrete HTTP "
            "evidence for every finding, calculate accurate CVSS v3.1 scores, and always "
            "provide clear, actionable remediation guidance. You follow ethical testing "
            "practices and only test authorised targets in controlled environments."
        ),
        tools=[
            test_authentication_security,
            test_object_level_authorization,
            test_sql_injection,
            test_data_exposure,
            test_mass_assignment,
            test_rate_limiting,
            get_security_summary,
        ],
        verbose=True,
        allow_delegation=False,
        max_iter=15,
        respect_context_window=True,
        use_system_prompt=False,   # Gemini: merge system prompt into first user message
    )


    logger.info("Security Testing Specialist agent created")
    return agent


def create_security_task(agent: Agent, catalog_path: str, base_url: str) -> Task:
    """
    Create the security testing task for the Security Testing Specialist.

    Parameters
    ----------
    agent:
        The Security Testing Specialist agent.
    catalog_path:
        Path to the Phase 1 catalog JSON file.
    base_url:
        Target application base URL.

    Returns
    -------
    Task
        Configured CrewAI Task for security testing.
    """
    return Task(
        description=(
            f"Perform a comprehensive OWASP API Top 10 security assessment of the API at {base_url}. "
            f"The Phase 1 API Discovery catalog is available at: {catalog_path}. "
            "\n\nExecute ALL of the following security tests in this order:\n"
            "1. test_authentication_security() — Test JWT security, auth bypass, token validation\n"
            "2. test_object_level_authorization() — Test BOLA/IDOR: cross-user data access\n"
            "3. test_sql_injection() — Test SQL injection in email, login, registration endpoints\n"
            "4. test_data_exposure() — Check for sensitive fields, debug routes, security headers\n"
            "5. test_mass_assignment() — Test admin privilege escalation via registration\n"
            "6. test_rate_limiting() — Check for missing rate limiting on login/register\n"
            "7. get_security_summary() — Retrieve final findings summary\n\n"
            "For each vulnerability found, document: the OWASP category, CVSS score, "
            "proof-of-concept steps, and remediation recommendations."
        ),
        expected_output=(
            "A structured security assessment summary including:\n"
            "- Total findings with severity breakdown (CRITICAL/HIGH/MEDIUM/LOW)\n"
            "- Confirmed vulnerabilities with CVSS v3.1 scores\n"
            "- Key findings for each OWASP category tested\n"
            "- Overall risk posture of the target application\n"
            "- Top 3 most critical remediation priorities"
        ),
        agent=agent,
    )
