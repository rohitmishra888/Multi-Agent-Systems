"""
tools/data_exposure_tester.py
=============================
Security Tool 4 — Excessive Data Exposure Testing

Tests for OWASP API3:2019 Excessive Data Exposure.

VAmPI known exposures
---------------------
- ``GET /users/v1`` — returns password hashes / plaintext passwords
- ``GET /users/v1/{username}`` — returns admin flag, email, password
- ``GET /users/v1/_debug`` — debug endpoint exposing all user data

Detection logic
---------------
1. Fetch each user-related endpoint.
2. Scan response JSON fields against a blocklist of sensitive field names.
3. If a sensitive field is present, record as a finding.
4. Check HTTP response headers for security headers (CORS, HSTS, etc.).
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional, Set

from models.vulnerability import (
    CVSSScore,
    HTTPEvidence,
    OWASPCategory,
    TestStatus,
    VulnerabilityFinding,
)
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Sensitive field names (case-insensitive check)
# ---------------------------------------------------------------------------

_SENSITIVE_FIELDS: Set[str] = {
    "password", "passwd", "pwd", "pass",
    "secret", "token", "api_key", "apikey",
    "ssn", "credit_card", "card_number",
    "private_key", "hash", "salt",
    "admin",           # Exposing admin flag
    "is_admin", "isadmin", "role",
    "internal_id", "db_id",
}

_DEBUG_SIGNALS = [
    "traceback", "stack trace", "exception", "debug", "internal server",
    "werkzeug", "flask", "sqlalchemy", "sqlite",
]


class DataExposureTester:
    """
    Tests for excessive data exposure in API responses.

    Parameters
    ----------
    client:
        Configured ``HTTPClient`` for the target application.
    base_url:
        Base URL of the target application.
    """

    def __init__(self, client: HTTPClient, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._findings: List[VulnerabilityFinding] = []
        self._vuln_counter = 0
        self._jwt: Optional[str] = None
        self._username: Optional[str] = None

    # ── Public interface ────────────────────────────────────────────────────

    def run(self) -> List[VulnerabilityFinding]:
        """Execute all data exposure tests and return findings."""
        logger.info("DataExposureTester: starting tests")
        self._setup_auth()
        self._test_user_list_exposure()
        self._test_individual_user_exposure()
        self._test_debug_endpoint_exposure()
        self._test_security_headers()
        self._test_error_message_disclosure()
        logger.info("DataExposureTester: complete", findings=len(self._findings))
        return self._findings

    # ── Setup ───────────────────────────────────────────────────────────────

    def _setup_auth(self) -> None:
        """Create a test user and capture JWT."""
        suffix = uuid.uuid4().hex[:8]
        self._username = f"exp_{suffix}"
        try:
            self._client.post(
                "/users/v1/register",
                json={
                    "username": self._username,
                    "password": "ExpTest@2024!",
                    "email": f"{self._username}@test.invalid",
                },
                headers={"Content-Type": "application/json"},
            )
            resp = self._client.post(
                "/users/v1/login",
                json={"username": self._username, "password": "ExpTest@2024!"},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = json.loads(resp.text)
                self._jwt = (
                    data.get("auth_token") or data.get("token")
                    or data.get("access_token") or data.get("jwt")
                )
        except Exception as exc:
            logger.warning("DataExposureTester: auth setup failed", error=str(exc))

    # ── Test: User list sensitive field exposure ───────────────────────────

    def _test_user_list_exposure(self) -> None:
        """
        Test 1: GET /users/v1 — check if response contains sensitive fields.
        VAmPI is known to return password data in this endpoint.
        """
        resp = self._client.get("/users/v1")
        if resp.status_code != 200:
            return

        body = self._safe_json(resp.text)
        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}/users/v1",
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=body,
        )

        exposed_fields = self._find_sensitive_fields(body)

        if exposed_fields:
            self._add_finding(
                title="Excessive Data Exposure — Sensitive Fields in User List",
                owasp=OWASPCategory.API3_DATA_EXPOSURE,
                endpoint="/users/v1",
                method="GET",
                cvss=CVSSScore.from_score(
                    7.5,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"The GET /users/v1 endpoint returns sensitive fields in the response: "
                    f"{sorted(exposed_fields)}. "
                    f"This endpoint is publicly accessible without authentication and "
                    f"exposes private user data to any caller."
                ),
                impact=(
                    "Password hashes (or plaintext passwords) and admin flags are exposed to "
                    "unauthenticated attackers, enabling credential theft and privilege mapping."
                ),
                poc=f"curl {self._base_url}/users/v1 | jq .",
                evidence=[ev],
                remediation=[
                    f"Remove sensitive fields from API responses: {sorted(exposed_fields)}.",
                    "Apply a response filter/serialiser that whitelists only safe fields.",
                    "Use a DTO (Data Transfer Object) pattern to control what is exposed.",
                    "Require authentication for the user listing endpoint.",
                ],
            )
        else:
            logger.info("DataExposureTester: /users/v1 no sensitive fields found")

    # ── Test: Individual user profile exposure ─────────────────────────────

    def _test_individual_user_exposure(self) -> None:
        """
        Test 2: GET /users/v1/{username} — check for sensitive field exposure.
        """
        if not self._username:
            return

        headers = {}
        if self._jwt:
            headers["Authorization"] = f"Bearer {self._jwt}"

        resp = self._client.get(
            f"/users/v1/{self._username}",
            headers=headers,
        )

        if resp.status_code not in (200, 201):
            return

        body = self._safe_json(resp.text)
        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}/users/v1/{self._username}",
            response_status=resp.status_code,
            response_body=body,
        )

        exposed_fields = self._find_sensitive_fields(body)
        if exposed_fields:
            self._add_finding(
                title="Excessive Data Exposure — Sensitive Fields in User Profile",
                owasp=OWASPCategory.API3_DATA_EXPOSURE,
                endpoint="/users/v1/{username}",
                method="GET",
                cvss=CVSSScore.from_score(
                    6.5,
                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"User profile endpoint exposes sensitive fields: {sorted(exposed_fields)}. "
                    f"The API should only return the minimum data necessary."
                ),
                impact="Password hashes, admin status, and internal IDs exposed to authenticated users.",
                poc=f"curl -H 'Authorization: Bearer <JWT>' {self._base_url}/users/v1/{self._username}",
                evidence=[ev],
                remediation=[
                    "Return only: username, email (masked), and public profile fields.",
                    "Never return password, hash, or admin fields in profile responses.",
                    "Apply response field filtering at the serialiser layer.",
                ],
            )

    # ── Test: Debug endpoint exposure ──────────────────────────────────────

    def _test_debug_endpoint_exposure(self) -> None:
        """
        Test 3: GET /users/v1/_debug — VAmPI exposes this endpoint.
        """
        headers = {}
        if self._jwt:
            headers["Authorization"] = f"Bearer {self._jwt}"

        resp = self._client.get("/users/v1/_debug", headers=headers)
        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}/users/v1/_debug",
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code == 200:
            body_lower = (resp.text or "").lower()
            has_debug_data = any(sig in body_lower for sig in _DEBUG_SIGNALS)
            has_user_data = self._find_sensitive_fields(self._safe_json(resp.text))

            if has_user_data or has_debug_data or len(resp.text) > 100:
                self._add_finding(
                    title="Debug Endpoint Exposes Sensitive Data — /users/v1/_debug",
                    owasp=OWASPCategory.API3_DATA_EXPOSURE,
                    endpoint="/users/v1/_debug",
                    method="GET",
                    cvss=CVSSScore.from_score(
                        7.5,
                        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description=(
                        "The /users/v1/_debug endpoint is accessible and returns data. "
                        "Debug endpoints should never be exposed in any environment. "
                        f"Exposed sensitive fields: {sorted(has_user_data) if has_user_data else 'various user data'}"
                    ),
                    impact="Debug endpoints can expose internal system details, all user records, and credentials.",
                    poc=f"curl -H 'Authorization: Bearer <JWT>' {self._base_url}/users/v1/_debug",
                    evidence=[ev],
                    remediation=[
                        "Remove all debug/internal endpoints before deployment.",
                        "Use feature flags or environment-specific routing to disable debug routes.",
                        "If debug endpoints are needed, restrict to internal network only.",
                        "Implement proper access control: admin-only with IP whitelisting.",
                    ],
                )

    # ── Test: Security headers ─────────────────────────────────────────────

    def _test_security_headers(self) -> None:
        """
        Test 4: Check for missing security headers on API responses.
        """
        resp = self._client.get("/users/v1")
        if resp.status_code not in (200, 401, 403):
            return

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        missing_headers = []

        checks = [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", None),
            ("strict-transport-security", None),
            ("content-security-policy", None),
            ("x-xss-protection", None),
        ]

        for header_name, expected_value in checks:
            if header_name not in headers_lower:
                missing_headers.append(header_name)
            elif expected_value and expected_value not in headers_lower[header_name].lower():
                missing_headers.append(f"{header_name} (incorrect value)")

        # Check CORS
        if "access-control-allow-origin" in headers_lower:
            cors_val = headers_lower["access-control-allow-origin"]
            if cors_val == "*":
                self._add_finding(
                    title="Overly Permissive CORS Policy (Wildcard Origin)",
                    owasp=OWASPCategory.API7_SECURITY_MISCONF,
                    endpoint="/users/v1",
                    method="GET",
                    cvss=CVSSScore.from_score(
                        6.5,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description="API returns Access-Control-Allow-Origin: * allowing any origin to read responses.",
                    impact="Cross-origin data theft via malicious websites.",
                    poc=f"# In malicious page:\nfetch('{self._base_url}/users/v1').then(r => r.json()).then(console.log)",
                    evidence=[HTTPEvidence(
                        method="GET", url=f"{self._base_url}/users/v1",
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                    )],
                    remediation=[
                        "Restrict CORS to trusted origins only.",
                        "Never use Access-Control-Allow-Origin: * for authenticated APIs.",
                    ],
                )

        if missing_headers:
            self._add_finding(
                title="Missing Security Headers in API Responses",
                owasp=OWASPCategory.API7_SECURITY_MISCONF,
                endpoint="/users/v1",
                method="GET",
                cvss=CVSSScore.from_score(
                    4.3,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=f"The following security headers are missing: {missing_headers}",
                impact="Increases attack surface for XSS, clickjacking, and MIME sniffing attacks.",
                poc=f"curl -I {self._base_url}/users/v1",
                evidence=[HTTPEvidence(
                    method="GET", url=f"{self._base_url}/users/v1",
                    response_headers=dict(resp.headers),
                    response_status=resp.status_code,
                )],
                remediation=[
                    f"Add missing headers: {missing_headers}",
                    "Use a security headers middleware (e.g., flask-talisman).",
                ],
            )

    # ── Test: Error message disclosure ────────────────────────────────────

    def _test_error_message_disclosure(self) -> None:
        """
        Test 5: Trigger server errors and check if stack traces are exposed.
        """
        # Send a malformed request to trigger an error
        try:
            resp = self._client.put(
                "/users/v1/nonexistent/email",
                json={"email": "x"},
                headers={"Content-Type": "application/json"},
            )
            response_text = (resp.text or "").lower()
            has_disclosure = any(sig in response_text for sig in _DEBUG_SIGNALS)

            if has_disclosure:
                self._add_finding(
                    title="Server Error — Internal Information Disclosure in Error Response",
                    owasp=OWASPCategory.API3_DATA_EXPOSURE,
                    endpoint="/users/v1/{username}/email",
                    method="PUT",
                    cvss=CVSSScore.from_score(
                        5.3,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description="Server error responses include stack traces or internal framework details.",
                    impact="Reveals technology stack, file paths, and code structure to attackers.",
                    poc=f"curl -X PUT {self._base_url}/users/v1/nonexistent/email -d '{{\"email\":\"x\"}}'",
                    evidence=[HTTPEvidence(
                        method="PUT",
                        url=f"{self._base_url}/users/v1/nonexistent/email",
                        response_status=resp.status_code,
                        response_body=self._safe_json(resp.text),
                    )],
                    remediation=[
                        "Configure error handlers to return generic error messages.",
                        "Disable debug mode in production (FLASK_DEBUG=0).",
                        "Log detailed errors server-side only, never in responses.",
                    ],
                )
        except Exception:
            pass

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _find_sensitive_fields(self, data: Any, _depth: int = 0) -> Set[str]:
        """Recursively scan a parsed JSON structure for sensitive field names."""
        found: Set[str] = set()
        if _depth > 5:
            return found

        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in _SENSITIVE_FIELDS:
                    found.add(key.lower())
                found.update(self._find_sensitive_fields(value, _depth + 1))
        elif isinstance(data, list):
            for item in data[:10]:  # Limit to first 10 items
                found.update(self._find_sensitive_fields(item, _depth + 1))

        return found

    def _next_vuln_id(self) -> str:
        self._vuln_counter += 1
        return f"EXPO-{self._vuln_counter:03d}"

    def _add_finding(self, title, owasp, endpoint, method, cvss, status,
                     confirmed, description, impact, poc, evidence, remediation) -> None:
        finding = VulnerabilityFinding(
            vuln_id=self._next_vuln_id(), title=title, owasp_category=owasp,
            endpoint=endpoint, method=method, cvss=cvss, status=status,
            confirmed=confirmed, description=description, impact=impact,
            proof_of_concept=poc, evidence=evidence, remediation=remediation,
            references=["https://owasp.org/API-Security/editions/2019/en/0xa3-excessive-data-exposure/"],
        )
        self._findings.append(finding)
        logger.info("DataExposureTester: finding added", title=title, severity=cvss.severity.value)

    @staticmethod
    def _safe_json(text: str) -> Any:
        try:
            return json.loads(text)
        except Exception:
            return text[:500] if text else None
