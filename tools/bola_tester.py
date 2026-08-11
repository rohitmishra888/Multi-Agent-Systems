"""
tools/bola_tester.py
====================
Security Tool 2 — Broken Object Level Authorization (BOLA / IDOR)

Tests for OWASP API1:2019 Broken Object Level Authorization.

Test cases
----------
1. Register two users (UserA, UserB).
2. Login as UserA → capture JWT_A.
3. Use JWT_A to access ``GET /users/v1/UserB`` → should return 403/401.
4. Use JWT_A to ``DELETE /users/v1/UserB`` → should fail.
5. Use JWT_A to ``PUT /users/v1/UserB/email`` → should fail.
6. Use JWT_A to ``PUT /users/v1/UserB/password`` → should fail.
7. Access book belonging to another user → check data leakage.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

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


class BOLATester:
    """
    Tests for Broken Object Level Authorization (BOLA/IDOR) vulnerabilities.

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

        # Test user credentials
        suffix = uuid.uuid4().hex[:6]
        self._user_a = {"username": f"bola_a_{suffix}", "password": "TestPass@1", "email": f"a_{suffix}@test.invalid"}
        self._user_b = {"username": f"bola_b_{suffix}", "password": "TestPass@2", "email": f"b_{suffix}@test.invalid"}
        self._jwt_a: Optional[str] = None
        self._jwt_b: Optional[str] = None

    # ── Public interface ────────────────────────────────────────────────────

    def run(self) -> List[VulnerabilityFinding]:
        """Execute all BOLA tests and return findings."""
        logger.info("BOLATester: starting BOLA/IDOR tests")

        if not self._setup_users():
            logger.warning("BOLATester: could not set up test users, running limited tests")
            self._test_unauthenticated_user_access()
        else:
            self._test_cross_user_profile_read()
            self._test_cross_user_delete()
            self._test_cross_user_email_update()
            self._test_cross_user_password_update()
            self._test_unauthenticated_user_access()

        logger.info("BOLATester: complete", findings=len(self._findings))
        return self._findings

    # ── Setup ───────────────────────────────────────────────────────────────

    def _setup_users(self) -> bool:
        """Register two test users and capture their JWTs. Returns True on success."""
        try:
            for user in [self._user_a, self._user_b]:
                reg = self._client.post(
                    "/users/v1/register",
                    json=user,
                    headers={"Content-Type": "application/json"},
                )
                logger.debug(
                    "BOLATester: registered user",
                    username=user["username"],
                    status=reg.status_code,
                )

            self._jwt_a = self._login(self._user_a)
            self._jwt_b = self._login(self._user_b)

            if self._jwt_a and self._jwt_b:
                logger.info(
                    "BOLATester: both test users ready",
                    user_a=self._user_a["username"],
                    user_b=self._user_b["username"],
                )
                return True
        except Exception as exc:
            logger.warning("BOLATester: user setup failed", error=str(exc))
        return False

    def _login(self, user: Dict[str, str]) -> Optional[str]:
        """Login a user and return their JWT token."""
        try:
            resp = self._client.post(
                "/users/v1/login",
                json={"username": user["username"], "password": user["password"]},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = json.loads(resp.text)
                return (
                    data.get("auth_token")
                    or data.get("token")
                    or data.get("access_token")
                    or data.get("jwt")
                )
        except Exception as exc:
            logger.debug("BOLATester: login failed", error=str(exc))
        return None

    # ── Test: Cross-user profile read ─────────────────────────────────────

    def _test_cross_user_profile_read(self) -> None:
        """
        Test 1: User A accesses User B's profile using User A's token.
        This should return 403 but VAmPI allows it → BOLA confirmed.
        """
        target_path = f"/users/v1/{self._user_b['username']}"
        resp = self._client.get(
            target_path,
            headers={"Authorization": f"Bearer {self._jwt_a}"},
        )

        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}{target_path}",
            request_headers={"Authorization": "Bearer <User_A_JWT>"},
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code == 200:
            body = self._safe_json(resp.text)
            # Check if User B's data is returned
            if isinstance(body, dict) and (
                self._user_b["username"] in json.dumps(body)
                or "email" in str(body)
                or "admin" in str(body)
            ):
                self._add_finding(
                    title="Broken Object Level Authorization — Cross-User Profile Read",
                    owasp=OWASPCategory.API1_BOLA,
                    endpoint="/users/v1/{username}",
                    method="GET",
                    cvss=CVSSScore.from_score(
                        8.1,
                        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description=(
                        f"User '{self._user_a['username']}' (authenticated with their own JWT) "
                        f"successfully accessed User '{self._user_b['username']}'s profile data "
                        f"by simply changing the username in the URL. "
                        f"The API does not verify that the requesting user owns the resource."
                    ),
                    impact=(
                        "Any authenticated user can read any other user's profile data, "
                        "including potentially sensitive fields like email addresses and admin flags."
                    ),
                    poc=(
                        f"# Login as User A to get JWT\n"
                        f"curl -X POST {self._base_url}/users/v1/login "
                        f"-d '{{\"username\":\"{self._user_a['username']}\",\"password\":\"...\"}}\'\n\n"
                        f"# Use User A's JWT to access User B's data\n"
                        f"curl -H 'Authorization: Bearer <JWT_A>' "
                        f"{self._base_url}/users/v1/{self._user_b['username']}"
                    ),
                    evidence=[ev],
                    remediation=[
                        "Verify that the authenticated user ID matches the requested resource owner ID.",
                        "Use the JWT sub/username claim to authorise resource access, not the URL parameter.",
                        "Implement object-level access control checks in every endpoint handler.",
                        "Return HTTP 403 Forbidden when a user attempts to access another user's resource.",
                    ],
                )
            else:
                logger.info("BOLATester: cross-user read returned 200 but no PII found")
        elif resp.status_code in (401, 403):
            logger.info("BOLATester: cross-user read correctly rejected", status=resp.status_code)

    # ── Test: Cross-user DELETE ────────────────────────────────────────────

    def _test_cross_user_delete(self) -> None:
        """
        Test 2: User A attempts to delete User B's account.
        """
        target_path = f"/users/v1/{self._user_b['username']}"
        resp = self._client.delete(
            target_path,
            headers={"Authorization": f"Bearer {self._jwt_a}"},
        )

        ev = HTTPEvidence(
            method="DELETE",
            url=f"{self._base_url}{target_path}",
            request_headers={"Authorization": "Bearer <User_A_JWT>"},
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code in (200, 204):
            self._add_finding(
                title="Broken Object Level Authorization — Cross-User Account Deletion",
                owasp=OWASPCategory.API1_BOLA,
                endpoint="/users/v1/{username}",
                method="DELETE",
                cvss=CVSSScore.from_score(
                    9.1,
                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"User '{self._user_a['username']}' successfully deleted "
                    f"User '{self._user_b['username']}'s account using their own JWT. "
                    f"The API does not verify resource ownership before deletion."
                ),
                impact="Any authenticated user can delete any other user's account.",
                poc=(
                    f"curl -X DELETE "
                    f"-H 'Authorization: Bearer <JWT_A>' "
                    f"{self._base_url}/users/v1/{self._user_b['username']}"
                ),
                evidence=[ev],
                remediation=[
                    "Verify the authenticated user owns the resource before deletion.",
                    "Only allow admin users (role-checked) to delete other user accounts.",
                    "Log all deletion operations with the requesting user's identity.",
                ],
            )
        else:
            logger.info("BOLATester: cross-user DELETE correctly rejected", status=resp.status_code)

    # ── Test: Cross-user email update ──────────────────────────────────────

    def _test_cross_user_email_update(self) -> None:
        """
        Test 3: User A updates User B's email address (IDOR on email).
        """
        target_path = f"/users/v1/{self._user_b['username']}/email"
        new_email = f"hacked_{uuid.uuid4().hex[:6]}@evil.invalid"

        resp = self._client.put(
            target_path,
            json={"email": new_email},
            headers={
                "Authorization": f"Bearer {self._jwt_a}",
                "Content-Type": "application/json",
            },
        )

        ev = HTTPEvidence(
            method="PUT",
            url=f"{self._base_url}{target_path}",
            request_headers={"Authorization": "Bearer <User_A_JWT>"},
            request_body={"email": new_email},
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code in (200, 204):
            self._add_finding(
                title="IDOR — Unauthorized Email Update on Another User's Account",
                owasp=OWASPCategory.API1_BOLA,
                endpoint="/users/v1/{username}/email",
                method="PUT",
                cvss=CVSSScore.from_score(
                    8.1,
                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"User '{self._user_a['username']}' successfully updated "
                    f"User '{self._user_b['username']}'s email to '{new_email}'. "
                    f"This is an Insecure Direct Object Reference (IDOR) vulnerability."
                ),
                impact="Account takeover: attacker changes victim's email and requests password reset.",
                poc=(
                    f"curl -X PUT "
                    f"-H 'Authorization: Bearer <JWT_A>' "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{{\"email\":\"attacker@evil.com\"}}' "
                    f"{self._base_url}/users/v1/{self._user_b['username']}/email"
                ),
                evidence=[ev],
                remediation=[
                    "Extract username from the validated JWT token, not the URL.",
                    "Verify the JWT subject matches the URL username before processing.",
                    "Implement resource ownership middleware for all user-scoped endpoints.",
                ],
            )
        else:
            logger.info("BOLATester: cross-user email update correctly rejected", status=resp.status_code)

    # ── Test: Cross-user password update ──────────────────────────────────

    def _test_cross_user_password_update(self) -> None:
        """
        Test 4: User A updates User B's password.
        """
        target_path = f"/users/v1/{self._user_b['username']}/password"
        resp = self._client.put(
            target_path,
            json={"password": "hacked_password_123"},
            headers={
                "Authorization": f"Bearer {self._jwt_a}",
                "Content-Type": "application/json",
            },
        )

        ev = HTTPEvidence(
            method="PUT",
            url=f"{self._base_url}{target_path}",
            request_headers={"Authorization": "Bearer <User_A_JWT>"},
            request_body={"password": "<redacted>"},
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code in (200, 204):
            self._add_finding(
                title="IDOR — Unauthorized Password Change on Another User's Account",
                owasp=OWASPCategory.API1_BOLA,
                endpoint="/users/v1/{username}/password",
                method="PUT",
                cvss=CVSSScore.from_score(
                    9.1,
                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"User '{self._user_a['username']}' successfully changed "
                    f"User '{self._user_b['username']}'s password without knowing the current password."
                ),
                impact="Complete account takeover — attacker locks victim out of their account.",
                poc=(
                    f"curl -X PUT "
                    f"-H 'Authorization: Bearer <JWT_A>' "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{{\"password\":\"hacker_new_pass\"}}' "
                    f"{self._base_url}/users/v1/{self._user_b['username']}/password"
                ),
                evidence=[ev],
                remediation=[
                    "Only allow users to change their own password (verify JWT subject == URL username).",
                    "Require current password confirmation before allowing password change.",
                    "Implement strong audit logging for all password change operations.",
                ],
            )

    # ── Test: Unauthenticated user list access ─────────────────────────────

    def _test_unauthenticated_user_access(self) -> None:
        """
        Test 5: Access user list without any authentication.
        """
        resp = self._client.get("/users/v1")
        ev = HTTPEvidence(
            method="GET",
            url=f"{self._base_url}/users/v1",
            response_status=resp.status_code,
            response_body=self._safe_json(resp.text),
        )

        if resp.status_code == 200:
            body = self._safe_json(resp.text)
            if isinstance(body, (dict, list)):
                self._add_finding(
                    title="User List Accessible Without Authentication",
                    owasp=OWASPCategory.API5_BROKEN_FUNC_AUTH,
                    endpoint="/users/v1",
                    method="GET",
                    cvss=CVSSScore.from_score(
                        5.3,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description=(
                        "The user listing endpoint returns data without any authentication. "
                        "This exposes usernames and potentially other sensitive fields."
                    ),
                    impact="Enables user enumeration and reconnaissance for targeted attacks.",
                    poc=f"curl {self._base_url}/users/v1",
                    evidence=[ev],
                    remediation=[
                        "Require authentication for all user listing endpoints.",
                        "Restrict user listing to admin roles only.",
                        "Implement pagination and rate limiting on public endpoints.",
                    ],
                )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _next_vuln_id(self) -> str:
        self._vuln_counter += 1
        return f"BOLA-{self._vuln_counter:03d}"

    def _add_finding(self, title, owasp, endpoint, method, cvss, status,
                     confirmed, description, impact, poc, evidence, remediation) -> None:
        finding = VulnerabilityFinding(
            vuln_id=self._next_vuln_id(),
            title=title, owasp_category=owasp, endpoint=endpoint, method=method,
            cvss=cvss, status=status, confirmed=confirmed, description=description,
            impact=impact, proof_of_concept=poc, evidence=evidence, remediation=remediation,
            references=["https://owasp.org/API-Security/editions/2019/en/0xa1-broken-object-level-authorization/"],
        )
        self._findings.append(finding)
        logger.info("BOLATester: finding added", title=title, severity=cvss.severity.value)

    @staticmethod
    def _safe_json(text: str) -> Any:
        try:
            return json.loads(text)
        except Exception:
            return text[:500] if text else None
