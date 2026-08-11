"""
tools/rate_limit_tester.py
===========================
Security Tool 6 — Rate Limiting & DoS Testing

Tests for OWASP API4:2019 Lack of Resources & Rate Limiting.

Test cases
----------
1. Rapid login attempts — check for 429 / account lockout.
2. Rapid registration spam — check for 429.
3. Rapid GET requests — check for 429 on listing endpoints.
4. Check ``Retry-After`` and ``X-RateLimit-*`` headers.
5. Detect credential stuffing surface — unlimited login attempts.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

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
# Constants
# ---------------------------------------------------------------------------

_RAPID_REQUEST_COUNT = 20   # Send N rapid requests
_RATE_LIMIT_THRESHOLD = 15  # If > N requests succeed without 429, flag it
_RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-rate-limit-limit",
    "x-ratelimit-remaining", "ratelimit-limit",
    "retry-after",
]


class RateLimitTester:
    """
    Tests for missing or inadequate rate limiting on API endpoints.

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
        """Execute all rate limit tests and return findings."""
        logger.info("RateLimitTester: starting tests")
        self._test_login_rate_limit()
        self._test_registration_rate_limit()
        self._test_listing_rate_limit()
        logger.info("RateLimitTester: complete", findings=len(self._findings))
        return self._findings

    # ── Test: Login rate limiting ──────────────────────────────────────────

    def _test_login_rate_limit(self) -> None:
        """
        Test 1: Send N rapid login requests with wrong credentials.
        If no 429 is returned after threshold, rate limiting is missing.
        """
        logger.info("RateLimitTester: testing login rate limiting")

        statuses: List[int] = []
        evidence_sample: Optional[HTTPEvidence] = None
        rate_limit_headers_seen: Dict[str, str] = {}

        for i in range(_RAPID_REQUEST_COUNT):
            try:
                resp = self._client.post(
                    "/users/v1/login",
                    json={"username": "nonexistent_user_ratetest", "password": "wrongpass"},
                    headers={"Content-Type": "application/json"},
                )
                statuses.append(resp.status_code)

                # Capture headers from first response
                if i == 0:
                    evidence_sample = HTTPEvidence(
                        method="POST",
                        url=f"{self._base_url}/users/v1/login",
                        request_body={"username": "nonexistent_user_ratetest", "password": "***"},
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=self._safe_json(resp.text),
                    )
                    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                    for h in _RATE_LIMIT_HEADERS:
                        if h in headers_lower:
                            rate_limit_headers_seen[h] = headers_lower[h]

                if resp.status_code == 429:
                    logger.info(
                        "RateLimitTester: login 429 received",
                        after_requests=i + 1,
                    )
                    break

                time.sleep(0.05)  # 50ms between requests (still rapid)
            except Exception as exc:
                logger.debug("RateLimitTester: request error", error=str(exc))
                break

        rate_limited = 429 in statuses
        too_many_non_429 = statuses.count(401) >= _RATE_LIMIT_THRESHOLD

        if not rate_limited and too_many_non_429:
            evidence = []
            if evidence_sample:
                evidence.append(evidence_sample)

            self._add_finding(
                title="No Rate Limiting on Login Endpoint — Credential Stuffing Risk",
                owasp=OWASPCategory.API4_LACK_RESOURCES,
                endpoint="/users/v1/login",
                method="POST",
                cvss=CVSSScore.from_score(
                    7.5,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"Sent {len(statuses)} rapid login requests. "
                    f"No HTTP 429 (Too Many Requests) was returned. "
                    f"No rate-limit headers detected: {rate_limit_headers_seen or 'none'}. "
                    f"Status codes received: {dict(zip(*[[x for x in set(statuses)], [statuses.count(x) for x in set(statuses)]]))}"
                ),
                impact=(
                    "Attackers can perform unlimited brute-force or credential stuffing attacks "
                    "against the login endpoint without any throttling or lockout mechanism."
                ),
                poc=(
                    f"# Send 20 rapid login requests:\n"
                    f"for i in range(20):\n"
                    f"    requests.post('{self._base_url}/users/v1/login',\n"
                    f"        json={{\"username\":\"victim\",\"password\":f\"guess{{i}}\"}})\n"
                    f"# No 429 returned — unlimited attempts allowed"
                ),
                evidence=evidence,
                remediation=[
                    "Implement rate limiting: max 5 failed attempts per username per minute.",
                    "Add account lockout after 10 consecutive failed attempts.",
                    "Return HTTP 429 with Retry-After header when limit exceeded.",
                    "Implement CAPTCHA for login after N failed attempts.",
                    "Use exponential backoff for repeated failures.",
                    "Log and alert on high-frequency login failure patterns.",
                ],
            )
        elif rate_limited:
            logger.info(
                "RateLimitTester: login endpoint has rate limiting",
                after=statuses.index(429) + 1,
            )

    # ── Test: Registration rate limiting ──────────────────────────────────

    def _test_registration_rate_limit(self) -> None:
        """
        Test 2: Rapidly register multiple accounts.
        Unlimited registration enables spam and resource exhaustion.
        """
        logger.info("RateLimitTester: testing registration rate limiting")

        statuses: List[int] = []
        for i in range(10):  # Fewer iterations to avoid polluting the DB too much
            try:
                username = f"ratetest_{uuid.uuid4().hex[:8]}"
                resp = self._client.post(
                    "/users/v1/register",
                    json={
                        "username": username,
                        "password": "RateTest@1",
                        "email": f"{username}@test.invalid",
                    },
                    headers={"Content-Type": "application/json"},
                )
                statuses.append(resp.status_code)

                if resp.status_code == 429:
                    break

                time.sleep(0.1)
            except Exception:
                break

        rate_limited = 429 in statuses
        all_succeeded = all(s in (200, 201) for s in statuses)

        if not rate_limited and all_succeeded and len(statuses) >= 8:
            self._add_finding(
                title="No Rate Limiting on Registration Endpoint — Account Creation Spam",
                owasp=OWASPCategory.API4_LACK_RESOURCES,
                endpoint="/users/v1/register",
                method="POST",
                cvss=CVSSScore.from_score(
                    5.3,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"Successfully registered {len(statuses)} accounts in rapid succession "
                    f"without any rate limiting. All requests returned success status codes."
                ),
                impact=(
                    "Attackers can create unlimited accounts (bot registration, spam, "
                    "resource exhaustion of database and storage)."
                ),
                poc=(
                    f"for i in range(1000):\n"
                    f"    requests.post('{self._base_url}/users/v1/register',\n"
                    f"        json={{\"username\":f\"spam{{i}}\",\"password\":\"x\",\"email\":f\"s{{i}}@x.com\"}})"
                ),
                evidence=[],
                remediation=[
                    "Implement IP-based rate limiting on registration (max 5/hour per IP).",
                    "Add email verification to prevent disposable email spam.",
                    "Implement CAPTCHA on registration.",
                    "Return HTTP 429 with Retry-After when limit exceeded.",
                ],
            )

    # ── Test: Listing endpoint rate limiting ───────────────────────────────

    def _test_listing_rate_limit(self) -> None:
        """
        Test 3: Rapid GET requests to user listing endpoint.
        """
        logger.info("RateLimitTester: testing GET /users/v1 rate limiting")

        statuses: List[int] = []
        for i in range(30):
            try:
                resp = self._client.get("/users/v1")
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    break
                time.sleep(0.02)  # 20ms between requests
            except Exception:
                break

        rate_limited = 429 in statuses
        success_count = statuses.count(200)

        if not rate_limited and success_count >= 20:
            self._add_finding(
                title="No Rate Limiting on User Listing Endpoint",
                owasp=OWASPCategory.API4_LACK_RESOURCES,
                endpoint="/users/v1",
                method="GET",
                cvss=CVSSScore.from_score(
                    5.3,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                ),
                status=TestStatus.VULNERABLE,
                confirmed=True,
                description=(
                    f"Sent {len(statuses)} rapid GET requests to /users/v1 without 429. "
                    "Unlimited scraping of user data is possible."
                ),
                impact="Enables bulk user enumeration and DoS via resource exhaustion.",
                poc=(
                    f"# Unlimited user list scraping:\n"
                    f"for i in range(10000):\n"
                    f"    requests.get('{self._base_url}/users/v1')"
                ),
                evidence=[],
                remediation=[
                    "Implement global API rate limiting (e.g., 100 requests/minute per IP).",
                    "Use a reverse proxy (nginx, Cloudflare) for rate limit enforcement.",
                    "Add pagination to prevent bulk data extraction in a single request.",
                ],
            )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _next_vuln_id(self) -> str:
        self._vuln_counter += 1
        return f"RATE-{self._vuln_counter:03d}"

    def _add_finding(self, title, owasp, endpoint, method, cvss, status,
                     confirmed, description, impact, poc, evidence, remediation) -> None:
        finding = VulnerabilityFinding(
            vuln_id=self._next_vuln_id(), title=title, owasp_category=owasp,
            endpoint=endpoint, method=method, cvss=cvss, status=status,
            confirmed=confirmed, description=description, impact=impact,
            proof_of_concept=poc, evidence=evidence, remediation=remediation,
            references=["https://owasp.org/API-Security/editions/2019/en/0xa4-lack-of-resources-and-rate-limiting/"],
        )
        self._findings.append(finding)
        logger.info("RateLimitTester: finding added", title=title, severity=cvss.severity.value)

    @staticmethod
    def _safe_json(text: str) -> Any:
        try:
            return json.loads(text)
        except Exception:
            return text[:500] if text else None
