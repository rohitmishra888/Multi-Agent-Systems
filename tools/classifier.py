"""
tools/classifier.py
===================
Endpoint categorisation and preliminary security risk classification.

Design
------
Classification is rule-based, using ordered matcher lists.  This makes it:
- Transparent (no ML black box)
- Auditable (rules documented inline)
- Extensible (new rules are one-line additions)

Category classification
-----------------------
Matches are attempted in priority order; the first match wins.
Patterns examine the endpoint path, HTTP method, and tags.

Risk classification
-------------------
Risk scoring uses a weighted heuristic across multiple signals:
- HTTP method (DELETE, PUT → higher risk)
- Path patterns (admin, password → critical/high)
- Authentication status (no auth on modifying endpoint → elevated)
- Response codes (500 → server-side issue)

Risk thresholds:
  0–1   → LOW
  2–3   → MEDIUM
  4–5   → HIGH
  6+    → CRITICAL
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern, Tuple

from models.endpoint import EndpointCategory, EndpointModel, RiskLevel
from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Category matcher
# ---------------------------------------------------------------------------

@dataclass
class CategoryMatcher:
    """
    A single pattern-based rule for assigning a category.

    Attributes
    ----------
    category:
        The category to assign when this rule matches.
    path_patterns:
        List of regexes checked against the endpoint path (case-insensitive).
    methods:
        If set, only match when the HTTP method is in this list.
    tags:
        If set, match when the endpoint's OpenAPI tags overlap.
    """

    category: EndpointCategory
    path_patterns: List[Pattern] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def matches(self, endpoint: EndpointModel) -> bool:
        """Return True if this rule matches the given endpoint."""
        path = endpoint.endpoint.lower()
        method = endpoint.method.value.upper()
        ep_tags = [t.lower() for t in endpoint.tags]

        # Method constraint
        if self.methods and method not in [m.upper() for m in self.methods]:
            return False

        # Tag matching
        if self.tags:
            rule_tags = [t.lower() for t in self.tags]
            if any(rt in ep_tags for rt in rule_tags):
                return True

        # Path pattern matching
        for pattern in self.path_patterns:
            if pattern.search(path):
                return True

        return False


# Ordered list of category matchers — first match wins
_CATEGORY_MATCHERS: List[CategoryMatcher] = [
    # Administration — checked first (highest specificity)
    CategoryMatcher(
        category=EndpointCategory.ADMINISTRATION,
        path_patterns=[
            re.compile(r"/admin"),
            re.compile(r"/administration"),
            re.compile(r"/superuser"),
            re.compile(r"/console"),
        ],
        tags=["admin", "administration"],
    ),
    # Authentication
    CategoryMatcher(
        category=EndpointCategory.AUTHENTICATION,
        path_patterns=[
            re.compile(r"/login"),
            re.compile(r"/logout"),
            re.compile(r"/register"),
            re.compile(r"/auth(?:/|$)"),
            re.compile(r"/token"),
            re.compile(r"/refresh"),
            re.compile(r"/oauth"),
            re.compile(r"/verify"),
            re.compile(r"/forgot-password"),
            re.compile(r"/reset-password"),
        ],
        tags=["auth", "authentication", "login", "register"],
    ),
    # User Management
    CategoryMatcher(
        category=EndpointCategory.USER_MANAGEMENT,
        path_patterns=[
            re.compile(r"/users?"),
            re.compile(r"/profile"),
            re.compile(r"/account"),
            re.compile(r"/me"),
            re.compile(r"/password"),
            re.compile(r"/email"),
        ],
        tags=["users", "user", "profile"],
    ),
    # Book Management
    CategoryMatcher(
        category=EndpointCategory.BOOK_MANAGEMENT,
        path_patterns=[
            re.compile(r"/books?"),
            re.compile(r"/library"),
            re.compile(r"/catalogue"),
            re.compile(r"/catalog"),
        ],
        tags=["books", "book", "library"],
    ),
    # Internal
    CategoryMatcher(
        category=EndpointCategory.INTERNAL,
        path_patterns=[
            re.compile(r"/internal"),
            re.compile(r"/private"),
            re.compile(r"/health"),
            re.compile(r"/status"),
            re.compile(r"/metrics"),
            re.compile(r"/ping"),
        ],
        tags=["internal", "health", "monitoring"],
    ),
    # Public (catch-all for GET endpoints with no auth)
    CategoryMatcher(
        category=EndpointCategory.PUBLIC,
        path_patterns=[
            re.compile(r"^/$"),
            re.compile(r"/docs"),
            re.compile(r"/swagger"),
            re.compile(r"/redoc"),
            re.compile(r"/version"),
            re.compile(r"/info"),
        ],
        tags=["public"],
    ),
]


# ---------------------------------------------------------------------------
# Risk scoring rules
# ---------------------------------------------------------------------------

@dataclass
class RiskRule:
    """A single risk score contribution rule."""

    score: int
    description: str
    path_patterns: List[Pattern] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    requires_no_auth: bool = False
    requires_auth: bool = False
    response_codes: List[int] = field(default_factory=list)

    def applies(self, endpoint: EndpointModel) -> bool:
        """Check whether this rule applies to the given endpoint."""
        method = endpoint.method.value.upper()
        path = endpoint.endpoint.lower()

        if self.methods and method not in [m.upper() for m in self.methods]:
            return False
        if self.requires_no_auth and endpoint.authentication_required:
            return False
        if self.requires_auth and not endpoint.authentication_required:
            return False

        if self.path_patterns:
            if not any(p.search(path) for p in self.path_patterns):
                return False

        if self.response_codes:
            if not any(c in endpoint.response_codes for c in self.response_codes):
                return False

        return True


_RISK_RULES: List[RiskRule] = [
    # ── Critical signals ─────────────────────────────────────────────────────
    RiskRule(
        score=4,
        description="Admin endpoint",
        path_patterns=[re.compile(r"/admin")],
    ),
    RiskRule(
        score=3,
        description="Admin endpoint without authentication",
        path_patterns=[re.compile(r"/admin")],
        requires_no_auth=True,
    ),
    RiskRule(
        score=3,
        description="Mass-user deletion or bulk DELETE",
        methods=["DELETE"],
        path_patterns=[re.compile(r"/users"), re.compile(r"/accounts")],
    ),
    # ── High signals ─────────────────────────────────────────────────────────
    RiskRule(
        score=2,
        description="Authentication endpoint (login/register)",
        path_patterns=[re.compile(r"/login"), re.compile(r"/register")],
    ),
    RiskRule(
        score=2,
        description="Password change/reset endpoint",
        path_patterns=[re.compile(r"/password"), re.compile(r"/reset")],
    ),
    RiskRule(
        score=2,
        description="DELETE method",
        methods=["DELETE"],
    ),
    RiskRule(
        score=2,
        description="User profile/email update (IDOR risk)",
        methods=["PUT", "PATCH"],
        path_patterns=[re.compile(r"/users?/"), re.compile(r"/email")],
    ),
    RiskRule(
        score=2,
        description="Server error observed (500)",
        response_codes=[500],
    ),
    # ── Medium signals ───────────────────────────────────────────────────────
    RiskRule(
        score=1,
        description="Unauthenticated write operation",
        methods=["POST", "PUT", "PATCH", "DELETE"],
        requires_no_auth=True,
    ),
    RiskRule(
        score=1,
        description="POST method",
        methods=["POST"],
    ),
    RiskRule(
        score=1,
        description="PUT / PATCH method",
        methods=["PUT", "PATCH"],
    ),
    RiskRule(
        score=1,
        description="Parameterised path (potential IDOR)",
        path_patterns=[re.compile(r"\{[^}]+\}")],
    ),
    RiskRule(
        score=1,
        description="User data endpoint",
        path_patterns=[re.compile(r"/users?/")],
    ),
    # ── Low / protective signals ─────────────────────────────────────────────
    RiskRule(
        score=-1,
        description="Authentication required (reduces residual risk)",
        requires_auth=True,
    ),
]

# Score thresholds → RiskLevel
_RISK_THRESHOLDS: List[Tuple[int, RiskLevel]] = [
    (6, RiskLevel.CRITICAL),
    (4, RiskLevel.HIGH),
    (2, RiskLevel.MEDIUM),
    (0, RiskLevel.LOW),
]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class Classifier:
    """
    Assigns functional category and preliminary security risk to endpoints.

    The classifier is stateless — call ``classify()`` for each endpoint.
    """

    # ── Public interface ────────────────────────────────────────────────────

    def classify(self, endpoint: EndpointModel) -> EndpointModel:
        """
        Assign ``category``, ``risk``, ``sensitive_operation``, and ``potential_idor`` to an endpoint.
        """
        endpoint.category = self._classify_category(endpoint)

        # Set security context flags
        endpoint.sensitive_operation = endpoint.method.value in ("POST", "PUT", "PATCH", "DELETE") and endpoint.category != EndpointCategory.PUBLIC
        endpoint.potential_idor = bool(re.search(r"\{[^}]+\}", endpoint.endpoint))

        # Classify inherent attack-surface risk
        endpoint.risk, endpoint.risk_rationale = self._classify_risk(endpoint)

        logger.debug(
            "Classified endpoint",
            path=endpoint.endpoint,
            method=endpoint.method.value,
            category=endpoint.category.value,
            risk=endpoint.risk.value,
            supported=endpoint.supported,
        )
        return endpoint

    # ── Category ──────────────────────────────────────────────────────────────

    @staticmethod
    def _classify_category(endpoint: EndpointModel) -> EndpointCategory:
        """Apply category matchers in priority order; return first match."""
        for matcher in _CATEGORY_MATCHERS:
            if matcher.matches(endpoint):
                return matcher.category
        return EndpointCategory.UNKNOWN

    # ── Risk ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _classify_risk(endpoint: EndpointModel) -> Tuple[RiskLevel, str]:
        """
        Score the endpoint using all risk rules and return a (level, rationale).
        """
        # Unsupported methods (HTTP 405/404) carry no active attack surface
        if not endpoint.supported or (405 in endpoint.response_codes and 200 not in endpoint.response_codes):
            return RiskLevel.INFO, "HTTP method not supported by server (HTTP 405 Method Not Allowed)."

        total_score = 0
        matched_rules: List[str] = []

        for rule in _RISK_RULES:
            if rule.applies(endpoint):
                total_score += rule.score
                matched_rules.append(f"{rule.description} (+{rule.score})")

        # Clamp to 0 minimum
        total_score = max(0, total_score)

        # Map score to level
        risk = RiskLevel.LOW
        for threshold, level in _RISK_THRESHOLDS:
            if total_score >= threshold:
                risk = level
                break

        rationale = f"Score={total_score}. " + " | ".join(matched_rules) if matched_rules else "No inherent risk signals detected."

        return risk, rationale

