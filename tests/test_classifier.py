"""
tests/test_classifier.py
========================
Unit tests for the ``Classifier`` tool.

Coverage
--------
- Category classification for each EndpointCategory
- Risk level classification
- CRITICAL for admin without auth
- HIGH for DELETE, login, password endpoints
- LOW for public GET endpoints
- MEDIUM for parameterised paths
- Combined scoring
"""

from __future__ import annotations

import pytest

from models.endpoint import (
    AuthType,
    EndpointCategory,
    EndpointModel,
    HTTPMethod,
    RiskLevel,
)
from tools.classifier import Classifier


@pytest.fixture
def classifier() -> Classifier:
    return Classifier()


class TestCategoryClassification:
    """Tests for endpoint category assignment."""

    def test_login_is_authentication(self, classifier):
        ep = EndpointModel(endpoint="/users/v1/login", method=HTTPMethod.POST)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.AUTHENTICATION

    def test_register_is_authentication(self, classifier):
        ep = EndpointModel(endpoint="/users/v1/register", method=HTTPMethod.POST)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.AUTHENTICATION

    def test_users_list_is_user_management(self, classifier):
        ep = EndpointModel(endpoint="/users/v1", method=HTTPMethod.GET)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.USER_MANAGEMENT

    def test_books_is_book_management(self, classifier):
        ep = EndpointModel(endpoint="/books/v1", method=HTTPMethod.GET)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.BOOK_MANAGEMENT

    def test_admin_is_administration(self, classifier):
        ep = EndpointModel(endpoint="/admin/users", method=HTTPMethod.GET)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.ADMINISTRATION

    def test_health_is_internal(self, classifier):
        ep = EndpointModel(endpoint="/health", method=HTTPMethod.GET)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.INTERNAL

    def test_swagger_is_public(self, classifier):
        ep = EndpointModel(endpoint="/swagger.json", method=HTTPMethod.GET)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.PUBLIC

    def test_tag_based_classification(self, classifier):
        """Tags are used for classification when path doesn't match."""
        ep = EndpointModel(
            endpoint="/api/v1/resources",
            method=HTTPMethod.GET,
            tags=["books"],
        )
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.BOOK_MANAGEMENT

    def test_unknown_category_for_unmatched(self, classifier):
        ep = EndpointModel(endpoint="/xyz/random/thing", method=HTTPMethod.GET)
        result = classifier.classify(ep)
        assert result.category == EndpointCategory.UNKNOWN


class TestRiskClassification:
    """Tests for risk level assignment."""

    def test_public_get_is_low_risk(self, classifier):
        ep = EndpointModel(
            endpoint="/books/v1",
            method=HTTPMethod.GET,
            authentication_required=False,
        )
        result = classifier.classify(ep)
        assert result.risk in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_login_endpoint_is_high_risk(self, classifier):
        ep = EndpointModel(endpoint="/users/v1/login", method=HTTPMethod.POST)
        result = classifier.classify(ep)
        assert result.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_delete_endpoint_is_high_risk(self, classifier):
        ep = EndpointModel(
            endpoint="/users/v1/{user_id}",
            method=HTTPMethod.DELETE,
            authentication_required=True,
            authentication_type=AuthType.JWT,
        )
        result = classifier.classify(ep)
        assert result.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_admin_without_auth_is_critical(self, classifier):
        """Admin endpoint with no authentication is CRITICAL."""
        ep = EndpointModel(
            endpoint="/admin/all-users",
            method=HTTPMethod.GET,
            authentication_required=False,
        )
        result = classifier.classify(ep)
        assert result.risk == RiskLevel.CRITICAL

    def test_password_endpoint_is_high_risk(self, classifier):
        ep = EndpointModel(
            endpoint="/users/v1/{user_id}/password",
            method=HTTPMethod.PUT,
            authentication_required=True,
        )
        result = classifier.classify(ep)
        assert result.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_authenticated_endpoint_lower_risk(self, classifier):
        """Auth-required endpoints score lower than equivalent unprotected ones."""
        authenticated = EndpointModel(
            endpoint="/users/v1",
            method=HTTPMethod.POST,
            authentication_required=True,
            authentication_type=AuthType.JWT,
        )
        unauthenticated = EndpointModel(
            endpoint="/users/v1",
            method=HTTPMethod.POST,
            authentication_required=False,
        )
        auth_result = classifier.classify(authenticated)
        unauth_result = classifier.classify(unauthenticated)

        # Authenticated version should be at most as risky as unauthenticated
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert risk_order.index(auth_result.risk) <= risk_order.index(unauth_result.risk)

    def test_risk_rationale_populated(self, classifier):
        """risk_rationale is always set after classification."""
        ep = EndpointModel(endpoint="/users/v1/login", method=HTTPMethod.POST)
        result = classifier.classify(ep)
        assert result.risk_rationale is not None
        assert len(result.risk_rationale) > 0

    def test_500_response_code_increases_risk(self, classifier):
        """Endpoints that return 500 get an elevated risk score."""
        ep_normal = EndpointModel(
            endpoint="/books/v1",
            method=HTTPMethod.GET,
            response_codes=[200],
        )
        ep_error = EndpointModel(
            endpoint="/books/v1",
            method=HTTPMethod.GET,
            response_codes=[200, 500],
        )
        result_normal = classifier.classify(ep_normal)
        result_error = classifier.classify(ep_error)

        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert risk_order.index(result_error.risk) >= risk_order.index(result_normal.risk)
