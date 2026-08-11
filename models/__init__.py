"""
models/__init__.py
==================
Makes `models` a proper Python package and re-exports commonly-used types.
"""

from models.endpoint import (  # noqa: F401
    AuthType,
    DiscoveryMethod,
    EndpointCategory,
    EndpointModel,
    HTTPMethod,
    ParameterModel,
    RiskLevel,
)
from models.catalog import APICatalog, CatalogStats, ScanMetadata  # noqa: F401

__all__ = [
    "AuthType",
    "DiscoveryMethod",
    "EndpointCategory",
    "EndpointModel",
    "HTTPMethod",
    "ParameterModel",
    "RiskLevel",
    "APICatalog",
    "CatalogStats",
    "ScanMetadata",
]
