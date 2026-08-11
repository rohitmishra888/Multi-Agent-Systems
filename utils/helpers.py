"""
utils/helpers.py
================
Shared utility functions used across multiple modules.

Each function is small, pure (side-effect-free where possible), and tested
individually.  Nothing in here should know about business logic.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def normalise_path(path: str) -> str:
    """
    Normalise a URL path to a canonical form.

    * Ensures leading slash
    * Strips trailing slash (except for root "/")
    * Collapses duplicate slashes

    Examples
    --------
    >>> normalise_path("users/v1/")
    '/users/v1'
    >>> normalise_path("//users//v1")
    '/users/v1'
    """
    # Collapse duplicate slashes
    path = re.sub(r"/{2,}", "/", path)
    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path
    # Strip trailing slash unless it's the root
    if path != "/":
        path = path.rstrip("/")
    return path


def build_url(base: str, path: str) -> str:
    """
    Safely combine a base URL with a path.

    Parameters
    ----------
    base:
        Root URL, e.g. ``"http://localhost:5000"``.
    path:
        Relative path, e.g. ``"/users/v1"``.

    Returns
    -------
    str
        Absolute URL.
    """
    base = base.rstrip("/")
    path = "/" + path.lstrip("/")
    return base + path


def extract_path(url: str) -> str:
    """
    Extract only the path component from a full URL.

    Examples
    --------
    >>> extract_path("http://localhost:5000/users/v1?foo=bar")
    '/users/v1'
    """
    return urlparse(url).path


def is_same_host(url: str, base: str) -> bool:
    """
    Return True when *url* belongs to the same host as *base*.

    Used by the crawler to avoid following external links.
    """
    return urlparse(url).netloc == urlparse(base).netloc


# ---------------------------------------------------------------------------
# Path-parameter detection
# ---------------------------------------------------------------------------

# Patterns that indicate a URL segment is a variable placeholder
_PARAM_PATTERNS = [
    re.compile(r"^\{.+\}$"),          # {user_id}
    re.compile(r"^:.+"),              # :user_id  (Express-style)
    re.compile(r"^<.+>$"),            # <user_id>  (Flask-style)
    re.compile(r"^\d+$"),             # numeric literal → likely an ID
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),  # UUID
]


def contains_path_param(segment: str) -> bool:
    """
    Return True when a single path segment looks like a path parameter.

    Examples
    --------
    >>> contains_path_param("{user_id}")
    True
    >>> contains_path_param("users")
    False
    >>> contains_path_param("12345")
    True
    """
    return any(p.match(segment) for p in _PARAM_PATTERNS)


def extract_path_params(path: str) -> List[str]:
    """
    Extract all path-parameter names from a templated URL path.

    Examples
    --------
    >>> extract_path_params("/users/v1/{user_id}/email")
    ['user_id']
    """
    params: List[str] = []
    for segment in path.split("/"):
        m = re.match(r"^\{(.+)\}$", segment)
        if m:
            params.append(m.group(1))
    return params


# ---------------------------------------------------------------------------
# JSON / schema helpers
# ---------------------------------------------------------------------------

def safe_json_loads(text: str) -> Optional[Any]:
    """
    Attempt JSON parsing; return ``None`` instead of raising on failure.

    Parameters
    ----------
    text:
        Raw string to parse.

    Returns
    -------
    Any | None
        Parsed object or ``None`` on error.
    """
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def infer_json_schema(data: Any) -> Dict[str, Any]:
    """
    Naively infer a JSON Schema object from a concrete Python value.

    This is deliberately lightweight — it produces a *description* of the
    data shape rather than a fully-compliant draft schema.

    Parameters
    ----------
    data:
        Parsed JSON value (dict, list, str, int, float, bool, None).

    Returns
    -------
    dict
        Schema dict with at minimum a ``"type"`` key.
    """
    if data is None:
        return {"type": "null"}
    if isinstance(data, bool):
        return {"type": "boolean"}
    if isinstance(data, int):
        return {"type": "integer"}
    if isinstance(data, float):
        return {"type": "number"}
    if isinstance(data, str):
        return {"type": "string"}
    if isinstance(data, list):
        items_schema: Dict[str, Any] = {}
        if data:
            items_schema = infer_json_schema(data[0])
        return {"type": "array", "items": items_schema}
    if isinstance(data, dict):
        props = {k: infer_json_schema(v) for k, v in data.items()}
        return {"type": "object", "properties": props}
    return {"type": "unknown"}


# ---------------------------------------------------------------------------
# Endpoint deduplication key
# ---------------------------------------------------------------------------

def endpoint_key(method: str, path: str) -> str:
    """
    Build a canonical deduplication key for a (method, path) pair.

    Parameters
    ----------
    method:
        HTTP verb.
    path:
        Normalised URL path.

    Returns
    -------
    str
        Key in the form ``"GET:/users/v1"``.

    Examples
    --------
    >>> endpoint_key("get", "/users/v1/")
    'GET:/users/v1'
    """
    return f"{method.upper()}:{normalise_path(path)}"


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------

def slugify(text: str) -> str:
    """
    Convert arbitrary text into a filesystem-safe slug.

    Examples
    --------
    >>> slugify("User Management")
    'user-management'
    """
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate *text* to *max_len* characters, appending '…' if truncated."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def deduplicate_preserve_order(items: List[Any]) -> List[Any]:
    """
    Remove duplicates from a list while preserving insertion order.

    Parameters
    ----------
    items:
        List that may contain duplicates (items must be hashable).

    Returns
    -------
    list
        New list with duplicates removed.
    """
    seen: Set[Any] = set()
    result: List[Any] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
