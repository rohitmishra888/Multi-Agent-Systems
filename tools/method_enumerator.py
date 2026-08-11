"""
tools/method_enumerator.py
==========================
Step 5 of the discovery pipeline — HTTP method enumeration.

For every discovered endpoint, this tool probes all standard HTTP methods
(GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) to determine which are
actually supported.

Strategy
--------
1. Send an OPTIONS request first — many servers include an ``Allow`` header
   listing supported methods.
2. If the ``Allow`` header is not present or OPTIONS is blocked, probe each
   method individually.
3. A method is considered "supported" if the response is NOT 404 or 405.

Design
------
* Non-destructive: POST/PUT/PATCH/DELETE probes use empty or minimal bodies.
* Returns a list of (method, status_code) tuples for each endpoint.
* Updates the endpoint model with confirmed methods and additional status codes.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from models.endpoint import DiscoveryMethod, EndpointModel, HTTPMethod
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)

# HTTP methods to enumerate
_ALL_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# These status codes indicate the method IS supported (even if it fails for other reasons)
_SUPPORTED_CODES: Set[int] = {
    200, 201, 204,        # Success
    301, 302, 307, 308,   # Redirect
    400,                  # Bad request (endpoint exists, wrong input)
    401, 403,             # Auth required (endpoint exists)
    422,                  # Unprocessable (validation failure — endpoint exists)
    500,                  # Server error (endpoint exists, internal issue)
}

# These codes mean "method not supported" or "not found"
_NOT_SUPPORTED_CODES: Set[int] = {404, 405}


class MethodEnumerator:
    """
    Enumerates HTTP methods supported by each discovered endpoint.

    Parameters
    ----------
    client:
        An ``HTTPClient`` instance.
    """

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    # ── Public interface ────────────────────────────────────────────────────

    def enumerate(self, endpoint: EndpointModel) -> List[EndpointModel]:
        """
        Probe all HTTP methods for the given endpoint.

        Returns a list of ``EndpointModel`` instances — one per supported method.
        The original method (from Swagger / guessing) is always included.
        The input *endpoint* is not mutated.

        Parameters
        ----------
        endpoint:
            The base endpoint to enumerate methods for.

        Returns
        -------
        List[EndpointModel]
            One model per supported HTTP method, with ``discovered_by``
            set to ``DiscoveryMethod.METHOD_ENUM`` for newly found methods.
        """
        path = endpoint.endpoint
        logger.debug("Method enumeration", path=path)

        # Try OPTIONS first for efficiency
        supported = self._try_options_header(path)

        if not supported:
            # Fall back to individual probing
            supported = self._probe_all_methods(path)

        logger.debug(
            "Methods discovered",
            path=path,
            methods=list(supported.keys()),
        )

        return self._build_endpoints(endpoint, supported)

    # ── OPTIONS probe ────────────────────────────────────────────────────────

    def _try_options_header(self, path: str) -> Dict[str, int]:
        """
        Issue an OPTIONS request and parse the ``Allow`` header.

        Returns
        -------
        Dict[str, int]
            Map of method → status code from the OPTIONS response.
            Empty dict if OPTIONS is not informative.
        """
        try:
            resp = self._client.options(path)
            allow_header = resp.headers.get("allow", resp.headers.get("Access-Control-Allow-Methods", ""))

            if allow_header:
                methods: Dict[str, int] = {}
                for method in allow_header.replace(",", " ").split():
                    method = method.strip().upper()
                    if method in _ALL_METHODS:
                        methods[method] = 200  # Assume supported
                if methods:
                    logger.debug("OPTIONS Allow header parsed", path=path, methods=list(methods.keys()))
                    return methods
        except Exception as exc:
            logger.debug("OPTIONS probe failed", path=path, error=str(exc))

        return {}

    # ── Individual method probing ────────────────────────────────────────────

    def _probe_all_methods(self, path: str) -> Dict[str, int]:
        """
        Probe each HTTP method individually.

        Returns
        -------
        Dict[str, int]
            Map of supported method → observed status code.
        """
        supported: Dict[str, int] = {}

        for method in _ALL_METHODS:
            code = self._probe_method(method, path)
            if code is not None:
                supported[method] = code

        return supported

    def _probe_method(self, method: str, path: str) -> Optional[int]:
        """
        Issue a single request with *method* to *path*.

        Returns the status code if the method appears supported, else None.
        """
        try:
            kwargs = {}
            if method in ("POST", "PUT", "PATCH"):
                # Minimal body to avoid 400 due to missing content-type
                kwargs = {"json": {}, "headers": {"Content-Type": "application/json"}}

            resp = self._client.request(method, path, **kwargs)
            code = resp.status_code

            if code in _NOT_SUPPORTED_CODES:
                return None

            return code

        except Exception as exc:
            logger.debug(
                "Method probe failed",
                method=method,
                path=path,
                error=str(exc),
            )
            return None

    # ── Model building ────────────────────────────────────────────────────────

    @staticmethod
    def _build_endpoints(
        base: EndpointModel,
        supported: Dict[str, int],
    ) -> List[EndpointModel]:
        """
        Build one ``EndpointModel`` per supported method.

        For the method already recorded in *base*, we update its status codes.
        For newly discovered methods, we clone *base* with the new method.
        """
        if not supported:
            # Nothing new found; return the original
            return [base]

        result: List[EndpointModel] = []
        original_method = base.method.value.upper()

        for method, status_code in supported.items():
            # Update status codes on the original
            codes = sorted(set(base.response_codes) | {status_code})

            if method == original_method:
                # Update the existing model's codes
                updated = base.model_copy(
                    update={
                        "response_codes": codes,
                        "supported": True,
                        "observed_status": status_code,
                    }
                )
                result.append(updated)
            else:
                # Clone for the new method
                try:
                    new_ep = base.model_copy(
                        update={
                            "method": HTTPMethod(method),
                            "response_codes": codes,
                            "discovered_by": DiscoveryMethod.METHOD_ENUM,
                            "supported": True,
                            "declared_in_openapi": False,
                            "observed_status": status_code,
                            "description": (
                                f"Discovered via method enumeration — "
                                f"{method} {base.endpoint}"
                            ),
                        }
                    )
                    result.append(new_ep)
                    logger.debug(
                        "New method discovered",
                        method=method,
                        path=base.endpoint,
                        status=status_code,
                    )
                except ValueError:
                    # Unknown method enum value
                    pass

        return result if result else [base]

