"""
tools/endpoint_guesser.py
=========================
Step 3 of the discovery pipeline — intelligent REST endpoint guessing.

Strategy
--------
Combine a configurable word list with version prefix variations to generate
a set of candidate paths, then probe each with an HTTP GET.  Paths that
return any non-404 response are recorded as discovered.

The word list uses REST naming conventions (plural nouns, action verbs)
and is extended with common sub-resources to maximise coverage:

    /users          → also tries /users/v1, /users/register, etc.
    /books          → also tries /books/v1, /books/{title}

Design
------
* Entirely configuration-driven (no hard-coded paths).
* Deduplicates candidates before probing.
* Returns stub ``EndpointModel`` instances for enrichment by later tools.
* Concurrency-safe: probing is sequential to avoid rate-limiting.
"""

from __future__ import annotations

from typing import List, Optional, Set

from models.endpoint import DiscoveryMethod, EndpointModel, HTTPMethod
from utils.helpers import normalise_path
from utils.http_client import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)

# Response status codes that indicate the endpoint *exists*
# (404 and 405 = known route, wrong method → still exists)
_EXISTENCE_CODES: Set[int] = {
    200, 201, 204,       # Success
    301, 302, 307, 308,  # Redirect — endpoint exists
    400,                 # Bad Request — endpoint exists, bad input
    401, 403,            # Auth failure — endpoint exists
    405,                 # Method Not Allowed — endpoint exists, try other methods
    422,                 # Unprocessable — endpoint exists
    500,                 # Server error — endpoint exists (buggy, but present)
}

# Common sub-resource suffixes appended to each base path
_SUB_RESOURCES = [
    "",
    "/v1",
    "/v2",
    "/register",
    "/login",
    "/logout",
    "/profile",
    "/search",
    "/list",
    "/details",
    "/info",
]

# Parameterised variants to try alongside plain paths
_PARAM_VARIANTS = [
    "/1",
    "/{id}",
]


class EndpointGuesser:
    """
    Probes candidate paths derived from REST naming conventions.

    Parameters
    ----------
    client:
        An ``HTTPClient`` instance.
    wordlist:
        List of base path segments to guess.
    version_prefixes:
        Version path prefixes combined with each wordlist item.
    """

    def __init__(
        self,
        client: HTTPClient,
        wordlist: Optional[List[str]] = None,
        version_prefixes: Optional[List[str]] = None,
    ) -> None:
        from config.settings import settings
        self._client = client
        self._wordlist: List[str] = wordlist or settings.COMMON_WORDLIST
        self._version_prefixes: List[str] = version_prefixes or settings.VERSION_PREFIXES

    # ── Public interface ────────────────────────────────────────────────────

    def guess(self) -> List[EndpointModel]:
        """
        Generate and probe all candidate paths.

        Returns
        -------
        List[EndpointModel]
            Endpoint stubs for all paths that returned a non-404 response.
        """
        candidates = self._generate_candidates()
        logger.info("Endpoint guessing started", total_candidates=len(candidates))

        found: List[EndpointModel] = []
        for path in candidates:
            ep = self._probe_path(path)
            if ep:
                found.append(ep)

        logger.info(
            "Endpoint guessing complete",
            candidates_probed=len(candidates),
            endpoints_found=len(found),
        )
        return found

    # ── Candidate generation ────────────────────────────────────────────────

    def _generate_candidates(self) -> List[str]:
        """
        Build the full set of candidate paths from the word list and
        version prefixes, avoiding duplicates.
        """
        seen: Set[str] = set()
        candidates: List[str] = []

        for prefix in self._version_prefixes:
            for word in self._wordlist:
                # Base: /v1/users
                base = normalise_path(f"{prefix}/{word}")
                self._add_candidate(base, seen, candidates)

                # Sub-resources: /v1/users/register, /v1/users/login, …
                for sub in _SUB_RESOURCES:
                    if sub:  # skip empty (already covered by base)
                        variant = normalise_path(f"{base}{sub}")
                        self._add_candidate(variant, seen, candidates)

                # Parameterised variants: /v1/users/1
                for param in _PARAM_VARIANTS:
                    variant = normalise_path(f"{base}{param}")
                    self._add_candidate(variant, seen, candidates)

        return candidates

    @staticmethod
    def _add_candidate(path: str, seen: Set[str], result: List[str]) -> None:
        """Add *path* to *result* if not already seen."""
        if path not in seen:
            seen.add(path)
            result.append(path)

    # ── Path probing ─────────────────────────────────────────────────────────

    def _probe_path(self, path: str) -> Optional[EndpointModel]:
        """
        Probe a single path with a GET request.

        Parameters
        ----------
        path:
            Normalised URL path.

        Returns
        -------
        EndpointModel | None
            A stub endpoint if the path exists, else ``None``.
        """
        try:
            resp = self._client.get(path)
            code = resp.status_code

            if code == 404:
                return None  # Definitively not found

            logger.debug(
                "Guesser hit",
                path=path,
                status=code,
            )

            return EndpointModel(
                endpoint=path,
                method=HTTPMethod.GET,
                response_codes=[code],
                content_type=resp.content_type or "application/json",
                description=f"Discovered via endpoint guessing — HTTP {code}",
                discovered_by=DiscoveryMethod.GUESSER,
                declared_in_openapi=False,
                supported=True,
                observed_status=code,
                full_url=resp.url,
            )

        except Exception as exc:
            logger.debug("Guesser probe failed", path=path, error=str(exc))
            return None



