"""
agents/discovery_agent.py
==========================
Defines the CrewAI ``Agent`` and ``Task`` for the API Discovery Specialist.

The agent does not directly call HTTP endpoints itself — instead it delegates
to the ``DiscoveryService`` via a set of CrewAI-compatible tool functions.

Architecture
------------
CrewAI orchestrates the agent and provides it with:
- A role, goal, and backstory (LLM persona)
- A set of ``@tool``-decorated functions it can invoke

The LLM guides *which* tools to call and *how to interpret* results.
The actual HTTP work is done by the service layer.

Tools exposed to the agent
--------------------------
- ``discover_openapi``        → Step 1: Swagger/OpenAPI parsing
- ``crawl_application``       → Step 2: HTTP crawling
- ``guess_endpoints``         → Step 3: Endpoint guessing
- ``analyse_endpoint``        → Step 4: Response analysis for one endpoint
- ``enumerate_methods``       → Step 5: Method enumeration for one endpoint
- ``get_discovery_summary``   → Query current discovery state
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List

from crewai import Agent, Task
from crewai.tools import tool

from models.endpoint import EndpointModel
from services.discovery_service import DiscoveryService
from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Module-level discovery service instance
# (populated when create_discovery_agent is called)
# ---------------------------------------------------------------------------
_service: DiscoveryService | None = None
_discovered: List[EndpointModel] = []


def _get_service() -> DiscoveryService:
    """Return the module-level DiscoveryService, raising if not initialised."""
    if _service is None:
        raise RuntimeError(
            "DiscoveryService not initialised. "
            "Call create_discovery_agent() before using agent tools."
        )
    return _service


# ---------------------------------------------------------------------------
# CrewAI tool functions
# ---------------------------------------------------------------------------

@tool("Discover OpenAPI Specification")
def discover_openapi(target_url: str) -> str:
    """
    Probe the target application for an OpenAPI/Swagger specification.

    Checks common paths such as /swagger.json, /openapi.json, /docs, /redoc.
    Extracts all endpoint definitions, schemas, parameters, and authentication
    requirements from the specification if found.

    Args:
        target_url: The base URL of the target API application.

    Returns:
        JSON string summarising discovered endpoints and whether a spec was found.
    """
    logger.info("Tool: discover_openapi", target_url=target_url)
    svc = _get_service()

    try:
        endpoints, spec_url = svc._swagger_parser.parse()
        _discovered.extend(endpoints)

        result = {
            "spec_found": spec_url is not None,
            "spec_url": spec_url,
            "endpoints_discovered": len(endpoints),
            "endpoints": [
                {"method": e.method.value, "path": e.endpoint}
                for e in endpoints[:20]  # Limit for LLM context
            ],
        }
        logger.info(
            "discover_openapi complete",
            spec_found=result["spec_found"],
            endpoints=result["endpoints_discovered"],
        )
        return json.dumps(result, indent=2)

    except Exception as exc:
        logger.error("discover_openapi failed", error=str(exc))
        return json.dumps({"error": str(exc), "endpoints_discovered": 0})


@tool("Crawl Application for API Paths")
def crawl_application(target_url: str) -> str:
    """
    Crawl the target application's HTML pages, JavaScript files, and JSON
    responses to discover embedded API endpoint paths.

    Follows internal links and scans for fetch(), axios, and XHR patterns.

    Args:
        target_url: The base URL of the target API application.

    Returns:
        JSON string summarising paths discovered through crawling.
    """
    logger.info("Tool: crawl_application", target_url=target_url)
    svc = _get_service()

    try:
        endpoints = svc._crawler.crawl()
        # Avoid adding duplicates
        known_paths = {e.endpoint for e in _discovered}
        new_endpoints = [e for e in endpoints if e.endpoint not in known_paths]
        _discovered.extend(new_endpoints)

        result = {
            "paths_found": len(endpoints),
            "new_paths": len(new_endpoints),
            "paths": [e.endpoint for e in endpoints[:30]],
        }
        logger.info(
            "crawl_application complete",
            paths_found=result["paths_found"],
            new=result["new_paths"],
        )
        return json.dumps(result, indent=2)

    except Exception as exc:
        logger.error("crawl_application failed", error=str(exc))
        return json.dumps({"error": str(exc), "paths_found": 0})


@tool("Guess Common REST Endpoints")
def guess_endpoints(target_url: str) -> str:
    """
    Probe a list of common REST API endpoint paths derived from REST naming
    conventions. Records any path that returns a non-404 HTTP response.

    Args:
        target_url: The base URL of the target API application.

    Returns:
        JSON string listing discovered endpoints.
    """
    logger.info("Tool: guess_endpoints", target_url=target_url)
    svc = _get_service()

    try:
        endpoints = svc._guesser.guess()
        known_paths = {e.endpoint for e in _discovered}
        new_endpoints = [e for e in endpoints if e.endpoint not in known_paths]
        _discovered.extend(new_endpoints)

        result = {
            "endpoints_found": len(endpoints),
            "new_endpoints": len(new_endpoints),
            "endpoints": [
                {"method": e.method.value, "path": e.endpoint, "status": e.response_codes}
                for e in endpoints[:30]
            ],
        }
        logger.info(
            "guess_endpoints complete",
            found=result["endpoints_found"],
            new=result["new_endpoints"],
        )
        return json.dumps(result, indent=2)

    except Exception as exc:
        logger.error("guess_endpoints failed", error=str(exc))
        return json.dumps({"error": str(exc), "endpoints_found": 0})


@tool("Analyse Endpoint Response")
def analyse_endpoint(path: str, method: str = "GET") -> str:
    """
    Analyse the HTTP response for a specific endpoint to extract metadata:
    status codes, content type, security headers, response schema, and
    sample response payload.

    Args:
        path: The URL path to analyse (e.g., '/users/v1').
        method: HTTP method to use (default: GET).

    Returns:
        JSON string with extracted response metadata.
    """
    logger.info("Tool: analyse_endpoint", path=path, method=method)
    svc = _get_service()

    try:
        from models.endpoint import EndpointModel, HTTPMethod

        # Find or create an endpoint model for this path
        ep = next(
            (e for e in _discovered if e.endpoint == path and e.method.value == method.upper()),
            None,
        )
        if ep is None:
            ep = EndpointModel(endpoint=path, method=HTTPMethod(method.upper()))

        enriched = svc._response_analyzer.analyse(ep)

        result = {
            "path": path,
            "method": method.upper(),
            "status_codes": enriched.response_codes,
            "content_type": enriched.content_type,
            "response_headers": enriched.response_headers,
            "response_fields": enriched.response_fields,
            "has_schema": enriched.response_schema is not None,
        }
        return json.dumps(result, indent=2)

    except Exception as exc:
        logger.error("analyse_endpoint failed", path=path, error=str(exc))
        return json.dumps({"error": str(exc), "path": path})


@tool("Enumerate HTTP Methods for Endpoint")
def enumerate_methods(path: str) -> str:
    """
    Probe all standard HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS,
    HEAD) for a specific endpoint to determine which are supported.

    Args:
        path: The URL path to enumerate methods for (e.g., '/users/v1').

    Returns:
        JSON string listing supported methods and their response codes.
    """
    logger.info("Tool: enumerate_methods", path=path)
    svc = _get_service()

    try:
        from models.endpoint import EndpointModel, HTTPMethod

        base_ep = next(
            (e for e in _discovered if e.endpoint == path),
            EndpointModel(endpoint=path, method=HTTPMethod.GET),
        )

        variants = svc._method_enumerator.enumerate(base_ep)

        result = {
            "path": path,
            "supported_methods": [
                {"method": v.method.value, "status_codes": v.response_codes}
                for v in variants
            ],
        }
        return json.dumps(result, indent=2)

    except Exception as exc:
        logger.error("enumerate_methods failed", path=path, error=str(exc))
        return json.dumps({"error": str(exc), "path": path})


@tool("Get Discovery Summary")
def get_discovery_summary(query: str = "") -> str:
    """
    Return a summary of all endpoints discovered so far, including counts
    by method, category, and risk level.

    Args:
        query: Optional filter string (currently unused; included for extensibility).

    Returns:
        JSON string with discovery summary statistics.
    """
    logger.info("Tool: get_discovery_summary")

    result = {
        "total_endpoints": len(_discovered),
        "endpoints": [
            {
                "method": e.method.value,
                "path": e.endpoint,
                "auth_required": e.authentication_required,
                "discovered_by": e.discovered_by.value,
            }
            for e in _discovered[:50]
        ],
    }
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------

def create_discovery_agent(service: DiscoveryService) -> Agent:
    """
    Create and return the API Discovery Specialist CrewAI agent.

    This function also wires the provided ``DiscoveryService`` into the
    module-level ``_service`` variable used by the tool functions.

    Parameters
    ----------
    service:
        Fully configured ``DiscoveryService`` instance.

    Returns
    -------
    crewai.Agent
        The configured CrewAI agent.
    """
    global _service, _discovered  # noqa: PLW0603
    _service = service
    _discovered = []

    agent = Agent(
        role="Security Researcher",
        goal=(
            "Discover all API endpoints exposed by the target REST application "
            "and generate a comprehensive API inventory with security metadata. "
            "Use every available discovery technique to ensure complete coverage: "
            "OpenAPI specification parsing, HTTP crawling, endpoint guessing, "
            "response analysis, and method enumeration."
        ),
        backstory=(
            "You are an expert API reconnaissance engineer with 15 years of "
            "experience in discovering undocumented APIs, parsing OpenAPI "
            "specifications, analysing HTTP traffic, detecting authentication "
            "mechanisms, extracting metadata, identifying API relationships, "
            "and building comprehensive API inventories used for automated "
            "security testing. You are methodical, thorough, and leave no "
            "endpoint undiscovered."
        ),
        tools=[
            discover_openapi,
            crawl_application,
            guess_endpoints,
            analyse_endpoint,
            enumerate_methods,
            get_discovery_summary,
        ],
        verbose=True,
        allow_delegation=False,
        max_iter=20,
        respect_context_window=True,
        use_system_prompt=False,   # Gemini: merge system prompt into first user message
    )


    logger.info("API Discovery Specialist agent created")
    return agent


def create_discovery_task(agent: Agent, target_url: str) -> Task:
    """
    Create the discovery task assigned to the API Discovery Specialist.

    Parameters
    ----------
    agent:
        The ``API Discovery Specialist`` agent.
    target_url:
        The base URL of the target application.

    Returns
    -------
    crewai.Task
        The configured CrewAI task.
    """
    task = Task(
        description=(
            f"Perform a complete API discovery scan of the target application at: {target_url}\n\n"
            "Execute the following steps in order:\n"
            f"1. Call discover_openapi with target_url='{target_url}' to check for an OpenAPI/Swagger spec.\n"
            f"2. Call crawl_application with target_url='{target_url}' to find paths via crawling.\n"
            f"3. Call guess_endpoints with target_url='{target_url}' to find additional endpoints via guessing.\n"
            "4. For each discovered endpoint path, call analyse_endpoint to extract response metadata.\n"
            "5. For each unique path, call enumerate_methods to find all supported HTTP methods.\n"
            "6. Call get_discovery_summary to review the final inventory.\n\n"
            "Return a JSON summary of all discovered endpoints with their methods, "
            "authentication requirements, categories, and risk levels."
        ),
        expected_output=(
            "A comprehensive JSON report listing all discovered API endpoints. "
            "Each endpoint must include: path, HTTP method, authentication status, "
            "response codes, content type, and preliminary risk assessment. "
            "The report must also include total counts by method, category, and risk level."
        ),
        agent=agent,
    )

    logger.info("Discovery task created", target=target_url)
    return task
