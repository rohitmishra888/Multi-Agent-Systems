"""
config/settings.py
==================
Centralised, environment-driven configuration for the API Discovery platform.

All settings are read exclusively from environment variables or a .env file.
No value is hard-coded here — only *default* values for non-sensitive options.

Design: pydantic-settings (BaseSettings) gives us type coercion, validation,
and a single source of truth that the rest of the application imports from.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application-wide configuration loaded from environment variables.

    Precedence (highest → lowest):
      1. Actual OS environment variables
      2. Values defined in the .env file
      3. Default values declared below
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,   # BASE_URL == base_url
        extra="ignore",         # Ignore unknown env vars silently
    )

    # ── Target application ──────────────────────────────────────────────────
    BASE_URL: str = Field(
        default="http://localhost:5000",
        description="Base URL of the target API application (VAmPI).",
    )

    # ── HTTP client behaviour ───────────────────────────────────────────────
    REQUEST_TIMEOUT: int = Field(
        default=10,
        ge=1,
        le=120,
        description="Per-request timeout in seconds.",
    )
    MAX_RETRIES: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum number of retry attempts for transient failures.",
    )
    RETRY_BACKOFF_FACTOR: float = Field(
        default=0.5,
        ge=0.0,
        description="Exponential back-off factor between retries (seconds).",
    )

    # ── Logging ─────────────────────────────────────────────────────────────
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Python logging level: DEBUG | INFO | WARNING | ERROR | CRITICAL.",
    )

    # ── Output ──────────────────────────────────────────────────────────────
    OUTPUT_DIRECTORY: str = Field(
        default="reports",
        description="Directory where catalog.json and catalog.yaml are written.",
    )

    # ── Discovery tuning ────────────────────────────────────────────────────
    SWAGGER_PROBE_PATHS: List[str] = Field(
        default=[
            "/swagger",
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
            "/docs",
            "/api/docs",
            "/redoc",
            "/v1/swagger.json",
            "/v2/swagger.json",
            "/v3/swagger.json",
        ],
        description="Ordered list of paths probed during OpenAPI/Swagger discovery.",
    )

    COMMON_WORDLIST: List[str] = Field(
        default=[
            # Authentication / session
            "login",
            "logout",
            "register",
            "auth",
            "oauth",
            "token",
            "refresh",
            "verify",
            "reset-password",
            "forgot-password",
            # User resources
            "users",
            "user",
            "profile",
            "account",
            "accounts",
            "me",
            "admin",
            # Book / content resources (VAmPI-specific generalisation)
            "books",
            "book",
            "items",
            "products",
            "catalog",
            "categories",
            # Health / meta
            "health",
            "status",
            "ping",
            "version",
            "info",
            "metrics",
            "api",
        ],
        description="Common path segments used during endpoint guessing.",
    )

    # Version prefixes to combine with wordlist items during guessing
    VERSION_PREFIXES: List[str] = Field(
        default=["", "/v1", "/v2", "/api/v1", "/api/v2"],
        description="API version path prefixes tried during endpoint guessing.",
    )

    # ── LLM / CrewAI ────────────────────────────────────────────────────────
    OPENAI_API_KEY: str = Field(
        default="",
        description="OpenAI API key for CrewAI LLM backend. Leave blank when using Gemini.",
    )
    OPENAI_MODEL_NAME: str = Field(
        default="gpt-4o-mini",
        description="OpenAI model name (only used when OPENAI_API_KEY is set).",
    )
    GEMINI_API_KEY: str = Field(
        default="",
        description="Google Gemini API key for LiteLLM routing. Get one free at https://aistudio.google.com/apikey",
    )
    LLM_MODEL: str = Field(
        default="gemini/gemini-2.5-flash",
        description="LiteLLM model string, e.g. gemini/gemini-2.5-flash or gpt-4o-mini.",
    )


    # ── Computed helpers (properties, not env fields) ────────────────────────
    @field_validator("LOG_LEVEL")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}, got '{v}'")
        return upper

    @property
    def output_dir(self) -> Path:
        """Resolved Path object for the output directory."""
        return Path(self.OUTPUT_DIRECTORY)

    @property
    def base_url(self) -> str:
        """Normalised base URL with trailing slash stripped."""
        return self.BASE_URL.rstrip("/")


# ---------------------------------------------------------------------------
# Module-level singleton — import and use `settings` everywhere.
# ---------------------------------------------------------------------------
settings = Settings()
