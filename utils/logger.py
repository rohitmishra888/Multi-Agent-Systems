"""
utils/logger.py
===============
Structured, production-quality logging for the API Discovery platform.

Design goals
------------
* Single ``get_logger`` factory — every module calls it with ``__name__``.
* Level driven by ``settings.LOG_LEVEL`` so DEBUG/INFO/WARNING toggles at runtime.
* JSON-serialisable format to facilitate log aggregation (ELK, Cloud Logging, etc.).
* Context-enrichment helpers for binding request-scoped fields (url, method, …).

Usage
-----
    from utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Endpoint discovered", url="/users/v1", method="GET")
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from config.settings import settings


# ---------------------------------------------------------------------------
# Custom JSON-ish formatter
# ---------------------------------------------------------------------------

class _StructuredFormatter(logging.Formatter):
    """
    Formats a ``LogRecord`` as a compact key=value line that is both
    human-readable and trivially parseable by log shippers.

    Example output::

        2024-01-15T12:00:01Z [INFO ] utils.http_client | Sending request url=http://localhost:5000/users/v1 method=GET
    """

    _DATEFMT = "%Y-%m-%dT%H:%M:%SZ"

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        # Base fields
        ts = self.formatTime(record, self._DATEFMT)
        level = f"{record.levelname:<8}"
        name = record.name

        # Main message
        message = record.getMessage()

        # Any extra key=value pairs attached by the caller
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k
            not in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "taskName",
            }
        }

        extra_str = ""
        if extras:
            parts = [f"{k}={v!r}" for k, v in extras.items()]
            extra_str = " | " + " ".join(parts)

        # Exception traceback (if present)
        exc_str = ""
        if record.exc_info:
            exc_str = "\n" + self.formatException(record.exc_info)

        return f"{ts} [{level}] {name} | {message}{extra_str}{exc_str}"


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def _build_handler() -> logging.StreamHandler:
    """Create and configure the stdout stream handler."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_StructuredFormatter())
    return handler


# Module-level flag to ensure we only configure the root handler once.
_CONFIGURED: bool = False


def _configure_root_logger() -> None:
    """Idempotently attach our handler to the root logger."""
    global _CONFIGURED  # noqa: PLW0603
    if _CONFIGURED:
        return

    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.LOG_LEVEL, logging.INFO))

    # Avoid duplicate handlers if someone else already attached one.
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        root.addHandler(_build_handler())

    # Silence overly chatty third-party libraries.
    for noisy in ("httpx", "httpcore", "urllib3", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


class _KwargsAdapter(logging.LoggerAdapter):
    """
    A ``LoggerAdapter`` that accepts arbitrary keyword arguments and
    injects them into the ``extra`` dict so the ``_StructuredFormatter``
    can render them as key=value pairs.

    This allows callers to write::

        logger.info("Request sent", url="/users", method="GET")

    instead of the verbose::

        logger.info("Request sent", extra={"url": "/users", "method": "GET"})
    """

    def process(self, msg, kwargs):
        # kwargs here is the logging call kwargs dict (not our extra fields)
        # Pull out any 'extra' already provided, then merge with adapter's extra
        extra = dict(self.extra or {})
        extra.update(kwargs.pop("extra", {}))
        kwargs["extra"] = extra
        return msg, kwargs

    # Override the four common log levels to accept **kw as extra fields
    def debug(self, msg, *args, **kw):  # noqa: D401
        extra = kw.pop("exc_info", None)
        ei = {"exc_info": extra} if extra is not None else {}
        self.log(logging.DEBUG, msg, *args, extra=kw, **ei)

    def info(self, msg, *args, **kw):  # noqa: D401
        extra = kw.pop("exc_info", None)
        ei = {"exc_info": extra} if extra is not None else {}
        self.log(logging.INFO, msg, *args, extra=kw, **ei)

    def warning(self, msg, *args, **kw):  # noqa: D401
        extra = kw.pop("exc_info", None)
        ei = {"exc_info": extra} if extra is not None else {}
        self.log(logging.WARNING, msg, *args, extra=kw, **ei)

    def error(self, msg, *args, **kw):  # noqa: D401
        extra = kw.pop("exc_info", None)
        ei = {"exc_info": extra} if extra is not None else {}
        self.log(logging.ERROR, msg, *args, extra=kw, **ei)

    def exception(self, msg, *args, **kw):  # noqa: D401
        kw.setdefault("exc_info", True)
        self.error(msg, *args, **kw)

    def log(self, level, msg, *args, **kw):  # noqa: D401
        # Extract special logging kwargs, rest go to extra
        exc_info = kw.pop("exc_info", None)
        stack_info = kw.pop("stack_info", None)
        stacklevel = kw.pop("stacklevel", 1)
        extra = kw  # remaining kwargs are structured context fields
        if self.isEnabledFor(level):
            self.logger._log(
                level, msg, args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                stacklevel=stacklevel + 1,
            )


def get_logger(name: str) -> "_KwargsAdapter":
    """
    Return a named logger configured for structured output.

    The returned adapter accepts arbitrary keyword arguments as structured
    context fields::

        logger = get_logger(__name__)
        logger.info("Discovery started", target="http://localhost:5000")

    Parameters
    ----------
    name:
        Typically ``__name__`` of the calling module.

    Returns
    -------
    _KwargsAdapter
        A configured logger adapter.
    """
    _configure_root_logger()
    return _KwargsAdapter(logging.getLogger(name), {})


class LogContext:
    """
    A thin helper that wraps a logger and automatically injects fixed
    key=value context into every log call — similar to structlog bindings.

    Example
    -------
    >>> ctx = LogContext(get_logger(__name__), endpoint="/users/v1", method="GET")
    >>> ctx.info("Endpoint analysed")
    # → … | Endpoint analysed | endpoint='/users/v1' method='GET'
    """

    def __init__(self, logger: logging.Logger, **context: Any) -> None:
        self._logger = logger
        self._context = context

    # Delegate the four common levels ----------------------------------------
    def debug(self, msg: str, **extra: Any) -> None:  # noqa: D401
        self._logger.debug(msg, extra={**self._context, **extra})

    def info(self, msg: str, **extra: Any) -> None:  # noqa: D401
        self._logger.info(msg, extra={**self._context, **extra})

    def warning(self, msg: str, **extra: Any) -> None:  # noqa: D401
        self._logger.warning(msg, extra={**self._context, **extra})

    def error(self, msg: str, **extra: Any) -> None:  # noqa: D401
        self._logger.error(msg, extra={**self._context, **extra})

    def exception(self, msg: str, **extra: Any) -> None:  # noqa: D401
        self._logger.exception(msg, extra={**self._context, **extra})
