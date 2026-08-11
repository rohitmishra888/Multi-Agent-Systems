"""
config/__init__.py
==================
Makes `config` a proper Python package and re-exports the singleton `settings`
so callers can write:

    from config import settings

instead of:

    from config.settings import settings
"""

from config.settings import settings  # noqa: F401

__all__ = ["settings"]
