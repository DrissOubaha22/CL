"""Structured logging setup.

Logs carry CVE ids and feed names; they must never carry client-identifying
data (spec §11).  Nothing in the intel path has access to tenant data, which
is what keeps that true here.
"""

from __future__ import annotations

import logging
import sys

import structlog

from aegis.config import get_settings

_configured = False


def configure_logging(*, force: bool = False) -> None:
    """Install the structlog pipeline once per process."""
    global _configured
    if _configured and not force:
        return

    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if settings.log_json
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    _configured = True
