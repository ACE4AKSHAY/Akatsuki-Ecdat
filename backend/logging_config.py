"""Structured logging for the ECDAT API.

Every log line is a single JSON object so that log aggregators can index
it without regular expressions. A request id is attached to every record
emitted while handling a request, which lets an operator join an access
log entry, an application log line and a client-reported failure.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict

_request_id: ContextVar[str] = ContextVar("ecdat_request_id", default="-")


def set_request_id(request_id: str) -> None:
    _request_id.set(request_id)


def get_request_id() -> str:
    return _request_id.get()


class JsonFormatter(logging.Formatter):
    """Render records as one-line JSON documents."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "requestId": getattr(record, "request_id", None) or get_request_id(),
        }
        for key, value in getattr(record, "context", {}).items():
            if key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable single line, used for local development."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="seconds")
        request_id = getattr(record, "request_id", None) or get_request_id()
        base = f"{stamp} {record.levelname:<7} {record.name} [{request_id}] {record.getMessage()}"
        context = getattr(record, "context", {})
        if context:
            base += " " + " ".join(f"{k}={v}" for k, v in context.items())
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def configure_logging() -> None:
    """Install the configured root handler. Safe to call more than once."""
    level_name = os.getenv("ECDAT_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = os.getenv("ECDAT_LOG_FORMAT", "json").strip().lower()
    formatter = JsonFormatter() if fmt == "json" else TextFormatter()

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn keeps its own handlers; route them through the same formatter.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True
