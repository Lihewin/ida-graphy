"""IDA adapter helpers.

Provides lightweight checks and shared helpers for IDA APIs.
"""

import logging

try:
    import idaapi
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

logger = logging.getLogger(__name__)


def is_ida_available() -> bool:
    """Return True if running under IDA/idalib."""
    return IDA_AVAILABLE


def require_ida() -> None:
    """Raise if IDA APIs are unavailable."""
    if not IDA_AVAILABLE:
        raise RuntimeError("IDA SDK not available")
