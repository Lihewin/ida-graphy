"""Dataflow analysis helpers.

This module is a placeholder for Hex-Rays based dataflow analysis.
"""

import logging
from typing import List

try:
    import ida_hexrays
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

from .raw_data import RawDataAccess

logger = logging.getLogger(__name__)


def extract_dataflow_with_hexrays() -> List[RawDataAccess]:
    """Extract dataflow using Hex-Rays when available.

    Returns an empty list when Hex-Rays is unavailable.
    """
    if not IDA_AVAILABLE:
        logger.debug("Hex-Rays not available; skipping dataflow analysis")
        return []

    # TODO: integrate Hex-Rays ctree visitor to populate RawDataAccess
    return []
