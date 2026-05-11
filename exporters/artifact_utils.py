"""Shared helpers for exported artifact manifests."""

import hashlib
import os
from typing import Dict, Optional


def relative_artifact_path(output_dir: str, filepath: str) -> str:
    """Return a stable project-relative artifact path."""
    return os.path.relpath(filepath, output_dir).replace("\\", "/")


def file_sha256(filepath: str) -> str:
    """Return SHA-256 for an existing file, or an empty string if unavailable."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


def sanitize_filename(name: str, max_length: int = 100) -> str:
    """Sanitize function/type names for export filenames."""
    sanitized = "".join(
        ch if ch.isascii() and (ch.isalnum() or ch in "._-") else "_"
        for ch in name
    )
    return (sanitized or "function")[:max_length]


def artifact_record(
    output_dir: str,
    owner_id: str,
    owner_type: str,
    artifact_type: str,
    filepath: str,
    status: str = "exported",
    error: str = "",
    content_hash: Optional[str] = None,
) -> Dict[str, str]:
    """Build the normalized manifest row consumed by ExportManager."""
    return {
        "owner_id": owner_id,
        "owner_type": owner_type,
        "artifact_type": artifact_type,
        "path": relative_artifact_path(output_dir, filepath),
        "hash": content_hash if content_hash is not None else file_sha256(filepath),
        "status": status,
        "error": error,
    }
