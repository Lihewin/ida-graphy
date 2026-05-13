"""Lightweight export manifest generation and verification."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from core.models import GraphData
from .artifact_utils import file_sha256

MANIFEST_FILENAME = "_export_manifest.json"
MANIFEST_VERSION = 1


@dataclass(frozen=True)
class ExportVerificationIssue:
    owner_type: str
    owner_id: str
    path: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "owner_type": self.owner_type,
            "owner_id": self.owner_id,
            "path": self.path,
            "message": self.message,
        }


def write_binary_manifest(
    project_dir: str,
    binary,
    graph_data: GraphData,
    extra_artifacts: Optional[Iterable[Dict[str, str]]] = None,
    binary_name: str = "",
) -> str:
    """Write or update the per-binary manifest without changing graph schema."""
    manifest_binary_name = binary_name or binary.name
    manifest_path = get_manifest_path(project_dir, manifest_binary_name)
    existing_entries = _load_manifest_entries(manifest_path)
    entries = _preserved_extra_entries(existing_entries)
    entries.extend(_extra_entries(extra_artifacts or []))
    entries.extend(_node_entries(project_dir, binary, graph_data))

    manifest = {
        "version": MANIFEST_VERSION,
        "binary": {
            "id": binary.hash,
            "name": binary.name,
            "export_name": manifest_binary_name,
        },
        "entries": _dedupe_entries(entries),
    }

    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    binary.export_manifest_file = _relative_path(project_dir, manifest_path)
    binary.export_manifest_hash = file_sha256(manifest_path)
    return binary.export_manifest_file


def get_manifest_path(project_dir: str, binary_name: str) -> str:
    return os.path.join(project_dir, "exports", binary_name, MANIFEST_FILENAME)


def verify_project_export_paths(project_dir: str, db_path: str) -> Dict[str, object]:
    """Verify DB path attributes against manifests and files without IDA."""
    from database.ladybugdb_manager import LadybugDBManager

    records: List[Dict[str, str]] = []
    with LadybugDBManager(db_path) as db:
        binary_rows = db.query(
            "MATCH (b:Binary) WHERE b.export_manifest_hash <> '' "
            "RETURN b.hash, b.name, b.export_manifest_file, b.export_manifest_hash;"
        )["rows"]
        for binary_id, binary_name, manifest_file, manifest_hash in binary_rows:
            path = str(manifest_file or "") or _relative_path(
                project_dir,
                get_manifest_path(project_dir, str(binary_name)),
            )
            records.append(
                {
                    "owner_type": "Binary",
                    "owner_id": str(binary_id),
                    "binary_name": str(binary_name),
                    "path": path,
                    "manifest_hash": str(manifest_hash or ""),
                }
            )

        function_rows = db.query(
            "MATCH (f:Function) WHERE f.decompiled_file <> '' "
            "RETURN f.uid, f.binary_name, f.decompiled_file, f.pseudocode_hash;"
        )["rows"]
        for uid, binary_name, path, pseudocode_hash in function_rows:
            records.append(
                {
                    "owner_type": "Function",
                    "owner_id": str(uid),
                    "binary_name": str(binary_name),
                    "path": str(path),
                    "pseudocode_hash": str(pseudocode_hash or ""),
                }
            )

        dataslot_rows = db.query(
            "MATCH (d:DataSlot) WHERE d.struct_file <> '' RETURN d.uid, d.struct_file;"
        )["rows"]
        for uid, path in dataslot_rows:
            records.append(
                {
                    "owner_type": "DataSlot",
                    "owner_id": str(uid),
                    "path": str(path),
                    "pseudocode_hash": "",
                }
            )

    return verify_export_records(project_dir, records)


def verify_export_records(project_dir: str, records: Iterable[Dict[str, str]]) -> Dict[str, object]:
    """Verify already-loaded DB export path records against disk manifests."""
    issues: List[ExportVerificationIssue] = []
    manifest_cache: Dict[str, Dict[str, object]] = {}
    checked = 0

    for record in records:
        checked += 1
        owner_type = record.get("owner_type", "")
        owner_id = record.get("owner_id", "")
        raw_path = record.get("path", "")
        pseudocode_hash = record.get("pseudocode_hash", "")

        if not raw_path:
            continue

        artifact_path = _absolute_artifact_path(project_dir, raw_path)
        if not os.path.exists(artifact_path):
            issues.append(
                ExportVerificationIssue(owner_type, owner_id, raw_path, "exported file is missing")
            )
            continue

        if owner_type == "Binary" and record.get("manifest_hash"):
            actual_manifest_hash = file_sha256(artifact_path)
            if actual_manifest_hash != record.get("manifest_hash"):
                issues.append(
                    ExportVerificationIssue(owner_type, owner_id, raw_path, "manifest hash differs from database")
                )
            continue

        manifest_path = _manifest_path_for_record(project_dir, raw_path, record.get("binary_name", ""))
        manifest = manifest_cache.get(manifest_path)
        if manifest is None:
            manifest = _load_manifest(manifest_path)
            manifest_cache[manifest_path] = manifest

        if not manifest:
            issues.append(
                ExportVerificationIssue(owner_type, owner_id, raw_path, "manifest is missing")
            )
            continue

        entry = _find_manifest_entry(manifest.get("entries", []), owner_type, owner_id, raw_path)
        if entry is None:
            issues.append(
                ExportVerificationIssue(owner_type, owner_id, raw_path, "path is not present in manifest")
            )
            continue

        actual_hash = file_sha256(artifact_path)
        expected_hash = str(entry.get("file_hash") or "")
        if expected_hash and actual_hash != expected_hash:
            issues.append(
                ExportVerificationIssue(owner_type, owner_id, raw_path, "file hash differs from manifest")
            )

        expected_pseudocode_hash = str(entry.get("pseudocode_hash") or "")
        if owner_type == "Function" and pseudocode_hash and expected_pseudocode_hash:
            if pseudocode_hash != expected_pseudocode_hash:
                issues.append(
                    ExportVerificationIssue(
                        owner_type,
                        owner_id,
                        raw_path,
                        "Function.pseudocode_hash differs from manifest",
                    )
                )

    issue_dicts = [issue.to_dict() for issue in issues]
    return {
        "ok": not issues,
        "checked": checked,
        "issue_count": len(issues),
        "issues": issue_dicts,
    }


def _node_entries(project_dir: str, binary, graph_data: GraphData) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    for func in graph_data.functions:
        if func.binary_id != binary.hash or not func.decompiled_file:
            continue
        entries.append(
            _manifest_entry(
                project_dir,
                owner_type="Function",
                owner_id=func.uid,
                artifact_type=_function_artifact_type(func.decompiled_file),
                path=func.decompiled_file,
                pseudocode_hash=func.pseudocode_hash or "",
            )
        )

    for slot in graph_data.dataslots:
        if slot.is_global or not slot.struct_file:
            continue
        entries.append(
            _manifest_entry(
                project_dir,
                owner_type="DataSlot",
                owner_id=slot.uid,
                artifact_type="structure",
                path=slot.struct_file,
            )
        )

    return entries


def _extra_entries(artifacts: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    for artifact in artifacts:
        path = artifact.get("path", "")
        if not path:
            continue
        entries.append(
            {
                "owner_type": artifact.get("owner_type", ""),
                "owner_id": artifact.get("owner_id", ""),
                "artifact_type": artifact.get("artifact_type", ""),
                "path": path,
                "file_hash": artifact.get("hash", ""),
                "pseudocode_hash": artifact.get("pseudocode_hash", ""),
                "status": artifact.get("status", "exported"),
                "error": artifact.get("error", ""),
            }
        )
    return entries


def _manifest_entry(
    project_dir: str,
    owner_type: str,
    owner_id: str,
    artifact_type: str,
    path: str,
    pseudocode_hash: str = "",
) -> Dict[str, str]:
    return {
        "owner_type": owner_type,
        "owner_id": owner_id,
        "artifact_type": artifact_type,
        "path": path,
        "file_hash": file_sha256(_absolute_artifact_path(project_dir, path)),
        "pseudocode_hash": pseudocode_hash,
        "status": "exported",
        "error": "",
    }


def _function_artifact_type(path: str) -> str:
    return "ghidra_decompile" if "/ghidra_decompile/" in path.replace("\\", "/") else "decompile"


def _preserved_extra_entries(entries: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    return [
        entry
        for entry in entries
        if entry.get("owner_type") == "Binary" or entry.get("status") in {"failed", "skipped"}
    ]


def _dedupe_entries(entries: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    by_key: Dict[tuple, Dict[str, str]] = {}
    for entry in entries:
        key = (
            entry.get("owner_type", ""),
            entry.get("owner_id", ""),
            entry.get("artifact_type", ""),
            entry.get("path", ""),
        )
        by_key[key] = entry
    return sorted(
        by_key.values(),
        key=lambda entry: (
            entry.get("owner_type", ""),
            entry.get("owner_id", ""),
            entry.get("artifact_type", ""),
            entry.get("path", ""),
        ),
    )


def _load_manifest_entries(manifest_path: str) -> List[Dict[str, str]]:
    manifest = _load_manifest(manifest_path)
    entries = manifest.get("entries", []) if manifest else []
    return [entry for entry in entries if isinstance(entry, dict)]


def _load_manifest(manifest_path: str) -> Dict[str, object]:
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        return manifest if isinstance(manifest, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        return {}


def _find_manifest_entry(
    entries: Iterable[Dict[str, object]],
    owner_type: str,
    owner_id: str,
    path: str,
) -> Optional[Dict[str, object]]:
    normalized_path = path.replace("\\", "/")
    for entry in entries:
        entry_path = str(entry.get("path") or "").replace("\\", "/")
        if (
            entry_path == normalized_path
            and entry.get("owner_type") == owner_type
            and entry.get("owner_id") == owner_id
        ):
            return entry
    return None


def _manifest_path_for_record(project_dir: str, path: str, binary_name: str = "") -> str:
    normalized = _relative_record_path(project_dir, path)
    parts = normalized.split("/")
    if len(parts) >= 2 and parts[0] == "exports":
        return get_manifest_path(project_dir, parts[1])
    if binary_name:
        return get_manifest_path(project_dir, binary_name)
    return os.path.join(project_dir, MANIFEST_FILENAME)


def _absolute_artifact_path(project_dir: str, path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(project_dir, path)


def _relative_record_path(project_dir: str, path: str) -> str:
    if os.path.isabs(path):
        try:
            return os.path.relpath(path, project_dir).replace("\\", "/")
        except ValueError:
            return path.replace("\\", "/")
    return path.replace("\\", "/")


def _relative_path(project_dir: str, path: str) -> str:
    return os.path.relpath(path, project_dir).replace("\\", "/")
