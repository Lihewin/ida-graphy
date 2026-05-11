"""Unified export manager for graph data."""

import hashlib
import logging
import os
from typing import Dict, Iterable, Optional

from core.models import ExportArtifactNode, GraphData, HasArtifactEdge
from core.project.metadata import ProjectMetadata
from . import file_exporter
from . import ghidra_fallback
from .ladybugdb_exporter import LadybugDBExporter, create_ladybugdb_exporter

logger = logging.getLogger(__name__)


class ExportManager:
    """Unified export manager for LadybugDB and file exports."""

    def __init__(self, config: Dict, project_metadata: ProjectMetadata):
        self.config = config or {}
        self.project_metadata = project_metadata
        self.ladybugdb_exporter: Optional[LadybugDBExporter] = create_ladybugdb_exporter(self.config)

    def export_all(self, graph_data: GraphData, binary_path: str):
        """Export to LadybugDB and optional file exports."""
        if self._should_export_files() and binary_path:
            self.export_files(binary_path, graph_data)

        self.export_to_ladybugdb(graph_data)

    def export_to_ladybugdb(self, graph_data: GraphData) -> Dict[str, int]:
        if not self.ladybugdb_exporter:
            raise RuntimeError("LadybugDB exporter unavailable")
        return self.ladybugdb_exporter.export_to_ladybugdb(self._get_graph_db_path(), graph_data, rebuild=True)

    def export_files(self, binary_path: str, graph_data: GraphData):
        output_dir = self._get_project_dir()
        binary_name = os.path.basename(binary_path)
        exporter = file_exporter.FileExporter(output_dir, graph_data, binary_name=binary_name)
        if not file_exporter.IDA_AVAILABLE:
            logger.warning("IDA not available, skipping file export")
            return {}

        results = exporter.export_all()
        self._backfill_export_results(graph_data, binary_name, results)
        return results

    def export_ghidra_fallbacks(self, binary_path: str, graph_data: GraphData):
        """Run Ghidra fallback for queued hard limits after the IDA DB is closed."""
        if not graph_data.ghidra_fallbacks:
            return []

        output_dir = self._get_project_dir()
        artifacts = ghidra_fallback.export_ghidra_fallbacks(
            self.config,
            output_dir,
            binary_path,
            graph_data,
        )
        self._backfill_ghidra_artifacts(graph_data, os.path.basename(binary_path), artifacts)
        return artifacts

    def _backfill_ghidra_artifacts(
        self,
        graph_data: GraphData,
        binary_name: str,
        artifacts,
    ) -> None:
        if not artifacts:
            return

        binary = self._find_binary(graph_data, binary_name)
        if not binary:
            logger.warning("No Binary node found for Ghidra fallback artifacts: %s", binary_name)
            return

        function_by_uid = {func.uid: func for func in graph_data.functions}
        artifact_uids = {artifact.uid for artifact in graph_data.export_artifacts}
        artifact_edges = {(edge.from_id, edge.to_id) for edge in graph_data.has_artifact}

        for artifact in artifacts:
            func = function_by_uid.get(artifact.get("owner_id", ""))
            if func and artifact.get("status") == "exported":
                func.decompiled_file = artifact.get("path", "")
                func.pseudocode_hash = artifact.get("hash", "")
            self._add_artifact(
                graph_data,
                binary,
                artifact,
                edge_from_ids=[artifact.get("owner_id", "")],
                artifact_uids=artifact_uids,
                artifact_edges=artifact_edges,
            )

    def _backfill_export_results(self, graph_data: GraphData, binary_name: str, results: Dict) -> None:
        binary = self._find_binary(graph_data, binary_name)
        if not binary:
            logger.warning("No Binary node found for export artifacts: %s", binary_name)
            return

        artifact_uids = {artifact.uid for artifact in graph_data.export_artifacts}
        artifact_edges = {(edge.from_id, edge.to_id) for edge in graph_data.has_artifact}

        function_result = results.get("functions")
        if function_result:
            function_by_uid = {func.uid: func for func in graph_data.functions}
            for uid, mapping in function_result.file_mapping.items():
                func = function_by_uid.get(uid)
                if not func:
                    continue
                func.decompiled_file = mapping.get("path", "")
                func.pseudocode_hash = mapping.get("hash", "")

            for artifact in function_result.artifacts:
                self._add_artifact(
                    graph_data,
                    binary,
                    artifact,
                    edge_from_ids=[artifact["owner_id"]],
                    artifact_uids=artifact_uids,
                    artifact_edges=artifact_edges,
                )

        structure_result = results.get("structures")
        if structure_result:
            struct_slots = self._build_struct_slot_index(graph_data)
            for type_name, mapping in structure_result.file_mapping.items():
                matching_slots = struct_slots.get(type_name, [])
                for slot in matching_slots:
                    slot.struct_file = mapping.get("path", "")

            for artifact in structure_result.artifacts:
                if artifact.get("artifact_type") == "structure":
                    type_name = artifact["owner_id"]
                    roots = [
                        slot.uid
                        for slot in struct_slots.get(type_name, [])
                        if int(slot.offset) == -1
                    ]
                    # Attach all structure exports to the Binary for discovery.
                    # Individual members get `struct_file` directly; only struct roots
                    # get HAS_ARTIFACT edges to avoid exploding edge counts.
                    edge_ids = [binary.hash] + roots
                    self._add_artifact(
                        graph_data,
                        binary,
                        artifact,
                        edge_from_ids=edge_ids,
                        artifact_uids=artifact_uids,
                        artifact_edges=artifact_edges,
                    )
                else:
                    self._add_artifact(
                        graph_data,
                        binary,
                        artifact,
                        edge_from_ids=[binary.hash],
                        owner_id=binary.hash,
                        owner_type="Binary",
                        artifact_uids=artifact_uids,
                        artifact_edges=artifact_edges,
                    )

        for key in ("strings", "imports", "exports"):
            artifact = results.get(key)
            if artifact:
                self._add_artifact(
                    graph_data,
                    binary,
                    artifact,
                    edge_from_ids=[binary.hash],
                    owner_id=binary.hash,
                    owner_type="Binary",
                    artifact_uids=artifact_uids,
                    artifact_edges=artifact_edges,
                )

    def _find_binary(self, graph_data: GraphData, binary_name: str):
        for binary in graph_data.binaries:
            if binary.name == binary_name:
                return binary
        return graph_data.binaries[0] if graph_data.binaries else None

    def _matching_struct_slots(self, graph_data: GraphData, type_name: str):
        return [
            slot
            for slot in graph_data.dataslots
            if not slot.is_global and (slot.base_type_orig == type_name or slot.base_type == type_name)
        ]

    def _build_struct_slot_index(self, graph_data: GraphData):
        index = {}
        for slot in graph_data.dataslots:
            if slot.is_global:
                continue
            for key in {slot.base_type_orig, slot.base_type}:
                if key:
                    index.setdefault(key, []).append(slot)
        return index

    def _add_artifact(
        self,
        graph_data: GraphData,
        binary,
        artifact: Dict[str, str],
        edge_from_ids: Iterable[str],
        artifact_uids,
        artifact_edges,
        owner_id: Optional[str] = None,
        owner_type: Optional[str] = None,
    ) -> None:
        artifact_owner_id = owner_id or artifact.get("owner_id", "")
        artifact_owner_type = owner_type or artifact.get("owner_type", "Binary")
        artifact_type = artifact.get("artifact_type", "")
        relative_path = artifact.get("path", "")
        status = artifact.get("status", "exported")

        node = ExportArtifactNode(
            uid=self._artifact_uid(binary.hash, artifact_owner_type, artifact_owner_id, artifact_type, relative_path, status),
            owner_id=artifact_owner_id,
            owner_type=artifact_owner_type,
            artifact_type=artifact_type,
            relative_path=relative_path,
            content_hash=artifact.get("hash", ""),
            binary_id=binary.hash,
            binary_name=binary.name,
            status=status,
            error=artifact.get("error", ""),
        )

        if node.uid not in artifact_uids:
            graph_data.export_artifacts.append(node)
            artifact_uids.add(node.uid)

        for from_id in edge_from_ids:
            if not from_id:
                continue
            key = (from_id, node.uid)
            if key not in artifact_edges:
                graph_data.has_artifact.append(HasArtifactEdge(from_id=from_id, to_id=node.uid))
                artifact_edges.add(key)

    @staticmethod
    def _artifact_uid(
        binary_id: str,
        owner_type: str,
        owner_id: str,
        artifact_type: str,
        relative_path: str,
        status: str,
    ) -> str:
        raw = "|".join([binary_id, owner_type, owner_id, artifact_type, relative_path, status])
        return hashlib.md5(raw.encode("utf-8")).hexdigest()

    def _get_project_dir(self) -> str:
        root_dir = self.config.get("projects", {}).get("root_dir", "projects")
        project_dir = os.path.join(root_dir, self.project_metadata.name)
        os.makedirs(project_dir, exist_ok=True)
        return project_dir

    def _get_graph_db_path(self) -> str:
        return os.path.join(self._get_project_dir(), self.project_metadata.graph_db_file)

    def _should_export_files(self) -> bool:
        export_cfg = self.config.get("export", {})
        if "enable_file_export" in export_cfg:
            return bool(export_cfg.get("enable_file_export"))
        return export_cfg.get("auto_export_files", True)
