"""Unified export manager for graph data."""

import logging
import os
from typing import Dict, Optional

from core.models import GraphData
from core.project.metadata import ProjectMetadata
from . import export_manifest
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
        self._write_export_manifest(graph_data, binary_name, self._flatten_export_artifacts(results))
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
        self._write_export_manifest(graph_data, os.path.basename(binary_path), artifacts)
        return artifacts

    def _backfill_ghidra_artifacts(
        self,
        graph_data: GraphData,
        binary_name: str,
        artifacts,
    ) -> None:
        if not artifacts:
            return

        function_by_uid = {func.uid: func for func in graph_data.functions}

        for artifact in artifacts:
            func = function_by_uid.get(artifact.get("owner_id", ""))
            if func and artifact.get("status") == "exported":
                func.decompiled_file = artifact.get("path", "")
                func.pseudocode_hash = artifact.get("hash", "")

    def _backfill_export_results(self, graph_data: GraphData, binary_name: str, results: Dict) -> None:
        function_result = results.get("functions")
        if function_result:
            function_by_uid = {func.uid: func for func in graph_data.functions}
            for uid, mapping in function_result.file_mapping.items():
                func = function_by_uid.get(uid)
                if not func:
                    continue
                func.decompiled_file = mapping.get("path", "")
                func.pseudocode_hash = mapping.get("hash", "")

        structure_result = results.get("structures")
        if structure_result:
            struct_slots = self._build_struct_slot_index(graph_data)
            for type_name, mapping in structure_result.file_mapping.items():
                matching_slots = struct_slots.get(type_name, [])
                for slot in matching_slots:
                    slot.struct_file = mapping.get("path", "")

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

    def _write_export_manifest(self, graph_data: GraphData, binary_name: str, extra_artifacts) -> None:
        binary = self._find_binary(graph_data, binary_name)
        if not binary:
            logger.warning("No Binary node found for export manifest: %s", binary_name)
            return
        manifest_path = export_manifest.write_binary_manifest(
            self._get_project_dir(),
            binary,
            graph_data,
            extra_artifacts=extra_artifacts,
            binary_name=binary_name,
        )
        logger.info("Wrote export manifest: %s", manifest_path)

    @staticmethod
    def _flatten_export_artifacts(results: Dict):
        artifacts = []
        for value in results.values():
            if value is None:
                continue
            if isinstance(value, dict):
                artifacts.append(value)
                continue
            artifacts.extend(getattr(value, "artifacts", []) or [])
        return artifacts

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
