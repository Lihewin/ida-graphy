"""Unified export manager for graph data."""

import logging
import os
from typing import Dict, Optional

from core.models import GraphData
from core.project.metadata import ProjectMetadata
from .csv_exporter import CSVExporter
from . import file_exporter
from .neo4j_exporter import Neo4jExporter, create_neo4j_exporter

logger = logging.getLogger(__name__)


class ExportManager:
    """Unified export manager for Neo4j/CSV/files."""

    def __init__(self, config: Dict, project_metadata: ProjectMetadata):
        self.config = config or {}
        self.project_metadata = project_metadata
        self.neo4j_exporter: Optional[Neo4jExporter] = create_neo4j_exporter(self.config)

    def export_all(self, graph_data: GraphData, binary_path: str):
        """Export to Neo4j and optional file exports."""
        if self.neo4j_exporter and self.neo4j_exporter.neo4j_manager:
            self.export_to_neo4j(graph_data)
        else:
            self.export_to_csv(graph_data)

        if self._should_export_files() and binary_path:
            self.export_files(binary_path, graph_data)

    def export_to_neo4j(self, graph_data: GraphData) -> Dict[str, int]:
        return self.neo4j_exporter.export_to_neo4j(self.project_metadata, graph_data)

    def export_to_csv(self, graph_data: GraphData) -> Dict[str, str]:
        output_dir = self._get_csv_cache_dir()
        csv_exporter = CSVExporter(output_dir)
        return self._export_graph_data_to_csv(csv_exporter, graph_data)

    def export_files(self, binary_path: str, graph_data: GraphData):
        output_dir = self._get_csv_cache_dir()
        binary_name = os.path.basename(binary_path)
        exporter = file_exporter.FileExporter(output_dir, graph_data, binary_name=binary_name)
        if not file_exporter.IDA_AVAILABLE:
            logger.warning("IDA not available, skipping file export")
            return
        exporter.export_all()

    def _get_csv_cache_dir(self) -> str:
        root_dir = self.config.get("projects", {}).get("root_dir", "projects")
        return os.path.join(root_dir, self.project_metadata.name, "csv_cache")

    def _should_export_files(self) -> bool:
        export_cfg = self.config.get("export", {})
        if "enable_file_export" in export_cfg:
            return bool(export_cfg.get("enable_file_export"))
        return export_cfg.get("auto_export_files", True)

    def _export_graph_data_to_csv(self, csv_exporter: CSVExporter, graph_data: GraphData) -> Dict[str, str]:
        file_paths = {}

        if graph_data.binaries:
            file_paths["binary_nodes"] = csv_exporter._export_binary_nodes([n.to_dict() for n in graph_data.binaries])
        if graph_data.functions:
            file_paths["function_nodes"] = csv_exporter._export_function_nodes([n.to_dict() for n in graph_data.functions])
        if graph_data.dataslots:
            file_paths["dataslot_nodes"] = csv_exporter._export_dataslot_nodes([n.to_dict() for n in graph_data.dataslots])
        if graph_data.strings:
            file_paths["string_nodes"] = csv_exporter._export_string_nodes([n.to_dict() for n in graph_data.strings])

        if graph_data.contains:
            file_paths["contains_edges"] = csv_exporter._export_contains_edges([e.to_dict() for e in graph_data.contains])
        if graph_data.calls:
            file_paths["calls_edges"] = csv_exporter._export_calls_edges([e.to_dict() for e in graph_data.calls])
        if graph_data.links_to:
            file_paths["links_to_edges"] = csv_exporter._export_links_to_edges([e.to_dict() for e in graph_data.links_to])
        if graph_data.references:
            file_paths["references_edges"] = csv_exporter._export_references_edges([e.to_dict() for e in graph_data.references])
        if graph_data.writes:
            file_paths["writes_edges"] = csv_exporter._export_writes_edges([e.to_dict() for e in graph_data.writes])
        if graph_data.reads:
            file_paths["reads_edges"] = csv_exporter._export_reads_edges([e.to_dict() for e in graph_data.reads])

        return file_paths
