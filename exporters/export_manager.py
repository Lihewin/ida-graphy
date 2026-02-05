"""Unified export manager for graph data."""

import logging
import os
from typing import Dict, Optional

from core.models import GraphData
from core.project.metadata import ProjectMetadata
from . import file_exporter
from .neo4j_exporter import Neo4jExporter, create_neo4j_exporter

logger = logging.getLogger(__name__)


class ExportManager:
    """Unified export manager for Neo4j and file exports."""

    def __init__(self, config: Dict, project_metadata: ProjectMetadata):
        self.config = config or {}
        self.project_metadata = project_metadata
        self.neo4j_exporter: Optional[Neo4jExporter] = create_neo4j_exporter(self.config)

    def export_all(self, graph_data: GraphData, binary_path: str):
        """Export to Neo4j and optional file exports."""
        if not self.neo4j_exporter or not self.neo4j_exporter.neo4j_manager:
            raise RuntimeError("Neo4j is not configured or unavailable")

        self.export_to_neo4j(graph_data)

        if self._should_export_files() and binary_path:
            self.export_files(binary_path, graph_data)

    def export_to_neo4j(self, graph_data: GraphData) -> Dict[str, int]:
        return self.neo4j_exporter.export_to_neo4j(self.project_metadata, graph_data)

    def export_files(self, binary_path: str, graph_data: GraphData):
        output_dir = self._get_project_dir()
        binary_name = os.path.basename(binary_path)
        exporter = file_exporter.FileExporter(output_dir, graph_data, binary_name=binary_name)
        if not file_exporter.IDA_AVAILABLE:
            logger.warning("IDA not available, skipping file export")
            return
        exporter.export_all()

    def _get_project_dir(self) -> str:
        root_dir = self.config.get("projects", {}).get("root_dir", "projects")
        project_dir = os.path.join(root_dir, self.project_metadata.name)
        os.makedirs(project_dir, exist_ok=True)
        return project_dir

    def _should_export_files(self) -> bool:
        export_cfg = self.config.get("export", {})
        if "enable_file_export" in export_cfg:
            return bool(export_cfg.get("enable_file_export"))
        return export_cfg.get("auto_export_files", True)
