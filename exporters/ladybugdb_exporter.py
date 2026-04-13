"""LadybugDB exporter for ida-graphy GraphData."""

from __future__ import annotations

import logging
import os
from typing import Dict, Optional

from core.models import GraphData
from core.project.metadata import ProjectMetadata
from database.ladybugdb_manager import LadybugDBError, LadybugDBManager

logger = logging.getLogger(__name__)


class LadybugDBExportError(Exception):
    """LadybugDB export errors."""


class LadybugDBExporter:
    """Export helper that writes GraphData into an embedded LadybugDB file."""

    def export_to_ladybugdb(self, db_path: str, graph_data: GraphData, rebuild: bool = True) -> Dict[str, int]:
        try:
            os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
            if rebuild and os.path.exists(db_path):
                os.remove(db_path)

            with LadybugDBManager(db_path) as mgr:
                mgr.initialize_schema()
                return mgr.import_graph_data(graph_data)

        except LadybugDBError as e:
            raise LadybugDBExportError(str(e)) from e
        except Exception as e:
            raise LadybugDBExportError(f"Export to LadybugDB failed: {e}") from e

    def get_database_stats(self, db_path: str) -> Dict[str, int]:
        if not os.path.exists(db_path):
            return {}
        try:
            with LadybugDBManager(db_path) as mgr:
                return mgr.get_database_stats()
        except Exception as e:
            logger.debug("Failed to get LadybugDB stats: %s", e)
            return {}

    def test_connection(self) -> Dict[str, object]:
        return LadybugDBManager.test_connection()


def create_ladybugdb_exporter(_config: Optional[Dict] = None) -> LadybugDBExporter:
    # Reserved for future config toggles; currently always enabled.
    return LadybugDBExporter()
