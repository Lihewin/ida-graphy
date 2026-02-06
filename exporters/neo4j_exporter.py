"""Neo4j exporter for graph data."""

import logging
from typing import Dict, Optional, List

from database.neo4j_manager import Neo4jManager, Neo4jError
from core.models import GraphData
from core.project.metadata import ProjectMetadata

logger = logging.getLogger(__name__)


class Neo4jExportError(Exception):
    """Neo4j export errors."""
    pass


class Neo4jExporter:
    """Neo4j export helper for project data."""

    def __init__(self, neo4j_config: Optional[Dict] = None, import_config: Optional[Dict] = None):
        self.neo4j_config = neo4j_config or {}
        self.import_config = import_config or {}
        self._neo4j_manager = None

    @property
    def neo4j_manager(self) -> Optional[Neo4jManager]:
        if self._neo4j_manager is None and self.neo4j_config:
            try:
                self._neo4j_manager = Neo4jManager(
                    uri=self.neo4j_config["uri"],
                    user=self.neo4j_config["user"],
                    password=self.neo4j_config["password"],
                    max_connection_pool_size=self.neo4j_config.get("max_connection_pool_size", 50),
                    connection_timeout=self.neo4j_config.get("connection_timeout", 30.0),
                )
            except Exception as e:
                logger.error("无法创建Neo4j管理器: %s", e)
        return self._neo4j_manager

    def _get_batch_size(self) -> int:
        raw_value = self.import_config.get("batch_size", 100000)
        try:
            batch_size = int(raw_value)
        except (TypeError, ValueError):
            batch_size = 100000
        return max(1, batch_size)

    def export_to_neo4j(
        self,
        project_metadata: ProjectMetadata,
        graph_data: GraphData,
        clear_existing: bool = False,
    ) -> Dict[str, int]:
        if not self.neo4j_manager:
            raise Neo4jExportError("Neo4j未配置或连接失败")

        database_name = project_metadata.database_name

        try:
            if not self.neo4j_manager.database_exists(database_name):
                self.neo4j_manager.create_database(database_name)
                logger.info("为项目 '%s' 创建数据库: %s", project_metadata.name, database_name)

            if clear_existing:
                self.neo4j_manager.clear_database(database_name)
                logger.info("已清空数据库: %s", database_name)

            self.neo4j_manager.create_indexes(database_name)
            stats = self.neo4j_manager.import_graph_data(
                database_name,
                graph_data,
                batch_size=self._get_batch_size(),
            )

            logger.info("项目 '%s' 数据导入完成: %s", project_metadata.name, stats)
            return stats

        except Neo4jError as e:
            raise Neo4jExportError(f"Neo4j导出失败: {e}")
        except Exception as e:
            raise Neo4jExportError(f"导出到Neo4j失败: {e}")

    def remove_binary_from_neo4j(self, project_metadata: ProjectMetadata, binary_hash: str) -> Dict[str, int]:
        if not self.neo4j_manager:
            raise Neo4jExportError("Neo4j未配置或连接失败")

        try:
            stats = self.neo4j_manager.remove_binary_data(project_metadata.database_name, binary_hash)
            logger.info("从项目 '%s' 中移除二进制 %s: %s", project_metadata.name, binary_hash, stats)
            return stats
        except Neo4jError as e:
            raise Neo4jExportError(f"移除二进制数据失败: {e}")
        except Exception as e:
            raise Neo4jExportError(f"移除二进制数据失败: {e}")

    def sync_project_to_neo4j(
        self,
        project_metadata: ProjectMetadata,
        graph_data: GraphData,
        changed_binaries: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        if not self.neo4j_manager:
            raise Neo4jExportError("Neo4j未配置或连接失败")

        total_stats = {"nodes_created": 0, "relationships_created": 0, "nodes_deleted": 0}
        database_name = project_metadata.database_name

        try:
            if not self.neo4j_manager.database_exists(database_name):
                self.neo4j_manager.create_database(database_name)
                self.neo4j_manager.create_indexes(database_name)
                import_stats = self.neo4j_manager.import_graph_data(
                    database_name,
                    graph_data,
                    batch_size=self._get_batch_size(),
                )
                total_stats.update(import_stats)
                gc_stats = self.neo4j_manager.gc_orphan_nodes(database_name)
                total_stats["nodes_deleted"] += gc_stats.get("nodes_deleted", 0)
                logger.info("项目 '%s' 首次同步完成: %s", project_metadata.name, total_stats)
                return total_stats

            if changed_binaries:
                import_stats = self.neo4j_manager.import_graph_data(
                    database_name,
                    graph_data,
                    batch_size=self._get_batch_size(),
                )
                total_stats.update(import_stats)

                for binary_hash in changed_binaries:
                    del_stats = self.neo4j_manager.remove_binary_data(database_name, binary_hash)
                    total_stats["nodes_deleted"] += del_stats.get("nodes_deleted", 0)

                gc_stats = self.neo4j_manager.gc_orphan_nodes(database_name)
                total_stats["nodes_deleted"] += gc_stats.get("nodes_deleted", 0)

                logger.info("项目 '%s' 增量同步完成: %s", project_metadata.name, total_stats)
            else:
                self.neo4j_manager.clear_database(database_name)
                self.neo4j_manager.create_indexes(database_name)
                import_stats = self.neo4j_manager.import_graph_data(
                    database_name,
                    graph_data,
                    batch_size=self._get_batch_size(),
                )
                total_stats.update(import_stats)
                gc_stats = self.neo4j_manager.gc_orphan_nodes(database_name)
                total_stats["nodes_deleted"] += gc_stats.get("nodes_deleted", 0)
                logger.info("项目 '%s' 全量同步完成: %s", project_metadata.name, total_stats)

            return total_stats

        except Neo4jError as e:
            raise Neo4jExportError(f"同步到Neo4j失败: {e}")
        except Exception as e:
            raise Neo4jExportError(f"同步失败: {e}")

    def delete_project_database(self, project_metadata: ProjectMetadata) -> None:
        if not self.neo4j_manager:
            raise Neo4jExportError("Neo4j未配置或连接失败")

        try:
            self.neo4j_manager.drop_database(project_metadata.database_name, if_exists=True)
            logger.info("项目 '%s' 数据库已删除: %s", project_metadata.name, project_metadata.database_name)
        except Neo4jError as e:
            raise Neo4jExportError(f"删除项目数据库失败: {e}")
        except Exception as e:
            raise Neo4jExportError(f"删除项目数据库失败: {e}")

    def get_database_stats(self, project_metadata: ProjectMetadata) -> Dict[str, int]:
        if not self.neo4j_manager:
            return {}
        try:
            return self.neo4j_manager.get_database_stats(project_metadata.database_name)
        except Exception as e:
            logger.error("获取数据库统计失败: %s", e)
            return {}

    def test_connection(self) -> Dict[str, any]:
        if not self.neo4j_manager:
            return {"connected": False, "error": "Neo4j未配置"}
        return self.neo4j_manager.test_connection()

    def close(self):
        if self._neo4j_manager:
            self._neo4j_manager.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_neo4j_exporter(config: Dict) -> Neo4jExporter:
    neo4j_config = config.get("neo4j", {}).get("connection", {})
    import_config = config.get("neo4j", {}).get("import", {})
    if not neo4j_config.get("uri"):
        logger.warning("Neo4j配置不完整，无法导出")
        return Neo4jExporter()
    return Neo4jExporter(neo4j_config, import_config)
