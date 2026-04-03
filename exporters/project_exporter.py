"""
Project Data Exporter

Enhanced data export module that supports direct Neo4j database import
for ida-graphy projects. Integrates with project management to provide
seamless data synchronization capabilities.

Key Features:
- Direct Neo4j database import via Python driver
- Project-aware data management with conflict resolution
- Incremental updates and binary-level removal
- Integrated with existing GraphData model
- Transaction support for data consistency

Architecture:
- Integrates with Neo4jManager for database operations
- Supports both batch and incremental data operations
- Provides unified interface for project data export
"""

import logging
from typing import Dict, List, Optional

from database.neo4j_manager import Neo4jManager, Neo4jError
from core.models import GraphData, ProjectMetadata

logger = logging.getLogger(__name__)


class ProjectExportError(Exception):
    """项目导出相关异常"""
    pass


class ProjectExporter:
    """项目数据导出器，支持直接Neo4j导出"""
    
    def __init__(self, neo4j_config: Optional[Dict] = None, import_config: Optional[Dict] = None):
        """
        初始化项目导出器
        
        Args:
            neo4j_config: Neo4j连接配置字典，包含uri、user、password等
        """
        self.neo4j_config = neo4j_config
        self.import_config = import_config or {}
        self._neo4j_manager = None
        
    @property
    def neo4j_manager(self) -> Optional[Neo4jManager]:
        """懒加载Neo4j管理器"""
        if self._neo4j_manager is None and self.neo4j_config:
            try:
                self._neo4j_manager = Neo4jManager(
                    uri=self.neo4j_config['uri'],
                    user=self.neo4j_config['user'],
                    password=self.neo4j_config['password'],
                    max_connection_pool_size=self.neo4j_config.get('max_connection_pool_size', 50),
                    connection_timeout=self.neo4j_config.get('connection_timeout', 30.0)
                )
            except Exception as e:
                logger.error(f"无法创建Neo4j管理器: {e}")
                
        return self._neo4j_manager

    def _get_batch_size(self) -> int:
        raw_value = self.import_config.get("batch_size", 100000)
        try:
            batch_size = int(raw_value)
        except (TypeError, ValueError):
            batch_size = 100000
        return max(1, batch_size)
    
    def export_to_neo4j(self, project_metadata: ProjectMetadata, 
                       graph_data: GraphData, 
                       clear_existing: bool = False) -> Dict[str, int]:
        """
        直接导出项目数据到Neo4j数据库
        
        Args:
            project_metadata: 项目元数据
            graph_data: 图数据
            clear_existing: 是否清空现有数据
            
        Returns:
            导出统计信息
            
        Raises:
            ProjectExportError: 导出失败或Neo4j不可用
        """
        if not self.neo4j_manager:
            raise ProjectExportError("Neo4j未配置或连接失败")
        
        database_name = project_metadata.database_name
        
        try:
            # 确保数据库存在
            if not self.neo4j_manager.database_exists(database_name):
                self.neo4j_manager.create_database(database_name)
                logger.info(f"为项目 '{project_metadata.name}' 创建数据库: {database_name}")
            
            # 清空现有数据（如果需要）
            if clear_existing:
                self.neo4j_manager.clear_database(database_name)
                logger.info(f"已清空数据库: {database_name}")
            
            # 创建索引以提高性能
            self.neo4j_manager.create_indexes(database_name)
            
            # 导入图数据
            stats = self.neo4j_manager.import_graph_data(
                database_name,
                graph_data,
                batch_size=self._get_batch_size(),
            )
            
            logger.info(f"项目 '{project_metadata.name}' 数据导入完成: {stats}")
            return stats
            
        except Neo4jError as e:
            raise ProjectExportError(f"Neo4j导出失败: {e}")
        except Exception as e:
            raise ProjectExportError(f"导出到Neo4j失败: {e}")
    
    def remove_binary_from_neo4j(self, project_metadata: ProjectMetadata, 
                                binary_hash: str) -> Dict[str, int]:
        """
        从Neo4j数据库中移除指定二进制文件的数据
        
        Args:
            project_metadata: 项目元数据
            binary_hash: 要移除的二进制文件哈希
            
        Returns:
            删除统计信息
            
        Raises:
            ProjectExportError: 删除失败或Neo4j不可用
        """
        if not self.neo4j_manager:
            raise ProjectExportError("Neo4j未配置或连接失败")
        
        try:
            stats = self.neo4j_manager.remove_binary_data(
                project_metadata.database_name, 
                binary_hash
            )
            
            logger.info(f"从项目 '{project_metadata.name}' 中移除二进制 {binary_hash}: {stats}")
            return stats
            
        except Neo4jError as e:
            raise ProjectExportError(f"移除二进制数据失败: {e}")
        except Exception as e:
            raise ProjectExportError(f"移除二进制数据失败: {e}")
    
    def sync_project_to_neo4j(self, project_metadata: ProjectMetadata,
                             graph_data: GraphData,
                             changed_binaries: List[str] = None) -> Dict[str, int]:
        """
        同步项目数据到Neo4j（支持增量更新）
        
        Args:
            project_metadata: 项目元数据
            graph_data: 完整的图数据
            changed_binaries: 已变更的二进制文件哈希列表，如果为None则全量同步
            
        Returns:
            同步统计信息
            
        Raises:
            ProjectExportError: 同步失败
        """
        if not self.neo4j_manager:
            raise ProjectExportError("Neo4j未配置或连接失败")
        
        total_stats = {'nodes_created': 0, 'relationships_created': 0, 'nodes_deleted': 0}
        
        try:
            database_name = project_metadata.database_name
            
            # 确保数据库存在
            if not self.neo4j_manager.database_exists(database_name):
                self.neo4j_manager.create_database(database_name)
                self.neo4j_manager.create_indexes(database_name)
                
                # 首次创建，不需要增量处理
                import_stats = self.neo4j_manager.import_graph_data(
                    database_name,
                    graph_data,
                    batch_size=self._get_batch_size(),
                )
                total_stats.update(import_stats)
                gc_stats = self.neo4j_manager.gc_orphan_nodes(database_name)
                total_stats['nodes_deleted'] += gc_stats.get('nodes_deleted', 0)
                
                logger.info(f"项目 '{project_metadata.name}' 首次同步完成: {total_stats}")
                return total_stats
            
            if changed_binaries:
                # 增量更新：先导入新数据，再移除旧二进制
                import_stats = self.neo4j_manager.import_graph_data(
                    database_name,
                    graph_data,
                    batch_size=self._get_batch_size(),
                )
                total_stats.update(import_stats)

                for binary_hash in changed_binaries:
                    del_stats = self.neo4j_manager.remove_binary_data(database_name, binary_hash)
                    total_stats['nodes_deleted'] += del_stats.get('nodes_deleted', 0)

                    logger.debug(f"移除变更的二进制 {binary_hash}: {del_stats}")

                gc_stats = self.neo4j_manager.gc_orphan_nodes(database_name)
                total_stats['nodes_deleted'] += gc_stats.get('nodes_deleted', 0)

                logger.info(f"项目 '{project_metadata.name}' 增量同步完成: {total_stats}")
            else:
                # 全量同步：清空数据库并重新导入
                self.neo4j_manager.clear_database(database_name)
                self.neo4j_manager.create_indexes(database_name)
                
                import_stats = self.neo4j_manager.import_graph_data(
                    database_name,
                    graph_data,
                    batch_size=self._get_batch_size(),
                )
                total_stats.update(import_stats)
                gc_stats = self.neo4j_manager.gc_orphan_nodes(database_name)
                total_stats['nodes_deleted'] += gc_stats.get('nodes_deleted', 0)
                
                logger.info(f"项目 '{project_metadata.name}' 全量同步完成: {total_stats}")
            
            return total_stats
            
        except Neo4jError as e:
            raise ProjectExportError(f"同步到Neo4j失败: {e}")
        except Exception as e:
            raise ProjectExportError(f"同步失败: {e}")
    
    def delete_project_database(self, project_metadata: ProjectMetadata) -> None:
        """
        删除项目对应的Neo4j数据库
        
        Args:
            project_metadata: 项目元数据
            
        Raises:
            ProjectExportError: 删除失败
        """
        if not self.neo4j_manager:
            raise ProjectExportError("Neo4j未配置或连接失败")
        
        try:
            self.neo4j_manager.drop_database(project_metadata.database_name, if_exists=True)
            logger.info(f"项目 '{project_metadata.name}' 数据库已删除: {project_metadata.database_name}")
            
        except Neo4jError as e:
            raise ProjectExportError(f"删除项目数据库失败: {e}")
        except Exception as e:
            raise ProjectExportError(f"删除项目数据库失败: {e}")
    
    def get_database_stats(self, project_metadata: ProjectMetadata) -> Dict[str, int]:
        """
        获取项目数据库统计信息
        
        Args:
            project_metadata: 项目元数据
            
        Returns:
            统计信息字典
        """
        if not self.neo4j_manager:
            return {}
        
        try:
            return self.neo4j_manager.get_database_stats(project_metadata.database_name)
        except Exception as e:
            logger.error(f"获取数据库统计失败: {e}")
            return {}
    
    def test_neo4j_connection(self) -> Dict[str, any]:
        """测试Neo4j连接"""
        if not self.neo4j_manager:
            return {"connected": False, "error": "Neo4j未配置"}
        
        return self.neo4j_manager.test_connection()
    
    def close(self):
        """关闭资源连接"""
        if self._neo4j_manager:
            self._neo4j_manager.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_project_exporter(config: Dict) -> ProjectExporter:
    """
    根据配置创建项目导出器
    
    Args:
        config: 配置字典，应包含neo4j配置
        
    Returns:
        配置好的ProjectExporter实例
    """
    neo4j_config = config.get('neo4j', {}).get('connection', {})
    import_config = config.get("neo4j", {}).get("import", {})
    
    if not neo4j_config.get('uri'):
        logger.warning("Neo4j配置不完整，无法导出")
        return ProjectExporter()
    
    return ProjectExporter(neo4j_config, import_config)