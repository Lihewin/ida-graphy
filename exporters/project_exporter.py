"""
Project Data Exporter

Enhanced data export module that supports both CSV export and direct Neo4j database
import for ida-graphy projects. Integrates with project management to provide
seamless data synchronization capabilities.

Key Features:
- Direct Neo4j database import via Python driver  
- Traditional CSV export with Neo4j compatibility
- Project-aware data management with conflict resolution
- Incremental updates and binary-level removal
- Integrated with existing GraphData model
- Transaction support for data consistency

Architecture:
- Extends existing csv_exporter functionality
- Integrates with Neo4jManager for database operations
- Supports both batch and incremental data operations
- Provides unified interface for project data export
"""

import os
import logging
from typing import Dict, List, Optional, Union, Tuple
from pathlib import Path

from .csv_exporter import CSVExporter
from database.neo4j_manager import Neo4jManager, Neo4jError
from core.models import GraphData, ProjectMetadata

logger = logging.getLogger(__name__)


class ProjectExportError(Exception):
    """项目导出相关异常"""
    pass


class ProjectExporter:
    """项目数据导出器，支持CSV和直接Neo4j导出"""
    
    def __init__(self, neo4j_config: Optional[Dict] = None):
        """
        初始化项目导出器
        
        Args:
            neo4j_config: Neo4j连接配置字典，包含uri、user、password等
        """
        self.neo4j_config = neo4j_config
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
    
    def export_to_csv(self, project_metadata: ProjectMetadata, graph_data: GraphData, 
                     output_dir: Optional[str] = None) -> Dict[str, str]:
        """
        导出项目数据到CSV文件
        
        Args:
            project_metadata: 项目元数据
            graph_data: 图数据
            output_dir: 输出目录，如果为None则使用默认项目缓存目录
            
        Returns:
            导出文件路径字典
            
        Raises:
            ProjectExportError: 导出失败
        """
        if output_dir is None:
            # 使用项目缓存目录
            project_dir = Path("projects") / project_metadata.name / "csv_cache"
            output_dir = str(project_dir)
        
        try:
            # 使用现有的CSV导出器
            csv_exporter = CSVExporter(output_dir)
            
            # 导出所有数据
            file_paths = self._export_graph_data_to_csv(csv_exporter, graph_data)
            
            # 生成项目相关的导入脚本
            self._generate_project_import_scripts(
                project_metadata, 
                output_dir, 
                csv_exporter.stats
            )
            
            logger.info(f"项目 '{project_metadata.name}' CSV导出完成: {output_dir}")
            return file_paths
            
        except Exception as e:
            raise ProjectExportError(f"CSV导出失败: {e}")
    
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
            stats = self.neo4j_manager.import_graph_data(database_name, graph_data)
            
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
                import_stats = self.neo4j_manager.import_graph_data(database_name, graph_data)
                total_stats.update(import_stats)
                gc_stats = self.neo4j_manager.gc_orphan_nodes(database_name)
                total_stats['nodes_deleted'] += gc_stats.get('nodes_deleted', 0)
                
                logger.info(f"项目 '{project_metadata.name}' 首次同步完成: {total_stats}")
                return total_stats
            
            if changed_binaries:
                # 增量更新：先导入新数据，再移除旧二进制
                import_stats = self.neo4j_manager.import_graph_data(database_name, graph_data)
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
                
                import_stats = self.neo4j_manager.import_graph_data(database_name, graph_data)
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
    
    def _export_graph_data_to_csv(self, csv_exporter: CSVExporter, 
                                 graph_data: GraphData) -> Dict[str, str]:
        """将图数据导出到CSV文件（使用现有的导出器）"""
        file_paths = {}
        
        # 导出节点
        if graph_data.binaries:
            binary_data = [node.to_dict() for node in graph_data.binaries]
            file_paths['binary_nodes'] = csv_exporter._export_binary_nodes(binary_data)
        
        if graph_data.functions:
            function_data = [node.to_dict() for node in graph_data.functions]
            file_paths['function_nodes'] = csv_exporter._export_function_nodes(function_data)
        
        if graph_data.dataslots:
            dataslot_data = [node.to_dict() for node in graph_data.dataslots]
            file_paths['dataslot_nodes'] = csv_exporter._export_dataslot_nodes(dataslot_data)
        
        if graph_data.strings:
            string_data = [node.to_dict() for node in graph_data.strings]
            file_paths['string_nodes'] = csv_exporter._export_string_nodes(string_data)
        
        # 导出关系
        if graph_data.contains:
            edge_data = [edge.to_dict() for edge in graph_data.contains]
            file_paths['contains_edges'] = csv_exporter._export_contains_edges(edge_data)

        if graph_data.embeds:
            edge_data = [edge.to_dict() for edge in graph_data.embeds]
            file_paths['embeds_edges'] = csv_exporter._export_embeds_edges(edge_data)
        
        if graph_data.calls:
            edge_data = [edge.to_dict() for edge in graph_data.calls]
            file_paths['calls_edges'] = csv_exporter._export_calls_edges(edge_data)
        
        if graph_data.links_to:
            edge_data = [edge.to_dict() for edge in graph_data.links_to]
            file_paths['links_to_edges'] = csv_exporter._export_links_to_edges(edge_data)
        
        if graph_data.references:
            edge_data = [edge.to_dict() for edge in graph_data.references]
            file_paths['references_edges'] = csv_exporter._export_references_edges(edge_data)
        
        if graph_data.writes:
            edge_data = [edge.to_dict() for edge in graph_data.writes]
            file_paths['writes_edges'] = csv_exporter._export_writes_edges(edge_data)
        
        if graph_data.reads:
            edge_data = [edge.to_dict() for edge in graph_data.reads]
            file_paths['reads_edges'] = csv_exporter._export_reads_edges(edge_data)
        
        return file_paths
    
    def _generate_project_import_scripts(self, project_metadata: ProjectMetadata,
                                       output_dir: str, stats: Dict) -> None:
        """为项目生成Neo4j导入脚本"""
        database_name = project_metadata.database_name
        
        # 生成Cypher索引创建脚本
        index_file = os.path.join(output_dir, "create_indexes.cypher")
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(f"// Neo4j索引创建脚本 - 项目: {project_metadata.name}\n")
            f.write(f"// 数据库: {database_name}\n")
            f.write(f"// 生成时间: {project_metadata.modified_time}\n\n")
            
            indexes = [
                "CREATE INDEX binary_hash_idx IF NOT EXISTS FOR (n:Binary) ON (n.hash);",
                "CREATE INDEX function_uid_idx IF NOT EXISTS FOR (n:Function) ON (n.uid);",
                "CREATE INDEX function_binary_idx IF NOT EXISTS FOR (n:Function) ON (n.binary_id);",
                "CREATE INDEX dataslot_uid_idx IF NOT EXISTS FOR (n:DataSlot) ON (n.uid);",  
                "CREATE INDEX string_hash_idx IF NOT EXISTS FOR (n:String) ON (n.hash);",
                "CREATE INDEX function_rva_binary_idx IF NOT EXISTS FOR (n:Function) ON (n.rva, n.binary_id);",
                "CREATE INDEX dataslot_type_offset_idx IF NOT EXISTS FOR (n:DataSlot) ON (n.base_type, n.offset);",
            ]
            
            for index in indexes:
                f.write(index + "\n")
        
        # 生成统计报告
        stats_file = os.path.join(output_dir, "export_stats.txt")
        with open(stats_file, 'w', encoding='utf-8') as f:
            f.write(f"项目导出统计报告\n")
            f.write(f"==================\n\n")
            f.write(f"项目名称: {project_metadata.name}\n")
            f.write(f"项目描述: {project_metadata.description}\n")
            f.write(f"数据库名称: {database_name}\n")
            f.write(f"导出时间: {project_metadata.modified_time}\n\n")
            f.write(f"节点统计:\n")
            for node_type, count in stats.get('nodes', {}).items():
                f.write(f"  {node_type}: {count}\n")
            f.write(f"\n边统计:\n")
            for edge_type, count in stats.get('edges', {}).items():
                f.write(f"  {edge_type}: {count}\n")
            
            if stats.get('errors'):
                f.write(f"\n错误信息:\n")
                for error in stats['errors']:
                    f.write(f"  - {error}\n")
    
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
    
    if not neo4j_config.get('uri'):
        logger.warning("Neo4j配置不完整，仅支持CSV导出")
        return ProjectExporter()
    
    return ProjectExporter(neo4j_config)