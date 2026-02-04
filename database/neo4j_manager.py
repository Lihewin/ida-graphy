"""
Neo4j Database Manager

This module provides comprehensive Neo4j database management functionality
for ida-graphy projects. Each project gets its own dedicated database
for complete data isolation.

Key Features:
- Database creation and deletion
- Connection management with connection pooling
- Direct data import without CSV intermediates
- Transaction support for data consistency
- Health checks and status monitoring
- Automatic index creation for performance

Architecture:
- Each project maps to one Neo4j database (ida_project_{project_name})
- Uses Neo4j Python driver for direct database operations
- Supports both cloud and local Neo4j installations
- Provides safe database operations with error handling
"""

import logging
from typing import Dict, List, Optional, Any, Union
from contextlib import contextmanager
import time

try:
    from neo4j import GraphDatabase, Driver, Session, Transaction
    from neo4j.exceptions import ServiceUnavailable, DatabaseError, ClientError
    HAS_NEO4J = True
except ImportError:
    # Graceful degradation if neo4j driver not available
    GraphDatabase = None
    Driver = None
    Session = None
    Transaction = None
    ServiceUnavailable = Exception
    DatabaseError = Exception  
    ClientError = Exception
    HAS_NEO4J = False

from core.models import GraphData, BinaryNode, FunctionNode, DataSlotNode, StringNode

logger = logging.getLogger(__name__)


class Neo4jError(Exception):
    """Neo4j操作相关异常"""
    pass


class Neo4jManager:
    """Neo4j数据库管理器"""
    
    def __init__(self, uri: str, user: str, password: str, 
                 max_connection_pool_size: int = 50,
                 connection_timeout: float = 30.0,
                 max_retry_time: float = 300.0):
        """
        初始化Neo4j管理器
        
        Args:
            uri: Neo4j连接URI (e.g., "bolt://localhost:7687")
            user: 用户名
            password: 密码
            max_connection_pool_size: 最大连接池大小
            connection_timeout: 连接超时时间（秒）

        
        Raises:
            Neo4jError: Neo4j驱动不可用或连接失败
        """
        if not HAS_NEO4J:
            raise Neo4jError("Neo4j Python驱动未安装，请运行: pip install neo4j")
        
        self.uri = uri
        self.user = user
        self.password = password
        
        try:
            self.driver = GraphDatabase.driver(
                uri, 
                auth=(user, password),
                max_connection_pool_size=max_connection_pool_size,
                connection_timeout=connection_timeout
            )
            
            # 测试连接
            self.driver.verify_connectivity()
            logger.info(f"成功连接到Neo4j: {uri}")
            
        except Exception as e:
            raise Neo4jError(f"无法连接到Neo4j {uri}: {e}")
    
    def close(self):
        """关闭数据库连接"""
        if hasattr(self, 'driver') and self.driver:
            self.driver.close()
            logger.info("Neo4j连接已关闭")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    @contextmanager
    def get_session(self, database: Optional[str] = None):
        """
        获取数据库会话的上下文管理器
        
        Args:
            database: 数据库名称，如果为None则使用默认数据库
            
        Yields:
            Neo4j Session对象
        """
        session = None
        try:
            session = self.driver.session(database=database)
            yield session
        except Exception as e:
            logger.error(f"数据库会话错误: {e}")
            raise
        finally:
            if session:
                session.close()
    
    def list_databases(self) -> List[str]:
        """
        列出所有数据库
        
        Returns:
            数据库名称列表
        """
        try:
            with self.get_session("system") as session:
                result = session.run("SHOW DATABASES")
                databases = [record["name"] for record in result]
                return databases
        except Exception as e:
            logger.error(f"列出数据库失败: {e}")
            raise Neo4jError(f"列出数据库失败: {e}")
    
    def database_exists(self, database_name: str) -> bool:
        """
        检查数据库是否存在
        
        Args:
            database_name: 数据库名称
            
        Returns:
            数据库是否存在
        """
        try:
            databases = self.list_databases()
            return database_name in databases
        except Exception as e:
            logger.warning(f"检查数据库存在性时出错: {e}")
            return False
    
    def create_database(self, database_name: str, wait_for_creation: bool = True) -> None:
        """
        创建数据库
        
        Args:
            database_name: 数据库名称
            wait_for_creation: 是否等待数据库创建完成
            
        Raises:
            Neo4jError: 创建失败
        """
        try:
            if self.database_exists(database_name):
                logger.info(f"数据库 '{database_name}' 已存在")
                return
            
            with self.get_session("system") as session:
                session.run(f"CREATE DATABASE `{database_name}`")
                logger.info(f"数据库 '{database_name}' 创建成功")
            
            # 等待数据库变为在线状态
            if wait_for_creation:
                self._wait_for_database_online(database_name)
                
        except ClientError as e:
            if "already exists" in str(e):
                logger.info(f"数据库 '{database_name}' 已存在")
                return
            raise Neo4jError(f"创建数据库失败: {e}")
        except Exception as e:
            raise Neo4jError(f"创建数据库失败: {e}")
    
    def drop_database(self, database_name: str, if_exists: bool = True) -> None:
        """
        删除数据库
        
        Args:
            database_name: 数据库名称
            if_exists: 如果数据库不存在是否忽略错误
            
        Raises:
            Neo4jError: 删除失败且if_exists为False
        """
        try:
            # 防止意外删除系统数据库
            if database_name in ("system", "neo4j"):
                raise Neo4jError(f"不能删除系统数据库: {database_name}")
            
            if_exists_clause = "IF EXISTS" if if_exists else ""
            
            with self.get_session("system") as session:
                session.run(f"DROP DATABASE `{database_name}` {if_exists_clause}")
                logger.info(f"数据库 '{database_name}' 删除成功")
                
        except ClientError as e:
            if "does not exist" in str(e) and if_exists:
                logger.info(f"数据库 '{database_name}' 不存在")
                return
            raise Neo4jError(f"删除数据库失败: {e}")
        except Exception as e:
            raise Neo4jError(f"删除数据库失败: {e}")
    
    def _wait_for_database_online(self, database_name: str, timeout: float = 60.0) -> None:
        """
        等待数据库变为在线状态
        
        Args:
            database_name: 数据库名称
            timeout: 超时时间（秒）
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with self.get_session("system") as session:
                    result = session.run(
                        "SHOW DATABASE $name", 
                        name=database_name
                    )
                    for record in result:
                        if record.get("currentStatus") == "online":
                            logger.info(f"数据库 '{database_name}' 已上线")
                            return
                
                time.sleep(1.0)  # 等待1秒后重试
                
            except Exception as e:
                logger.debug(f"检查数据库状态时出错: {e}")
                time.sleep(1.0)
        
        raise Neo4jError(f"等待数据库上线超时: {database_name}")
    
    def clear_database(self, database_name: str) -> None:
        """
        清空数据库中的所有数据
        
        Args:
            database_name: 数据库名称
        """
        try:
            with self.get_session(database_name) as session:
                # 删除所有节点和关系（分批进行以避免内存问题）
                batch_size = 1000
                while True:
                    result = session.run(f"""
                        MATCH (n) 
                        WITH n LIMIT {batch_size}
                        DETACH DELETE n
                        RETURN count(n) as deleted
                    """)
                    
                    deleted = result.single()["deleted"]
                    if deleted == 0:
                        break
                    
                    logger.debug(f"删除了 {deleted} 个节点")
                
                logger.info(f"数据库 '{database_name}' 已清空")
                
        except Exception as e:
            raise Neo4jError(f"清空数据库失败: {e}")
    
    def create_indexes(self, database_name: str) -> None:
        """
        为数据库创建索引以提高查询性能
        
        Args:
            database_name: 数据库名称
        """
        indexes = [
            # 节点索引
            "CREATE INDEX binary_hash_idx IF NOT EXISTS FOR (n:Binary) ON (n.hash)",
            "CREATE INDEX function_uid_idx IF NOT EXISTS FOR (n:Function) ON (n.uid)",
            "CREATE INDEX function_binary_idx IF NOT EXISTS FOR (n:Function) ON (n.binary_id)",
            "CREATE INDEX dataslot_uid_idx IF NOT EXISTS FOR (n:DataSlot) ON (n.uid)",
            "CREATE INDEX string_hash_idx IF NOT EXISTS FOR (n:String) ON (n.hash)",
            
            # 复合索引
            "CREATE INDEX function_rva_binary_idx IF NOT EXISTS FOR (n:Function) ON (n.rva, n.binary_id)",
            "CREATE INDEX dataslot_type_offset_idx IF NOT EXISTS FOR (n:DataSlot) ON (n.base_type, n.offset)",
        ]
        
        try:
            with self.get_session(database_name) as session:
                for index_query in indexes:
                    try:
                        session.run(index_query)
                        logger.debug(f"索引创建成功: {index_query}")
                    except ClientError as e:
                        if "already exists" in str(e):
                            continue
                        logger.warning(f"创建索引失败: {index_query}, 错误: {e}")
                
                logger.info(f"数据库 '{database_name}' 索引创建完成")
                
        except Exception as e:
            raise Neo4jError(f"创建索引失败: {e}")
    
    def import_graph_data(self, database_name: str, graph_data: GraphData) -> Dict[str, int]:
        """
        将图数据导入数据库
        
        Args:
            database_name: 数据库名称
            graph_data: 要导入的图数据
            
        Returns:
            导入统计信息字典
            
        Raises:
            Neo4jError: 导入失败
        """
        stats = {
            'nodes_created': 0,
            'relationships_created': 0,
            'nodes_skipped': 0,
            'error_count': 0
        }
        
        try:
            with self.get_session(database_name) as session:
                with session.begin_transaction() as tx:
                    # 导入节点
                    stats['nodes_created'] += self._import_nodes(tx, graph_data)
                    
                    # 导入关系
                    stats['relationships_created'] += self._import_relationships(tx, graph_data)
                    
                    logger.info(f"图数据导入完成: {stats}")
                    return stats
                    
        except Exception as e:
            stats['error_count'] += 1
            logger.error(f"导入图数据失败: {e}")
            raise Neo4jError(f"导入图数据失败: {e}")
    
    def _import_nodes(self, tx: Transaction, graph_data: GraphData) -> int:
        """导入节点数据"""
        total_created = 0
        
        # 导入Binary节点
        if graph_data.binaries:
            for binary in graph_data.binaries:
                tx.run("""
                    MERGE (b:Binary {hash: $hash})
                    SET b.name = $name,
                        b.orig_name = $orig_name,
                        b.base_addr = $base_addr,
                        b.arch = $arch,
                        b.compile_ts = $compile_ts
                """, binary.to_dict())
            total_created += len(graph_data.binaries)
        
        # 导入Function节点
        if graph_data.functions:
            for function in graph_data.functions:
                tx.run("""
                    MERGE (f:Function {uid: $uid})
                    SET f.rva = $rva,
                        f.name = $name,
                        f.orig_name = $orig_name,
                        f.size = $size,
                        f.is_lib = $is_lib,
                        f.func_type = $func_type,
                        f.signature = $signature,
                        f.complexity = $complexity,
                        f.binary_id = $binary_id,
                        f.binary_name = $binary_name,
                        f.decompiled_file = $decompiled_file,
                        f.pseudocode_hash = $pseudocode_hash
                """, function.to_dict())
            total_created += len(graph_data.functions)
        
        # 导入DataSlot节点
        if graph_data.dataslots:
            for dataslot in graph_data.dataslots:
                tx.run("""
                    MERGE (d:DataSlot {uid: $uid})
                    SET d.base_type = $base_type,
                        d.base_type_orig = $base_type_orig,
                        d.offset = $offset,
                        d.size = $size,
                        d.name = $name,
                        d.orig_name = $orig_name,
                        d.is_global = $is_global,
                        d.struct_file = $struct_file
                """, dataslot.to_dict())
            total_created += len(graph_data.dataslots)
        
        # 导入String节点
        if graph_data.strings:
            for string in graph_data.strings:
                tx.run("""
                    MERGE (s:String {hash: $hash})
                    SET s.content = $content,
                        s.orig_name = $orig_name,
                        s.encoding = $encoding
                """, string.to_dict())
            total_created += len(graph_data.strings)
        
        return total_created
    
    def _import_relationships(self, tx: Transaction, graph_data: GraphData) -> int:
        """导入关系数据"""
        total_created = 0

        if graph_data.links_to:
            # Reset external export placeholders and stale LINKS_TO edges before reimport.
            tx.run("MATCH ()-[r:LINKS_TO]->() DELETE r")
            tx.run("MATCH (f:Function {binary_id: 'EXTERNAL'}) DETACH DELETE f")
        
        # CONTAINS关系 - 需要正确处理不同节点类型的ID属性
        for edge in graph_data.contains:
            # Binary节点使用hash作为ID，目标节点使用不同的ID字段：
            # - Function和DataSlot使用uid
            # - String使用hash
            result = tx.run("""
                MATCH (from:Binary {hash: $from_id})
                OPTIONAL MATCH (func:Function {uid: $to_id})  
                OPTIONAL MATCH (data:DataSlot {uid: $to_id})
                OPTIONAL MATCH (str:String {hash: $to_id})
                WITH from, COALESCE(func, data, str) as target
                WHERE target IS NOT NULL
                MERGE (from)-[:CONTAINS]->(target)
                RETURN count(*) as created
            """, edge.to_dict())
            
            # 记录创建的关系数
            record = result.single()
            if record and record['created'] > 0:
                total_created += record['created']
        
        logger.info(f"CONTAINS关系导入完成，创建了 {total_created} 个关系")

        # EMBEDS关系
        for edge in graph_data.embeds:
            result = tx.run("""
                MATCH (from:DataSlot {uid: $from_id}), (to:DataSlot {uid: $to_id})
                MERGE (from)-[:EMBEDS]->(to)
                RETURN count(*) as created
            """, edge.to_dict())
            record = result.single()
            if record and record['created'] > 0:
                total_created += record['created']
        
        # CALLS关系
        for edge in graph_data.calls:
            result = tx.run("""
                MATCH (from:Function {uid: $from_id}), (to:Function {uid: $to_id})
                MERGE (from)-[r:CALLS]->(to)
                SET r.type = $type, r.count = $count
                RETURN count(r) as created
            """, edge.to_dict())
            record = result.single()
            if record and record['created'] > 0:
                total_created += record['created']
        
        # LINKS_TO关系
        for edge in graph_data.links_to:
            result = tx.run("""
                MERGE (from:Function {uid: $from_id})
                ON CREATE SET from.func_type = 'IMPORT'
                MERGE (to:Function {uid: $to_id})
                ON CREATE SET to.name = $func_name,
                              to.func_type = 'EXPORT',
                              to.binary_id = 'EXTERNAL',
                              to.binary_name = $dll_name
                MERGE (from)-[r:LINKS_TO]->(to)
                SET r.dll_name = $dll_name, r.func_name = $func_name
                RETURN count(r) as created
            """, edge.to_dict())
            record = result.single()
            if record and record['created'] > 0:
                total_created += record['created']
        
        # REFERENCES关系
        for edge in graph_data.references:
            result = tx.run("""
                MATCH (from:Function {uid: $from_id}), (to:String {hash: $to_id})
                MERGE (from)-[:REFERENCES]->(to)
                RETURN count(*) as created
            """, edge.to_dict())
            record = result.single()
            if record and record['created'] > 0:
                total_created += record['created']
        
        # WRITES关系
        for edge in graph_data.writes:
            result = tx.run("""
                MATCH (from:Function {uid: $from_id}), (to:DataSlot {uid: $to_id})
                MERGE (from)-[r:WRITES]->(to)
                SET r.op_type = $op_type, r.const_val = $const_val, r.loc = $loc
                RETURN count(r) as created
            """, edge.to_dict())
            record = result.single()
            if record and record['created'] > 0:
                total_created += record['created']
        
        # READS关系
        for edge in graph_data.reads:
            result = tx.run("""
                MATCH (from:Function {uid: $from_id}), (to:DataSlot {uid: $to_id})
                MERGE (from)-[r:READS]->(to)
                SET r.condition = $condition, r.op_type = $op_type, 
                    r.const_val = $const_val, r.loc = $loc
                RETURN count(r) as created
            """, edge.to_dict())
            record = result.single()
            if record and record['created'] > 0:
                total_created += record['created']
        
        logger.info(f"所有关系导入完成，总共创建了 {total_created} 个关系")
        return total_created
    
    def remove_binary_data(self, database_name: str, binary_hash: str) -> Dict[str, int]:
        """
        从数据库中移除指定二进制文件的所有数据
        
        Args:
            database_name: 数据库名称
            binary_hash: 二进制文件哈希
            
        Returns:
            删除统计信息
        """
        stats = {'nodes_deleted': 0, 'relationships_deleted': 0}
        
        try:
            with self.get_session(database_name) as session:
                with session.begin_transaction() as tx:
                    result = tx.run("""
                        MATCH (b:Binary {hash: $hash})
                        OPTIONAL MATCH (b)-[r]-()
                        WITH b, count(r) as rels
                        DETACH DELETE b
                        RETURN rels as relationships_deleted, 1 as nodes_deleted
                    """, hash=binary_hash)

                    record = result.single()
                    if record:
                        stats['nodes_deleted'] = record.get('nodes_deleted', 0)
                        stats['relationships_deleted'] = record.get('relationships_deleted', 0)
                    
                    logger.info(f"已删除二进制 {binary_hash} 的数据: {stats}")
                    return stats
                    
        except Exception as e:
            raise Neo4jError(f"删除二进制数据失败: {e}")

    def gc_orphan_nodes(self, database_name: str) -> Dict[str, int]:
        """
        删除无任何关系的孤儿节点

        Args:
            database_name: 数据库名称

        Returns:
            删除统计信息
        """
        stats = {'nodes_deleted': 0}

        try:
            with self.get_session(database_name) as session:
                while True:
                    result = session.run("""
                        MATCH (n)
                        WHERE NOT (n)--()
                        WITH n LIMIT 10000
                        DETACH DELETE n
                        RETURN count(n) as deleted
                    """)

                    record = result.single()
                    batch_deleted = record.get('deleted', 0) if record else 0
                    stats['nodes_deleted'] += batch_deleted

                    if batch_deleted == 0:
                        break

                logger.info("孤儿节点GC完成: %s", stats)
                return stats

        except Exception as e:
            raise Neo4jError(f"孤儿节点GC失败: {e}")
    
    def get_database_stats(self, database_name: str) -> Dict[str, int]:
        """
        获取数据库统计信息
        
        Args:
            database_name: 数据库名称
            
        Returns:
            统计信息字典
        """
        try:
            with self.get_session(database_name) as session:
                # 获取节点数量
                node_result = session.run("""
                    MATCH (n)
                    RETURN labels(n) as labels, count(n) as count
                """)
                
                node_stats = {}
                total_nodes = 0
                for record in node_result:
                    labels = record["labels"]
                    count = record["count"]
                    if labels:
                        label = labels[0]  # 取第一个标签
                        node_stats[f"{label.lower()}_nodes"] = count
                        total_nodes += count
                
                # 获取关系数量
                rel_result = session.run("""
                    MATCH ()-[r]->()
                    RETURN type(r) as type, count(r) as count
                """)
                
                rel_stats = {}
                total_relationships = 0
                for record in rel_result:
                    rel_type = record["type"]
                    count = record["count"]
                    rel_stats[f"{rel_type.lower()}_relationships"] = count
                    total_relationships += count
                
                stats = {
                    'total_nodes': total_nodes,
                    'total_relationships': total_relationships,
                    **node_stats,
                    **rel_stats
                }
                
                return stats
                
        except Exception as e:
            logger.error(f"获取数据库统计信息失败: {e}")
            return {}
    
    def test_connection(self) -> Dict[str, Any]:
        """
        测试数据库连接并返回服务器信息
        
        Returns:
            连接信息字典
        """
        try:
            with self.get_session() as session:
                result = session.run("CALL dbms.components()") 
                components = list(result)
                
                server_info = {}
                for component in components:
                    name = component.get("name", "")
                    versions = component.get("versions", [])
                    if name == "Neo4j Kernel" and versions:
                        server_info["version"] = versions[0]
                    server_info["edition"] = component.get("edition", "unknown")
                
                server_info["uri"] = self.uri
                server_info["connected"] = True
                
                return server_info
                
        except Exception as e:
            return {
                "uri": self.uri,
                "connected": False,
                "error": str(e)
            }