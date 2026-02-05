#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA-Graphy - Binary Analysis Framework with Graph Database Integration
Project-based binary analysis with Neo4j integration

Commands:
  project create <name>                 Create a new project
  project delete <name>                 Delete a project and its database
  project list                          List all projects
  project info <name>                   Show project information
  
  project add <name> <binary_path>      Add binary file to project
  project remove <name> <binary_path>   Remove binary file from project
  
  project sync <name>                   Analyze and sync project to database
  project status <name>                 Check project sync status
  
  neo4j test                            Test Neo4j connection
  neo4j databases                       List Neo4j databases
  
  monitor start <name>                  Start file monitoring for project
  monitor stop <name>                   Stop file monitoring for project

Example:
  ida-graphy project create malware_analysis --description "APT campaign analysis"
  ida-graphy project add malware_analysis sample1.exe
  ida-graphy project add malware_analysis sample2.dll
  ida-graphy project sync malware_analysis
"""

import sys
import os
import argparse
import logging
import yaml
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import time

# Import project management modules
from core.project.manager import ProjectManager, ProjectError, Project
from core.file_watcher import FileWatcher, ProjectFileMonitor, create_project_monitor
from exporters.export_manager import ExportManager
from exporters.neo4j_exporter import create_neo4j_exporter

# Global logger
logger = logging.getLogger('ida-graphy')


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """配置日志系统"""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    logger.setLevel(level)


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """加载配置文件
    
    Args:
        config_path: 配置文件路径，如果为None则使用config.yaml
        
    Returns:
        配置字典
        
    Raises:
        FileNotFoundError: 配置文件不存在
        ValueError: 配置文件格式错误或缺少必需配置
    """
    # 确定配置文件路径
    if config_path is None:
        config_path = "config.yaml"
    
    # 检查配置文件是否存在
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"配置文件不存在: {config_path}\n"
            f"请确保config.yaml文件存在于当前目录，或使用--config参数指定配置文件路径"
        )
    
    # 加载配置文件
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        raise ValueError(f"读取配置文件失败: {config_path}\n错误: {e}")
    
    # 验证必需的配置项
    required_sections = ['ida', 'export', 'analysis', 'neo4j', 'projects', 'logging']
    missing_sections = []
    
    for section in required_sections:
        if section not in config:
            missing_sections.append(section)
    
    if missing_sections:
        raise ValueError(
            f"配置文件缺少必需的部分: {', '.join(missing_sections)}\n"
            f"请检查config.yaml文件的完整性"
        )
    
    # 验证关键配置项
    required_keys = {
        'ida': ['path', 'idalib_python'],
        'neo4j': ['connection', 'projects'],
        'neo4j.connection': ['uri', 'user', 'password'],
        'projects': ['root_dir']
    }
    
    missing_keys = []
    for section, keys in required_keys.items():
        section_parts = section.split('.')
        current_config = config
        
        # 导航到嵌套配置
        for part in section_parts:
            if part not in current_config:
                missing_keys.append(f"{section}.{keys}")
                break
            current_config = current_config[part]
        else:
            # 检查必需的键
            for key in keys:
                if key not in current_config:
                    missing_keys.append(f"{section}.{key}")
    
    if missing_keys:
        raise ValueError(
            f"配置文件缺少必需的配置项: {', '.join(missing_keys)}\n"
            f"请检查config.yaml文件中的配置项"
        )
    
    logger.info(f"配置文件加载成功: {config_path}")
    return config


def ensure_ida_available(config: Dict) -> bool:
    """检查IDA和idalib是否可用"""
    ida_path = config['ida']['path']
    idalib_path = config['ida']['idalib_python']
    
    if not os.path.exists(ida_path):
        logger.error(f"IDA路径不存在: {ida_path}")
        return False
    
    if not os.path.exists(idalib_path):
        logger.error(f"idalib路径不存在: {idalib_path}")
        return False
    
    # 尝试导入idalib（IDA Pro 9.0+中模块名为idapro）
    try:
        sys.path.insert(0, idalib_path)
        import idapro as idalib
        logger.debug("idalib导入成功")
        return True
    except ImportError as e:
        logger.error(f"无法导入idalib: {e}")
        logger.error("请确保IDA 9.0+已安装并且支持idalib")
        return False


def analyze_project_binaries(project, config: Dict[str, Any]):
    """分析项目中的二进制文件
    
    Args:
        project: 项目对象
        config: 配置字典
        
    Returns:
        GraphData对象，如果分析失败则返回None
    """
    from core.models import GraphData
    from core.mapping.symbol_resolver import resolve_symbols
    from core.mapping.symbol_resolver import resolve_symbols
    from exporters.export_manager import ExportManager
    import tempfile
    import shutil
    import os
    
    # 检查IDA配置
    if not ensure_ida_available(config):
        logger.error("IDA不可用，无法进行分析")
        return None
    
    # 合并的图数据
    merged_graph = GraphData()
    
    logger.info(f"开始分析 {len(project.binaries)} 个二进制文件...")
    
    # 添加IDA路径到环境
    idalib_path = config['ida']['idalib_python']
    if idalib_path not in sys.path:
        sys.path.insert(0, idalib_path)
    
    try:
        import idapro as idalib
        import ida_auto
    except ImportError as e:
        logger.error(f"无法导入IDA库: {e}")
        return None
    
    exporter = ExportManager(config, project)
    enable_file_export = config.get("export", {}).get("enable_file_export", False)

    for i, binary in enumerate(project.binaries, 1):
        logger.info(f"[{i}/{len(project.binaries)}] 分析文件: {binary.name}")
        
        try:
            # 检查文件是否存在
            if not os.path.exists(binary.path):
                logger.warning(f"文件不存在，跳过: {binary.path}")
                continue
                
            # 读取二进制内容
            with open(binary.path, 'rb') as f:
                binary_content = f.read()
            
            # 使用idalib打开数据库
            logger.info(f"使用IDA分析: {binary.path}")
            result = idalib.open_database(binary.path, True)
            
            if result == 0:
                # 等待自动分析完成
                logger.info("等待IDA自动分析完成...")
                ida_auto.auto_wait()
                
                # 执行提取与映射
                logger.info("提取原始数据...")
                from core.extraction.engine import ExtractionEngine
                from core.mapping.graph_mapper import GraphMapper

                enable_dataflow = config.get('analysis', {}).get('enable_dataflow', True)
                engine = ExtractionEngine(binary.path, enable_dataflow=enable_dataflow)
                raw_data = engine.extract()
                
                logger.info("映射为图数据...")
                mapper = GraphMapper(binary_content=binary_content)
                graph_data = mapper.map(raw_data)

                if config.get("export", {}).get("enable_file_export", False):
                    exporter = ExportManager(config, project)
                    exporter.export_files(binary.path, graph_data)
                
                # 合并到总图数据中
                merged_graph.merge(graph_data)

                if enable_file_export:
                    exporter.export_files(binary.path, graph_data)
                
                logger.info(f"完成分析: {binary.name} - 节点:{graph_data.node_count()}, 边:{graph_data.edge_count()}")
                
                # 关闭数据库
                idalib.close_database()
                
            else:
                logger.error(f"IDA无法打开文件: {binary.path} (错误码: {result})")
                
        except Exception as e:
            logger.error(f"分析文件失败 {binary.name}: {e}")
            # 尝试关闭数据库（如果打开了的话）
            try:
                idalib.close_database()
            except:
                pass
            continue
    
    if merged_graph.node_count() > 0:
        binary_names = {b.hash: b.name for b in merged_graph.binaries}
        merged_graph.links_to = resolve_symbols(
            merged_graph.functions,
            merged_graph.links_to,
            binary_names,
        )
        binary_names = {b.hash: b.name for b in merged_graph.binaries}
        merged_graph.links_to = resolve_symbols(
            merged_graph.functions,
            merged_graph.links_to,
            binary_names,
        )
        logger.info(f"✅ 项目分析完成 - 总节点: {merged_graph.node_count()}, 总边: {merged_graph.edge_count()}")
        return merged_graph
    else:
        logger.warning("分析完成，但未生成任何图数据")
        return GraphData()  # 返回空图数据而不是None


def calculate_file_hash(file_path: str) -> str:
    """计算文件SHA256哈希
    
    Args:
        file_path: 文件路径
        
    Returns:
        SHA256哈希字符串
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================================
# 项目管理命令
# ============================================================================

def cmd_project_create(args, config: Dict) -> int:
    """创建新项目"""
    try:
        project_manager = ProjectManager(config['projects']['root_dir'])
        
        metadata = project_manager.create_project(
            project_name=args.name,
            description=args.description or "",
            config_overrides={},
            config=config
        )
        
        print(f"✅ 项目 '{args.name}' 创建成功")
        print(f"   数据库: {metadata.database_name}")
        print(f"   目录: {project_manager._get_project_dir(args.name)}")
        
        # 如果配置了Neo4j，创建数据库
        if config['neo4j']['projects']['auto_create_database']:
            try:
                exporter = create_neo4j_exporter(config)
                if exporter.neo4j_manager:
                    exporter.neo4j_manager.create_database(metadata.database_name)
                    print(f"✅ Neo4j数据库 '{metadata.database_name}' 创建成功")
            except Exception as e:
                logger.warning(f"创建Neo4j数据库失败: {e}")
        
        return 0
        
    except ProjectError as e:
        logger.error(f"创建项目失败: {e}")
        return 1


def cmd_project_delete(args, config: Dict) -> int:
    """删除项目"""
    try:
        project_manager = ProjectManager(config['projects']['root_dir'])
        
        if not args.force:
            # 确认删除
            response = input(f"确定要删除项目 '{args.name}' 吗？这将删除所有数据 [y/N]: ")
            if response.lower() not in ('y', 'yes'):
                print("取消删除操作")
                return 0
        
        # 获取项目数据库名
        try:
            project = project_manager.get_project(args.name)
            database_name = project.database_name
        except:
            database_name = None
        
        # 删除项目
        project_manager.delete_project(args.name, force=args.force)
        print(f"✅ 项目 '{args.name}' 删除成功")
        
        # 删除Neo4j数据库
        if database_name and config['neo4j']['projects']['drop_database_on_delete']:
            try:
                exporter = create_neo4j_exporter(config)
                if exporter.neo4j_manager:
                    exporter.neo4j_manager.drop_database(database_name, if_exists=True)
                    print(f"✅ Neo4j数据库 '{database_name}' 删除成功")
            except Exception as e:
                logger.warning(f"删除Neo4j数据库失败: {e}")
        
        return 0
        
    except ProjectError as e:
        logger.error(f"删除项目失败: {e}")
        return 1


def cmd_project_list(args, config: Dict) -> int:
    """列出所有项目"""
    try:
        project_manager = ProjectManager(config['projects']['root_dir'])
        projects = project_manager.list_projects()
        
        if not projects:
            print("没有找到项目")
            return 0
        
        print(f"找到 {len(projects)} 个项目:")
        print()
        
        for project in projects:
            print(f"📁 {project.name}")
            print(f"   描述: {project.description or '无'}")
            print(f"   创建时间: {project.created_time}")
            print(f"   二进制文件: {len(project.binaries)}")
            print(f"   数据库: {project.database_name}")
            print()
        
        return 0
        
    except Exception as e:
        logger.error(f"列出项目失败: {e}")
        return 1


def cmd_project_info(args, config: Dict) -> int:
    """显示项目详细信息"""
    try:
        project_manager = ProjectManager(config['projects']['root_dir'])
        project = project_manager.get_project(args.name)
        
        print(f"📁 项目: {project.name}")
        print(f"   描述: {project.description or '无'}")
        print(f"   创建时间: {project.created_time}")
        print(f"   最后修改: {project.modified_time}")
        print(f"   数据库: {project.database_name}")
        print()
        
        if project.binaries:
            print(f"二进制文件 ({len(project.binaries)} 个):")
            for binary in project.binaries:
                print(f"  📄 {binary.name}")
                print(f"     路径: {binary.path}")
                print(f"     大小: {binary.size} bytes")
                print(f"     哈希: {binary.hash[:16]}...")
                print(f"     添加时间: {binary.added_time}")
                
                if binary.last_analyzed:
                    print(f"     最后分析: {binary.last_analyzed}")
                else:
                    print(f"     状态: 未分析")
                print()
        else:
            print("项目中没有二进制文件")
        
        # 检查数据库状态
        try:
            exporter = create_neo4j_exporter(config)
            if exporter.neo4j_manager:
                stats = exporter.get_database_stats(project)
                if stats:
                    print("数据库统计:")
                    for key, value in stats.items():
                        print(f"  {key}: {value}")
        except Exception as e:
            logger.debug(f"获取数据库统计失败: {e}")
        
        return 0
        
    except ProjectError as e:
        logger.error(f"获取项目信息失败: {e}")
        return 1


def cmd_project_add(args, config: Dict) -> int:
    """向项目添加二进制文件"""
    try:
        project_manager = ProjectManager(config['projects']['root_dir'])
        
        # 检查文件是否存在
        if not os.path.exists(args.binary_path):
            logger.error(f"文件不存在: {args.binary_path}")
            return 1
        
        binary_file = project_manager.add_binary(args.name, args.binary_path)
        
        print(f"✅ 文件已添加到项目 '{args.name}':")
        print(f"   文件: {binary_file.name}")
        print(f"   路径: {binary_file.path}")
        print(f"   大小: {binary_file.size} bytes")
        print(f"   哈希: {binary_file.hash}")
        
        return 0
        
    except ProjectError as e:
        logger.error(f"添加文件失败: {e}")
        return 1


def cmd_project_remove(args, config: Dict) -> int:
    """从项目中移除二进制文件"""
    try:
        project_manager = ProjectManager(config['projects']['root_dir'])
        
        if not args.force:
            # 确认移除
            response = input(f"确定要从项目 '{args.name}' 中移除文件 '{args.binary_path}' 吗？[y/N]: ")
            if response.lower() not in ('y', 'yes'):
                print("取消移除操作")
                return 0
        
        project_manager.remove_binary(args.name, args.binary_path)
        
        print(f"✅ 文件已从项目 '{args.name}' 中移除: {args.binary_path}")
        
        return 0
        
    except ProjectError as e:
        logger.error(f"移除文件失败: {e}")
        return 1


def cmd_project_sync(args, config: Dict) -> int:
    """同步项目到数据库"""
    try:
        if not ensure_ida_available(config):
            return 1
        
        project_manager = ProjectManager(config['projects']['root_dir'])
        project = project_manager.get_project(args.name)
        
        if not project.binaries:
            logger.error(f"项目 '{args.name}' 中没有二进制文件")
            return 1
        
        print(f"🔄 开始同步项目 '{args.name}' 到数据库...")
        
        # 检查文件变化
        changes = project_manager.check_file_changes(args.name)
        changed_files = [binary for binary, status in changes if status in ('modified', 'missing')]
        
        if changed_files:
            print(f"检测到 {len(changed_files)} 个文件变化")
            for binary in changed_files:
                print(f"  - {binary.path}")
        
        # TODO: 集成分析流程
        # 这里需要调用实际的IDA分析流程来生成图数据
        # 现在先创建一个空的图数据作为占位符
        from core.models import GraphData
        
        # 分析项目中的二进制文件
        graph_data = analyze_project_binaries(project, config)
        
        if graph_data is None:
            logger.error("分析失败，无法生成图数据")
            return 1
        
        # 导出到Neo4j
        try:
            neo4j_exporter = create_neo4j_exporter(config)
            if neo4j_exporter.neo4j_manager:
                changed_hashes = [binary.hash for binary in changed_files] if changed_files else None
                stats = neo4j_exporter.sync_project_to_neo4j(project, graph_data, changed_hashes)

                print("✅ 同步完成:")
                print(f"   创建节点: {stats.get('nodes_created', 0)}")
                print(f"   创建关系: {stats.get('relationships_created', 0)}")
                print(f"   删除节点: {stats.get('nodes_deleted', 0)}")
            else:
                logger.error("Neo4j未配置或连接失败，无法同步")
                return 1

        except Exception as e:
            logger.error(f"同步失败: {e}")
            return 1
        
        # 更新分析时间
        for binary in project.binaries:
            if binary.path not in [b.path for b in changed_files] or not changed_files:
                project_manager.update_binary_analysis_time(args.name, binary.path)
        
        return 0
        
    except ProjectError as e:
        logger.error(f"同步项目失败: {e}")
        return 1


def cmd_project_status(args, config: Dict) -> int:
    """检查项目同步状态"""
    try:
        project_manager = ProjectManager(config['projects']['root_dir'])
        project = project_manager.get_project(args.name)
        
        print(f"📊 项目状态: {project.name}")
        
        if not project.binaries:
            print("   项目中没有二进制文件")
            return 0
        
        # 检查文件变化
        changes = project_manager.check_file_changes(args.name)
        
        unanalyzed_count = 0
        modified_count = 0
        missing_count = 0
        unchanged_count = 0
        
        for binary, status in changes:
            if binary.last_analyzed is None:
                unanalyzed_count += 1
            
            if status == 'modified':
                modified_count += 1
            elif status == 'missing':
                missing_count += 1
            elif status == 'unchanged':
                unchanged_count += 1
        
        print(f"   文件状态:")
        print(f"     未分析: {unanalyzed_count}")
        print(f"     已修改: {modified_count}")
        print(f"     已丢失: {missing_count}")
        print(f"     未变化: {unchanged_count}")
        
        if unanalyzed_count > 0 or modified_count > 0:
            print("   状态: 🔄 需要同步")
        elif missing_count > 0:
            print("   状态: ⚠️  有文件丢失")
        else:
            print("   状态: ✅ 已同步")
        
        # 显示数据库统计
        try:
            exporter = create_neo4j_exporter(config)
            if exporter.neo4j_manager:
                stats = exporter.get_database_stats(project)
                if stats:
                    print(f"   数据库统计:")
                    print(f"     节点总数: {stats.get('total_nodes', 0)}")
                    print(f"     关系总数: {stats.get('total_relationships', 0)}")
        except Exception as e:
            logger.debug(f"获取数据库统计失败: {e}")
        
        return 0
        
    except ProjectError as e:
        logger.error(f"检查项目状态失败: {e}")
        return 1


# ============================================================================
# Neo4j管理命令
# ============================================================================

def cmd_neo4j_test(args, config: Dict) -> int:
    """测试Neo4j连接"""
    try:
        exporter = create_neo4j_exporter(config)
        if not exporter.neo4j_manager:
            logger.error("Neo4j未配置")
            return 1
        
        info = exporter.test_connection()
        
        if info.get('connected'):
            print("✅ Neo4j连接成功")
            print(f"   URI: {info.get('uri')}")
            print(f"   版本: {info.get('version', '未知')}")
            print(f"   版本: {info.get('edition', '未知')}")
        else:
            print("❌ Neo4j连接失败")
            print(f"   错误: {info.get('error')}")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"测试Neo4j连接失败: {e}")
        return 1


def cmd_neo4j_databases(args, config: Dict) -> int:
    """列出Neo4j数据库"""
    try:
        exporter = create_neo4j_exporter(config)
        if not exporter.neo4j_manager:
            logger.error("Neo4j未配置")
            return 1
        
        databases = exporter.neo4j_manager.list_databases()
        
        print(f"Neo4j数据库 ({len(databases)} 个):")
        
        project_prefix = config['neo4j']['projects']['database_prefix']
        
        for db in databases:
            if db.startswith(project_prefix):
                project_name = db[len(project_prefix):]
                print(f"  📊 {db} (项目: {project_name})")
            else:
                print(f"  🔧 {db}")
        
        return 0
        
    except Exception as e:
        logger.error(f"列出数据库失败: {e}")
        return 1


# ============================================================================
# 监控管理命令
# ============================================================================

def cmd_monitor_start(args, config: Dict) -> int:
    """开始文件监控"""
    print("⚠️  文件监控功能需要在后台服务中实现")
    print("当前版本暂不支持交互式监控")
    return 1


def cmd_monitor_stop(args, config: Dict) -> int:
    """停止文件监控"""
    print("⚠️  文件监控功能需要在后台服务中实现")
    print("当前版本暂不支持交互式监控")
    return 1


# ============================================================================
# 命令行解析
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """创建命令行解析器"""
    parser = argparse.ArgumentParser(
        description='IDA-Graphy - 项目式二进制分析框架',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 创建新项目
  ida-graphy project create malware_analysis --description "恶意软件分析"
  
  # 添加二进制文件
  ida-graphy project add malware_analysis sample1.exe
  ida-graphy project add malware_analysis sample2.dll
  
  # 分析并同步到数据库
  ida-graphy project sync malware_analysis
  
  # 检查项目状态
  ida-graphy project status malware_analysis
  
  # 测试Neo4j连接
  ida-graphy neo4j test
        """
    )
    
    # 全局参数
    parser.add_argument('--config', '-c', help='配置文件路径')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    parser.add_argument('--log-file', help='日志文件路径')
    
    # 子命令
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 项目管理命令
    project_parser = subparsers.add_parser('project', help='项目管理')
    project_subparsers = project_parser.add_subparsers(dest='project_action', help='项目操作')
    
    # project create
    create_parser = project_subparsers.add_parser('create', help='创建项目')
    create_parser.add_argument('name', help='项目名称')
    create_parser.add_argument('--description', '-d', help='项目描述')
    
    # project delete
    delete_parser = project_subparsers.add_parser('delete', help='删除项目')
    delete_parser.add_argument('name', help='项目名称')
    delete_parser.add_argument('--force', '-f', action='store_true', help='强制删除，不询问')
    
    # project list
    project_subparsers.add_parser('list', help='列出项目')
    
    # project info
    info_parser = project_subparsers.add_parser('info', help='项目信息')
    info_parser.add_argument('name', help='项目名称')
    
    # project add
    add_parser = project_subparsers.add_parser('add', help='添加文件')
    add_parser.add_argument('name', help='项目名称')
    add_parser.add_argument('binary_path', help='二进制文件路径')
    
    # project remove
    remove_parser = project_subparsers.add_parser('remove', help='移除文件')
    remove_parser.add_argument('name', help='项目名称')
    remove_parser.add_argument('binary_path', help='二进制文件路径')
    remove_parser.add_argument('--force', '-f', action='store_true', help='强制移除，不询问')
    
    # project sync
    sync_parser = project_subparsers.add_parser('sync', help='同步到数据库')
    sync_parser.add_argument('name', help='项目名称')
    
    # project status
    status_parser = project_subparsers.add_parser('status', help='检查状态')
    status_parser.add_argument('name', help='项目名称')
    
    # Neo4j管理命令
    neo4j_parser = subparsers.add_parser('neo4j', help='Neo4j数据库管理')
    neo4j_subparsers = neo4j_parser.add_subparsers(dest='neo4j_action', help='Neo4j操作')
    
    neo4j_subparsers.add_parser('test', help='测试连接')
    neo4j_subparsers.add_parser('databases', help='列出数据库')
    
    # 监控命令
    monitor_parser = subparsers.add_parser('monitor', help='文件监控')
    monitor_subparsers = monitor_parser.add_subparsers(dest='monitor_action', help='监控操作')
    
    start_monitor_parser = monitor_subparsers.add_parser('start', help='开始监控')
    start_monitor_parser.add_argument('name', help='项目名称')
    
    stop_monitor_parser = monitor_subparsers.add_parser('stop', help='停止监控')
    stop_monitor_parser.add_argument('name', help='项目名称')
    
    return parser


def main() -> int:
    """主函数"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    # 加载配置
    config = load_config(args.config)
    
    # 设置日志
    setup_logging(args.verbose, args.log_file or config['logging'].get('file'))
    
    try:
        # 分发命令
        if args.command == 'project':
            if args.project_action == 'create':
                return cmd_project_create(args, config)
            elif args.project_action == 'delete':
                return cmd_project_delete(args, config)
            elif args.project_action == 'list':
                return cmd_project_list(args, config)
            elif args.project_action == 'info':
                return cmd_project_info(args, config)
            elif args.project_action == 'add':
                return cmd_project_add(args, config)
            elif args.project_action == 'remove':
                return cmd_project_remove(args, config)
            elif args.project_action == 'sync':
                return cmd_project_sync(args, config)
            elif args.project_action == 'status':
                return cmd_project_status(args, config)
            else:
                parser.print_help()
                return 1
        
        elif args.command == 'neo4j':
            if args.neo4j_action == 'test':
                return cmd_neo4j_test(args, config)
            elif args.neo4j_action == 'databases':
                return cmd_neo4j_databases(args, config)
            else:
                parser.print_help()
                return 1
        
        elif args.command == 'monitor':
            if args.monitor_action == 'start':
                return cmd_monitor_start(args, config)
            elif args.monitor_action == 'stop':
                return cmd_monitor_stop(args, config)
            else:
                parser.print_help()
                return 1
        
        else:
            parser.print_help()
            return 1
    
    except KeyboardInterrupt:
        print("\n操作已取消")
        return 130
    except Exception as e:
        logger.error(f"未预期的错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())