#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA-Graphy - Binary Analysis Framework with Graph Database Integration
Main entry point for analyzing binaries and exporting to CSV/Neo4j format
"""

import sys
import os
import argparse
import logging
import yaml
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
import time

# Global logger
logger = logging.getLogger('ida-graphy')


def setup_logging(verbose: bool = False):
    """配置日志系统"""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    
    logger.setLevel(level)
    logger.addHandler(handler)


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """加载配置文件
    
    Args:
        config_path: 配置文件路径，如果为None则使用默认配置
        
    Returns:
        配置字典
    """
    default_config = {
        'ida': {
            'path': r"C:\Program Files\IDA Professional 9.2",
            'idalib_python': r"C:\Program Files\IDA Professional 9.2\idalib\python"
        },
        'export': {
            'output_dir': './csv_output',
            'skip_lib_functions': True,
            'validate_data': True,
            'generate_stats': True
        },
        'analysis': {
            'enable_dataflow': True,
            'enable_string_refs': True,
            'parallel_workers': 4,
            'max_function_size': 10000
        },
        'neo4j': {
            'home': '/path/to/neo4j',
            'database': 'ida-graphy'
        }
    }
    
    if config_path and os.path.exists(config_path):
        logger.info(f"Loading configuration from: {config_path}")
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f)
                # 递归合并配置
                def merge_dict(base, override):
                    for key, value in override.items():
                        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                            merge_dict(base[key], value)
                        else:
                            base[key] = value
                merge_dict(default_config, user_config)
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            logger.info("Using default configuration")
    else:
        if config_path:
            logger.warning(f"Config file not found: {config_path}")
        logger.info("Using default configuration")
    
    return default_config


def setup_ida_paths(config: Dict[str, Any]) -> bool:
    """设置IDA Python路径
    
    Args:
        config: 配置字典
        
    Returns:
        是否成功设置
    """
    ida_path = config['ida']['path']
    idalib_python = config['ida']['idalib_python']
    
    if not os.path.exists(ida_path):
        logger.error(f"IDA installation not found: {ida_path}")
        return False
    
    # 添加IDA Python路径
    ida_python = os.path.join(ida_path, "python")
    if os.path.exists(ida_python) and ida_python not in sys.path:
        sys.path.append(ida_python)
        logger.debug(f"Added to sys.path: {ida_python}")
    
    # 添加idalib Python路径
    if os.path.exists(idalib_python) and idalib_python not in sys.path:
        sys.path.append(idalib_python)
        logger.debug(f"Added to sys.path: {idalib_python}")
    
    # 尝试导入idalib
    try:
        import idapro as idalib
        logger.info("✓ idalib loaded successfully")
        return True
    except ImportError as e:
        logger.error(f"Failed to import idalib: {e}")
        logger.error("Please ensure IDA 9.0+ is installed with idalib support")
        return False


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


def process_binary(binary_path: str, config: Dict[str, Any], all_nodes: Dict, all_edges: Dict) -> bool:
    """处理单个二进制文件
    
    Args:
        binary_path: 二进制文件路径
        config: 配置字典
        all_nodes: 全局节点字典（用于累积）
        all_edges: 全局边字典（用于累积）
        
    Returns:
        是否处理成功
    """
    import idapro as idalib
    import ida_auto
    
    binary_path = os.path.abspath(binary_path)
    if not os.path.exists(binary_path):
        logger.error(f"Binary file not found: {binary_path}")
        return False
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Processing: {os.path.basename(binary_path)}")
    logger.info(f"{'='*60}")
    
    # 计算文件哈希
    file_hash = calculate_file_hash(binary_path)
    logger.info(f"File hash: {file_hash[:16]}...")
    
    # 打开IDA数据库
    logger.info("Opening binary with idalib...")
    result = idalib.open_database(binary_path, True)
    
    if result != 0:
        logger.error(f"Failed to open database: error code {result}")
        return False
    
    try:
        # 等待自动分析完成
        if not ida_auto.auto_is_ok():
            logger.info("Waiting for IDA auto-analysis to complete...")
            ida_auto.auto_wait()
        
        logger.info("✓ Binary loaded successfully")
        
        # 使用新的图提取器
        logger.info("\n[Phase 1] Extracting graph data...")
        
        # 确保项目根目录在sys.path中
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        
        # 读取二进制文件内容
        with open(binary_path, 'rb') as f:
            binary_content = f.read()
        
        from core.graph_extractor import GraphExtractor
        extractor = GraphExtractor(binary_content, binary_path)
        
        # 设置配置选项
        extractor.enable_dataflow = config['analysis'].get('enable_dataflow', True)
        extractor.enable_string_refs = config['analysis'].get('enable_string_refs', True)
        extractor.skip_lib_functions = config['export'].get('skip_lib_functions', True)
        
        graph_data = extractor.extract_all()
        
        # 将GraphData对象转换为字典格式
        all_nodes['Binary'].extend(graph_data.binaries)
        all_nodes['Function'].extend(graph_data.functions)
        all_nodes['DataSlot'].extend(graph_data.dataslots)
        all_nodes['String'].extend(graph_data.strings)
        
        all_edges['CONTAINS'].extend(graph_data.contains)
        all_edges['CALLS'].extend(graph_data.calls)
        all_edges['LINKS_TO'].extend(graph_data.links_to)
        all_edges['REFERENCES'].extend(graph_data.references)
        all_edges['WRITES'].extend(graph_data.writes)
        all_edges['READS'].extend(graph_data.reads)
        
        logger.info(f"\n✓ Extraction completed:")
        logger.info(f"  - Binary nodes: {len(graph_data.binaries)}")
        logger.info(f"  - Function nodes: {len(graph_data.functions)}")
        logger.info(f"  - DataSlot nodes: {len(graph_data.dataslots)}")
        logger.info(f"  - String nodes: {len(graph_data.strings)}")
        logger.info(f"  - CONTAINS edges: {len(graph_data.contains)} -> accumulated: {len(all_edges['CONTAINS'])}")
        logger.info(f"  - CALLS edges: {len(graph_data.calls)} -> accumulated: {len(all_edges['CALLS'])}")
        logger.info(f"  - Total edges: {graph_data.edge_count()}")
        
        # [Phase 1.5] File Export (while database is still open)
        if config['export'].get('enable_file_export', False):
            try:
                from exporters.file_exporter import FileExporter
                
                logger.info("\n[Phase 1.5] Exporting files (decompiled code, structures, etc.)...")
                logger.info("NOTE: This requires database to be open")
                
                # Get output_dir from config
                output_dir = config['export']['output_dir']
                binary_name = os.path.basename(binary_path)
                
                file_exporter = FileExporter(output_dir, graph_data, binary_name)
                export_results = file_exporter.export_all()
                
                # Update function nodes with file references
                if 'functions' in export_results and export_results['functions'].file_mapping:
                    for func in graph_data.functions:
                        if func.uid in export_results['functions'].file_mapping:
                            mapping = export_results['functions'].file_mapping[func.uid]
                            func.decompiled_file = mapping['path']
                            func.pseudocode_hash = mapping['hash']
                    logger.info(f"✓ Updated {len(export_results['functions'].file_mapping)} functions with file references")
                
                # Update dataslot nodes with struct file references
                if 'structures' in export_results and export_results['structures'].file_mapping:
                    for slot in graph_data.dataslots:
                        if not slot.is_global and slot.base_type in export_results['structures'].file_mapping:
                            mapping = export_results['structures'].file_mapping[slot.base_type]
                            slot.struct_file = mapping['path']
                    logger.info(f"✓ Linked DataSlots to {len(export_results['structures'].file_mapping)} structure files")
                
                logger.info("✓ File export completed")
                
            except Exception as e:
                logger.error(f"File export failed: {e}", exc_info=True)
                logger.warning("Continuing with graph extraction...")
        
        return True
        
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # 关闭数据库（不保存）
        logger.info("\nClosing database...")
        idalib.close_database(False)
        
        # 清理临时文件
        cleanup_temp_files(binary_path)


def cleanup_temp_files(binary_path: str):
    """清理IDA临时文件
    
    Args:
        binary_path: 二进制文件路径
    """
    db_base = os.path.splitext(binary_path)[0]
    temp_exts = ['.id0', '.id1', '.id2', '.nam', '.til', '.unp']
    
    for ext in temp_exts:
        temp_file = db_base + ext
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
                logger.debug(f"Cleaned up: {os.path.basename(temp_file)}")
            except Exception as e:
                logger.warning(f"Failed to delete {temp_file}: {e}")


def export_to_csv(all_nodes: Dict, all_edges: Dict, output_dir: str, config: Dict[str, Any]) -> bool:
    """导出数据到CSV文件
    
    Args:
        all_nodes: 所有节点数据
        all_edges: 所有边数据
        output_dir: 输出目录
        config: 配置字典
        
    Returns:
        是否导出成功
    """
    from exporters.csv_exporter import CSVExporter
    
    logger.info(f"\n[Phase 2] Symbol resolution and CSV export: {output_dir}")
    
    # 符号解析：将LINKS_TO边的虚拟外部ID替换为真实EXPORT函数ID
    if len(all_edges['LINKS_TO']) > 0:
        from core.symbol_resolver import SymbolResolver
        
        resolver = SymbolResolver()
        
        # 构建导出表
        binary_names = {}  # {binary_hash: binary_name}
        for binary in all_nodes['Binary']:
            binary_names[binary.hash] = binary.name
        
        # 按二进制分组函数
        binary_functions = {}
        for func in all_nodes['Function']:
            if func.binary_id not in binary_functions:
                binary_functions[func.binary_id] = []
            binary_functions[func.binary_id].append(func)
        
        # 为每个二进制构建导出表
        for binary_hash, functions in binary_functions.items():
            binary_name = binary_names.get(binary_hash, "unknown")
            resolver.build_export_table(functions, binary_name)
        
        # 解析LINKS_TO边
        all_edges['LINKS_TO'] = resolver.resolve_links_to_edges(all_edges['LINKS_TO'])
    
    exporter = CSVExporter(output_dir, config)
    
    # 转换节点对象为字典
    binaries_dict = [node.to_dict() for node in all_nodes['Binary']]
    functions_dict = [node.to_dict() for node in all_nodes['Function']]
    dataslots_dict = [node.to_dict() for node in all_nodes['DataSlot']]
    strings_dict = [node.to_dict() for node in all_nodes['String']]
    
    # 转换边对象为字典
    contains_dict = [edge.to_dict() for edge in all_edges['CONTAINS']]
    calls_dict = [edge.to_dict() for edge in all_edges['CALLS']]
    links_to_dict = [edge.to_dict() for edge in all_edges['LINKS_TO']]
    references_dict = [edge.to_dict() for edge in all_edges['REFERENCES']]
    writes_dict = [edge.to_dict() for edge in all_edges['WRITES']]
    reads_dict = [edge.to_dict() for edge in all_edges['READS']]
    
    # 调试输出
    logger.info(f"Converting edges to dict: CONTAINS={len(contains_dict)}, CALLS={len(calls_dict)}")
    
    # 调用导出函数
    exporter.export_all(
        binaries_dict,
        functions_dict,
        dataslots_dict,
        strings_dict,
        contains_dict,
        calls_dict,
        links_to_dict,
        references_dict,
        writes_dict,
        reads_dict,
        validate=config['export'].get('validate_data', True)
    )
    
    if config['export'].get('generate_stats', True):
        logger.info("Generating statistics...")
        exporter.generate_stats_report()
    
    logger.info(f"\n✓ CSV export completed!")
    return True


def process_multiple_binaries(binaries: List[str], config: Dict[str, Any]) -> bool:
    """批量处理多个二进制文件
    
    Args:
        binaries: 二进制文件路径列表
        config: 配置字典
        
    Returns:
        是否全部处理成功
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"Batch Processing Mode: {len(binaries)} binaries")
    logger.info(f"{'='*60}")
    
    # 初始化全局数据容器
    all_nodes = {
        'Binary': [],
        'Function': [],
        'DataSlot': [],
        'String': []
    }
    all_edges = {
        'CONTAINS': [],
        'CALLS': [],
        'LINKS_TO': [],
        'REFERENCES': [],
        'WRITES': [],
        'READS': []
    }
    
    success_count = 0
    failed_binaries = []
    
    start_time = time.time()
    
    for idx, binary_path in enumerate(binaries, 1):
        logger.info(f"\n[Binary {idx}/{len(binaries)}]")
        
        try:
            if process_binary(binary_path, config, all_nodes, all_edges):
                success_count += 1
            else:
                failed_binaries.append(binary_path)
        except Exception as e:
            logger.error(f"Unexpected error processing {binary_path}: {e}")
            failed_binaries.append(binary_path)
    
    elapsed_time = time.time() - start_time
    
    # 导出CSV
    output_dir = config['export']['output_dir']
    os.makedirs(output_dir, exist_ok=True)
    export_to_csv(all_nodes, all_edges, output_dir, config)
    
    # 打印总结
    logger.info(f"\n{'='*60}")
    logger.info("Processing Summary")
    logger.info(f"{'='*60}")
    logger.info(f"Total binaries: {len(binaries)}")
    logger.info(f"Successful: {success_count}")
    logger.info(f"Failed: {len(failed_binaries)}")
    logger.info(f"Time elapsed: {elapsed_time:.2f}s ({elapsed_time/60:.2f}min)")
    
    if failed_binaries:
        logger.warning("\nFailed binaries:")
        for binary in failed_binaries:
            logger.warning(f"  - {binary}")
    
    return len(failed_binaries) == 0


def parse_args() -> argparse.Namespace:
    """解析命令行参数
    
    Returns:
        参数命名空间
    """
    parser = argparse.ArgumentParser(
        description='IDA-Graphy: Binary Analysis Framework with Graph Database Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze single binary
  %(prog)s --binary exploit.exe --output ./csv_output
  
  # Analyze multiple binaries
  %(prog)s --binaries kernel32.dll user32.dll app.exe --output ./csv_output
  
  # Use custom configuration
  %(prog)s --config config.yaml --binaries *.dll
  
  # Debug mode (skip dataflow analysis)
  %(prog)s --binary test.dll --no-dataflow --verbose
  
  # Validate existing CSV files
  %(prog)s --validate-csv ./csv_output
        '''
    )
    
    # 输入参数
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument(
        '--binary',
        type=str,
        help='Path to a single binary file to analyze'
    )
    input_group.add_argument(
        '--binaries',
        nargs='+',
        type=str,
        help='Paths to multiple binary files to analyze'
    )
    
    # 配置参数
    parser.add_argument(
        '--config',
        type=str,
        help='Path to YAML configuration file (default: use built-in config)'
    )
    
    # 输出参数
    parser.add_argument(
        '--output',
        type=str,
        default='./csv_output',
        help='Output directory for CSV files (default: ./csv_output)'
    )
    
    # 分析选项
    parser.add_argument(
        '--no-dataflow',
        action='store_true',
        help='Disable dataflow analysis (faster, for testing)'
    )
    
    parser.add_argument(
        '--skip-lib-functions',
        action='store_true',
        default=True,
        help='Skip library functions during analysis (default: True)'
    )
    
    parser.add_argument(
        '--export-files',
        action='store_true',
        help='Export decompiled code, structures, and other files (requires Hex-Rays)'
    )
    
    # 调试选项
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    # 验证选项
    parser.add_argument(
        '--validate-csv',
        type=str,
        metavar='DIR',
        help='Validate existing CSV files in specified directory'
    )
    
    args = parser.parse_args()
    
    # 参数验证
    if not args.validate_csv and not args.binary and not args.binaries:
        parser.error("One of --binary, --binaries, or --validate-csv is required")
    
    return args


def validate_csv_files(csv_dir: str) -> bool:
    """验证CSV文件有效性
    
    Args:
        csv_dir: CSV目录路径
        
    Returns:
        是否验证通过
    """
    logger.info(f"Validating CSV files in: {csv_dir}")
    
    # TODO: 实现CSV验证逻辑
    # from exporters.csv_exporter import CSVExporter
    # exporter = CSVExporter(csv_dir)
    # return exporter.validate()
    
    logger.info("CSV validation will be implemented in future version")
    return True


def main():
    """主入口函数"""
    args = parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    logger.info("=" * 60)
    logger.info("IDA-Graphy - Binary Analysis Framework")
    logger.info("=" * 60)
    
    # 如果是验证模式
    if args.validate_csv:
        if validate_csv_files(args.validate_csv):
            logger.info("\n✓ CSV validation passed")
            return 0
        else:
            logger.error("\n✗ CSV validation failed")
            return 1
    
    # 加载配置
    config = load_config(args.config)
    
    # 覆盖配置（命令行参数优先级更高）
    if args.output:
        config['export']['output_dir'] = args.output
    if args.no_dataflow:
        config['analysis']['enable_dataflow'] = False
    if args.skip_lib_functions:
        config['export']['skip_lib_functions'] = True
    if args.export_files:
        config['export']['enable_file_export'] = True
    
    # 显示配置摘要
    logger.info("\nConfiguration:")
    logger.info(f"  IDA Path: {config['ida']['path']}")
    logger.info(f"  Output Dir: {config['export']['output_dir']}")
    logger.info(f"  Dataflow Analysis: {config['analysis']['enable_dataflow']}")
    logger.info(f"  Skip Library Functions: {config['export']['skip_lib_functions']}")
    logger.info(f"  Export Files: {config['export'].get('enable_file_export', False)}")
    
    # 设置IDA路径
    if not setup_ida_paths(config):
        logger.error("Failed to setup IDA environment")
        return 1
    
    # 收集所有需要处理的二进制文件
    binaries = []
    if args.binary:
        binaries = [args.binary]
    elif args.binaries:
        binaries = args.binaries
    
    # 展开通配符
    expanded_binaries = []
    for pattern in binaries:
        from glob import glob
        matches = glob(pattern)
        if matches:
            expanded_binaries.extend(matches)
        else:
            logger.warning(f"No files match pattern: {pattern}")
    
    if not expanded_binaries:
        logger.error("No binaries to process")
        return 1
    
    # 处理二进制文件
    try:
        if len(expanded_binaries) == 1:
            # 单文件模式
            all_nodes = {'Binary': [], 'Function': [], 'DataSlot': [], 'String': []}
            all_edges = {'CONTAINS': [], 'CALLS': [], 'LINKS_TO': [], 'REFERENCES': [], 'WRITES': [], 'READS': []}
            
            if process_binary(expanded_binaries[0], config, all_nodes, all_edges):
                output_dir = config['export']['output_dir']
                os.makedirs(output_dir, exist_ok=True)
                export_to_csv(all_nodes, all_edges, output_dir, config)
                
                logger.info("\n✓ Analysis completed successfully")
                return 0
            else:
                logger.error("\n✗ Analysis failed")
                return 1
        else:
            # 多文件模式
            if process_multiple_binaries(expanded_binaries, config):
                logger.info("\n✓ Batch processing completed successfully")
                return 0
            else:
                logger.warning("\n⚠ Batch processing completed with errors")
                return 1
    
    except KeyboardInterrupt:
        logger.warning("\n\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
