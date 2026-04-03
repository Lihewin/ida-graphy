"""
ExtractionEngine 使用示例
演示如何使用 ExtractionEngine + GraphMapper 提取图数据
"""

import os
import sys

# 添加 core 模块路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.extraction.engine import ExtractionEngine
from core.mapping.graph_mapper import GraphMapper


def example_usage():
    """
    使用示例：在IDA中运行此脚本
    
    在IDA中执行：
    1. 打开二进制文件
    2. Alt+F7 或 File -> Script file
    3. 选择此脚本运行
    """
    
    # 获取当前分析的二进制文件路径
    import ida_nalt
    binary_path = ida_nalt.get_input_file_path()
    
    print(f"[*] Analyzing: {binary_path}")
    
    # 读取二进制文件内容
    with open(binary_path, 'rb') as f:
        binary_content = f.read()
    
    # 提取原始数据并映射
    engine = ExtractionEngine(binary_path)
    raw_data = engine.extract()
    mapper = GraphMapper(binary_content=binary_content)
    graph_data = mapper.map(raw_data)
    
    # 访问提取的数据
    print(f"\n[+] Extraction Results:")
    print(f"    Binary nodes: {len(graph_data.binaries)}")
    print(f"    Function nodes: {len(graph_data.functions)}")
    print(f"    String nodes: {len(graph_data.strings)}")
    print(f"    DataSlot nodes: {len(graph_data.dataslots)}")
    print(f"\n    CONTAINS edges: {len(graph_data.contains)}")
    print(f"    CALLS edges: {len(graph_data.calls)}")
    print(f"    REFERENCES edges: {len(graph_data.references)}")
    
    # 示例：列出前5个函数
    print(f"\n[+] Sample Functions:")
    for i, func in enumerate(graph_data.functions[:5]):
        print(f"    {i+1}. {func.name} (Type: {func.func_type}, RVA: 0x{func.rva:X})")
    
    # 示例：列出前5个调用关系
    print(f"\n[+] Sample Call Edges:")
    for i, call in enumerate(graph_data.calls[:5]):
        # 查找函数名
        from_func = next((f for f in graph_data.functions if f.uid == call.from_id), None)
        to_func = next((f for f in graph_data.functions if f.uid == call.to_id), None)
        if from_func and to_func:
            print(f"    {i+1}. {from_func.name} -> {to_func.name} (count: {call.count})")
    
    print(f"\n[✓] Extraction completed successfully!")
    
    return graph_data


def standalone_example(binary_path):
    """
    独立使用示例（在idalib环境中）
    
    Args:
        binary_path: 二进制文件路径
    """
    # 这个示例需要在 idalib 环境中运行（类似 ida_export.py）
    print(f"[*] Opening binary with idalib: {binary_path}")
    
    try:
        import idapro as idalib
        import ida_auto
        
        # 打开数据库
        result = idalib.open_database(binary_path, True)
        if result == 0:
            # 等待自动分析完成
            print("[*] Waiting for auto-analysis to complete...")
            ida_auto.auto_wait()
            
            # 读取二进制内容
            with open(binary_path, 'rb') as f:
                binary_content = f.read()
            
            # 提取原始数据并映射
            engine = ExtractionEngine(binary_path)
            raw_data = engine.extract()
            mapper = GraphMapper(binary_content=binary_content)
            graph_data = mapper.map(raw_data)
            
            print(f"\n[✓] Extracted {graph_data.node_count()} nodes and {graph_data.edge_count()} edges")
            
            # 关闭数据库
            idalib.close_database()
            
            return graph_data
        else:
            print(f"[!] Failed to open database: {result}")
            return None
            
    except ImportError:
        print("[!] idalib not found. This example requires IDA 9.0+ with idalib support.")
        return None


if __name__ == "__main__":
    # 在IDA中运行
    if 'ida_nalt' in sys.modules:
        example_usage()
    else:
        # 独立运行（需要idalib）
        if len(sys.argv) > 1:
            binary_path = sys.argv[1]
            standalone_example(binary_path)
        else:
            print("Usage: python example_usage.py <binary_path>")
