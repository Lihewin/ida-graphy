"""
CSV Exporter测试脚本
用于验证导出器的功能和生成示例数据
"""

import sys
import os

# 添加父目录到路径以便导入模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exporters.csv_exporter import CSVExporter, NodeIDGenerator


def create_test_data():
    """创建测试数据"""
    
    # 模拟Binary哈希
    binary_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    
    # 创建ID生成器
    id_gen = NodeIDGenerator(binary_hash=binary_hash)
    
    # Binary节点
    binaries = [
        {
            'hash': binary_hash,
            'name': 'test_binary.exe',
            'orig_name': 'test_binary.exe',
            'base_addr': 0x400000,
            'arch': 'x86_64',
            'compile_ts': 1609459200
        }
    ]
    
    # Function节点
    functions = []
    func_data = [
        (0x1000, 'main', 512, False, 'NORMAL', 'int main(int argc, char** argv)', 8),
        (0x1200, 'Process_Data', 256, False, 'NORMAL', 'void Process_Data(void* ctx)', 5),
        (0x1400, 'Validate_Input', 128, False, 'NORMAL', 'bool Validate_Input(char* input)', 3),
        (0x1600, 'printf', 64, True, 'IMPORT', 'int printf(const char* fmt, ...)', 1),
        (0x1800, 'malloc', 32, True, 'IMPORT', 'void* malloc(size_t size)', 1),
    ]
    
    for rva, name, size, is_lib, func_type, sig, complexity in func_data:
        functions.append({
            'uid': id_gen.get_function_id(rva),
            'rva': rva,
            'name': name,
            'orig_name': name,
            'size': size,
            'is_lib': is_lib,
            'func_type': func_type,
            'signature': sig,
            'complexity': complexity,
            'binary_id': binary_hash
        })
    
    # DataSlot节点（结构体成员）
    dataslots = []
    struct_data = [
        ('SessionEntry', 0, 8, 'session_id', False),
        ('SessionEntry', 8, 4, 'status', False),
        ('SessionEntry', 12, 4, 'flags', False),
        ('SessionEntry', 16, 8, 'timestamp', False),
        ('PacketHeader', 0, 4, 'magic', False),
        ('PacketHeader', 4, 4, 'length', False),
    ]
    
    for base_type, offset, size, name, is_global in struct_data:
        dataslots.append({
            'uid': id_gen.get_struct_slot_id(base_type, offset),
            'base_type': base_type,
            'base_type_orig': base_type,
            'offset': offset,
            'size': size,
            'name': name,
            'orig_name': name,
            'is_global': is_global
        })
    
    # DataSlot节点（全局变量）
    global_data = [
        (0x5000, 4, 'g_config'),
        (0x5010, 8, 'g_session_count'),
    ]
    
    for rva, size, name in global_data:
        dataslots.append({
            'uid': id_gen.get_global_slot_id(rva),
            'base_type': 'GLOBAL',
            'base_type_orig': 'GLOBAL',
            'offset': rva,
            'size': size,
            'name': name,
            'orig_name': name,
            'is_global': True
        })
    
    # String节点
    strings = []
    string_data = [
        'Connection established',
        'Invalid input detected',
        'Processing packet...',
        'Error: Memory allocation failed',
    ]
    
    for content in string_data:
        strings.append({
            'hash': id_gen.get_string_id(content),
            'content': content,
            'orig_name': content,
            'encoding': 'ASCII'
        })
    
    # CONTAINS边
    contains_edges = []
    # Binary包含所有Functions
    for func in functions:
        contains_edges.append({
            'from_id': binary_hash,
            'to_id': func['uid'],
            'to_type': 'Function'
        })
    # Binary包含所有DataSlots
    for slot in dataslots:
        contains_edges.append({
            'from_id': binary_hash,
            'to_id': slot['uid'],
            'to_type': 'DataSlot'
        })
    # Binary包含所有Strings
    for string in strings:
        contains_edges.append({
            'from_id': binary_hash,
            'to_id': string['hash'],
            'to_type': 'String'
        })
    
    # CALLS边
    calls_edges = [
        {
            'from_id': id_gen.get_function_id(0x1000),  # main
            'to_id': id_gen.get_function_id(0x1200),    # Process_Data
            'call_type': 'DIRECT',
            'count': 1
        },
        {
            'from_id': id_gen.get_function_id(0x1000),  # main
            'to_id': id_gen.get_function_id(0x1400),    # Validate_Input
            'call_type': 'DIRECT',
            'count': 2
        },
        {
            'from_id': id_gen.get_function_id(0x1200),  # Process_Data
            'to_id': id_gen.get_function_id(0x1600),    # printf
            'call_type': 'DIRECT',
            'count': 3
        },
        {
            'from_id': id_gen.get_function_id(0x1200),  # Process_Data
            'to_id': id_gen.get_function_id(0x1800),    # malloc
            'call_type': 'DIRECT',
            'count': 1
        },
    ]
    
    # REFERENCES边
    references_edges = [
        {
            'from_id': id_gen.get_function_id(0x1200),  # Process_Data
            'to_id': id_gen.get_string_id('Processing packet...')
        },
        {
            'from_id': id_gen.get_function_id(0x1400),  # Validate_Input
            'to_id': id_gen.get_string_id('Invalid input detected')
        },
    ]
    
    # WRITES边（核心）
    writes_edges = [
        {
            'from_id': id_gen.get_function_id(0x1000),  # main
            'to_id': id_gen.get_struct_slot_id('SessionEntry', 8),  # status
            'op_type': 'ASSIGN',
            'const_val': '0x1',
            'loc': 0x1050
        },
        {
            'from_id': id_gen.get_function_id(0x1200),  # Process_Data
            'to_id': id_gen.get_struct_slot_id('SessionEntry', 12),  # flags
            'op_type': 'OR',
            'const_val': '0x80',
            'loc': 0x1250
        },
        {
            'from_id': id_gen.get_function_id(0x1200),  # Process_Data
            'to_id': id_gen.get_global_slot_id(0x5010),  # g_session_count
            'op_type': 'ADD',
            'const_val': '1',
            'loc': 0x1280
        },
    ]
    
    # READS边（核心）
    reads_edges = [
        {
            'from_id': id_gen.get_function_id(0x1000),  # main
            'to_id': id_gen.get_struct_slot_id('SessionEntry', 8),  # status
            'condition': True,
            'op_type': 'CMP',
            'const_val': '0x3'
        },
        {
            'from_id': id_gen.get_function_id(0x1200),  # Process_Data
            'to_id': id_gen.get_struct_slot_id('PacketHeader', 0),  # magic
            'condition': True,
            'op_type': 'CMP',
            'const_val': '0xDEADBEEF'
        },
        {
            'from_id': id_gen.get_function_id(0x1200),  # Process_Data
            'to_id': id_gen.get_global_slot_id(0x5000),  # g_config
            'condition': False,
            'op_type': 'MOV',
            'const_val': ''
        },
    ]
    
    # LINKS_TO边（动态链接）
    links_to_edges = []  # 简化版，暂不添加

    # EMBEDS边（结构体根到成员）
    embeds_edges = []
    
    return {
        'binaries': binaries,
        'functions': functions,
        'dataslots': dataslots,
        'strings': strings,
        'contains_edges': contains_edges,
        'embeds_edges': embeds_edges,
        'calls_edges': calls_edges,
        'links_to_edges': links_to_edges,
        'references_edges': references_edges,
        'writes_edges': writes_edges,
        'reads_edges': reads_edges,
        'binary_hash': binary_hash
    }


def test_csv_exporter():
    """测试CSV导出器"""
    
    print("=" * 70)
    print("CSV Exporter Test Script")
    print("=" * 70)
    print()
    
    # 创建测试数据
    print("[*] Creating test data...")
    test_data = create_test_data()
    print(f"    ✓ Binary nodes: {len(test_data['binaries'])}")
    print(f"    ✓ Function nodes: {len(test_data['functions'])}")
    print(f"    ✓ DataSlot nodes: {len(test_data['dataslots'])}")
    print(f"    ✓ String nodes: {len(test_data['strings'])}")
    print(f"    ✓ Total edges: {sum([len(test_data[k]) for k in test_data if k.endswith('_edges')])}")
    print()
    
    # 初始化导出器
    output_dir = os.path.join(os.path.dirname(__file__), 'test_output')
    print(f"[*] Initializing exporter...")
    print(f"    Output directory: {output_dir}")
    
    exporter = CSVExporter(
        output_dir=output_dir,
        binary_hash=test_data['binary_hash']
    )
    print()
    
    # 执行导出
    print("[*] Starting export...")
    result = exporter.export_all(
        binaries=test_data['binaries'],
        functions=test_data['functions'],
        dataslots=test_data['dataslots'],
        strings=test_data['strings'],
        contains_edges=test_data['contains_edges'],
        embeds_edges=test_data['embeds_edges'],
        calls_edges=test_data['calls_edges'],
        links_to_edges=test_data['links_to_edges'],
        references_edges=test_data['references_edges'],
        writes_edges=test_data['writes_edges'],
        reads_edges=test_data['reads_edges'],
        validate=True
    )
    
    # 显示结果
    print("=" * 70)
    print("Test Results")
    print("=" * 70)
    print()
    
    print("✅ Export completed successfully!")
    print()
    
    print("Generated files:")
    print("  Nodes:")
    for node_type, filepath in result['node_files'].items():
        print(f"    - {os.path.basename(filepath)}")
    print()
    
    print("  Edges:")
    for edge_type, filepath in result['edge_files'].items():
        print(f"    - {os.path.basename(filepath)}")
    print()
    
    print("  Import Scripts:")
    for script_type, filepath in result['import_scripts'].items():
        print(f"    - {os.path.basename(filepath)}")
    print()
    
    print("Statistics:")
    print(f"  Total nodes: {sum(result['stats']['nodes'].values())}")
    print(f"  Total edges: {sum(result['stats']['edges'].values())}")
    print()
    
    if result['stats']['errors']:
        print(f"⚠️  Found {len(result['stats']['errors'])} validation errors!")
        print("   Check export_stats.txt for details.")
    else:
        print("✅ Data validation passed!")
    print()
    
    print("=" * 70)
    print("Next Steps:")
    print("=" * 70)
    print()
    print("1. Review the generated CSV files in:")
    print(f"   {output_dir}")
    print()
    print("2. Check the statistics report:")
    print(f"   {os.path.basename(result['stats_report'])}")
    print()
    print("3. To import into Neo4j:")
    print("   - Edit import_to_neo4j.sh (Linux/Mac) or import_to_neo4j.bat (Windows)")
    print("   - Set NEO4J_HOME to your Neo4j installation path")
    print("   - Stop Neo4j service")
    print("   - Run the import script")
    print("   - Start Neo4j service")
    print("   - Execute create_indexes.cypher in Neo4j Browser")
    print()
    
    return result


if __name__ == '__main__':
    try:
        result = test_csv_exporter()
        print("✅ Test completed successfully!")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
