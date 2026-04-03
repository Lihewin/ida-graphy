"""
示例：使用core模块创建完整的图数据结构

这个示例展示了如何使用NodeIDGenerator和数据模型类创建一个完整的图数据结构。
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import (
    NodeIDGenerator,
    BinaryNode,
    FunctionNode,
    DataSlotNode,
    StringNode,
    ContainsEdge,
    CallsEdge,
    WritesEdge,
    ReadsEdge,
    ReferencesEdge
)


def create_example_graph():
    """创建一个示例图结构"""
    
    print("=== IDA-Graphy Core Module Example ===\n")
    
    # 1. 创建ID生成器（模拟app.exe）
    print("1. 初始化ID生成器...")
    gen = NodeIDGenerator(binary_hash="a" * 64)
    print(f"   Binary Hash: {gen.get_binary_id()[:16]}...\n")
    
    # 2. 创建Binary节点
    print("2. 创建Binary节点...")
    binary = BinaryNode(
        hash=gen.get_binary_id(),
        name="app.exe",
        orig_name="app.exe",
        base_addr=0x140000000,
        arch="x86_64",
        compile_ts=1234567890
    )
    print(f"   Name: {binary.name}")
    print(f"   Arch: {binary.arch}")
    print(f"   Base: 0x{binary.base_addr:X}\n")
    
    # 3. 创建Function节点
    print("3. 创建Function节点...")
    func_main = FunctionNode(
        uid=gen.get_function_id(0x1000),
        rva=0x1000,
        name="main",
        binary_id=binary.hash,
        size=256,
        func_type='NORMAL',
        signature='int main(int argc, char** argv)',
        complexity=5
    )
    print(f"   Name: {func_main.name}")
    print(f"   RVA: 0x{func_main.rva:X}")
    print(f"   Type: {func_main.func_type}")
    print(f"   ID: {func_main.uid[:16]}...\n")
    
    func_process = FunctionNode(
        uid=gen.get_function_id(0x2000),
        rva=0x2000,
        name="process_data",
        binary_id=binary.hash,
        size=128,
        func_type='NORMAL'
    )
    print(f"   Name: {func_process.name}")
    print(f"   RVA: 0x{func_process.rva:X}\n")
    
    # 4. 创建DataSlot节点（展示跨二进制一致性）
    print("4. 创建DataSlot节点（结构体成员）...")
    config_flags = DataSlotNode(
        uid=gen.get_struct_slot_id("Config", 0),
        base_type="Config",
        base_type_orig="Config",
        offset=0,
        size=4,
        name="flags",
        orig_name="flags",
        is_global=False
    )
    print(f"   Type: {config_flags.base_type}")
    print(f"   Name: {config_flags.name}")
    print(f"   ID: {config_flags.uid[:16]}...")
    
    # 演示跨二进制一致性
    print("\n   验证跨二进制一致性:")
    gen2 = NodeIDGenerator(binary_hash="b" * 64)
    config_flags_2 = gen2.get_struct_slot_id("Config", 0)
    print(f"   另一个二进制的同一结构体成员ID: {config_flags_2[:16]}...")
    print(f"   ID相同: {config_flags.uid == config_flags_2}\n")
    
    # 5. 创建String节点
    print("5. 创建String节点...")
    error_msg = StringNode(
        hash=gen.get_string_id("Error: Invalid parameter"),
        content="Error: Invalid parameter",
        encoding="ASCII"
    )
    print(f"   Content: {error_msg.content}")
    print(f"   ID: {error_msg.hash[:16]}...\n")
    
    # 6. 创建CONTAINS边
    print("6. 创建CONTAINS边...")
    contains_main = ContainsEdge(
        from_id=binary.hash,
        to_id=func_main.uid
    )
    print(f"   Binary -> Function (main)")
    
    contains_string = ContainsEdge(
        from_id=binary.hash,
        to_id=error_msg.hash
    )
    print(f"   Binary -> String\n")
    
    # 7. 创建CALLS边
    print("7. 创建CALLS边...")
    calls = CallsEdge(
        from_id=func_main.uid,
        to_id=func_process.uid,
        call_type='DIRECT',
        count=3
    )
    print(f"   main -> process_data")
    print(f"   Type: {calls.call_type}")
    print(f"   Count: {calls.count}\n")
    
    # 8. 创建WRITES边（核心业务流）
    print("8. 创建WRITES边...")
    writes = WritesEdge(
        from_id=func_main.uid,
        to_id=config_flags.uid,
        op_type='OR',
        const_val='0x80',
        loc=0x1010
    )
    print(f"   Function: {func_main.name}")
    print(f"   -> DataSlot: {config_flags.name}")
    print(f"   Operation: {writes.op_type}")
    print(f"   Value: {writes.const_val}")
    print(f"   Location: 0x{writes.loc:X}\n")
    
    # 9. 创建READS边（核心业务流）
    print("9. 创建READS边...")
    reads = ReadsEdge(
        from_id=func_process.uid,
        to_id=config_flags.uid,
        condition=True,  # 在条件语句中读取
        op_type='CMP',
        const_val='0x80'
    )
    print(f"   Function: {func_process.name}")
    print(f"   -> DataSlot: {config_flags.name}")
    print(f"   In Condition: {reads.condition}")
    print(f"   Operation: {reads.op_type}")
    print(f"   Compare Value: {reads.const_val}\n")
    
    # 10. 创建REFERENCES边
    print("10. 创建REFERENCES边...")
    references = ReferencesEdge(
        from_id=func_main.uid,
        to_id=error_msg.hash
    )
    print(f"   Function: {func_main.name}")
    print(f"   -> String: \"{error_msg.content}\"\n")
    
    # 11. 导出为字典格式（用于CSV）
    print("11. 转换为CSV格式...")
    print("\n   Binary节点:")
    print(f"   {binary.to_dict()}")
    
    print("\n   Function节点:")
    print(f"   {func_main.to_dict()}")
    
    print("\n   WRITES边:")
    print(f"   {writes.to_dict()}")
    
    print("\n   READS边:")
    print(f"   {reads.to_dict()}")
    
    # 12. 统计
    print("\n=== 图数据统计 ===")
    print(f"节点总数: 5")
    print(f"  - Binary: 1")
    print(f"  - Function: 2")
    print(f"  - DataSlot: 1")
    print(f"  - String: 1")
    print(f"\n边总数: 6")
    print(f"  - CONTAINS: 2")
    print(f"  - CALLS: 1")
    print(f"  - WRITES: 1")
    print(f"  - READS: 1")
    print(f"  - REFERENCES: 1")
    
    print("\n✅ 示例完成！所有核心功能正常工作。")


if __name__ == "__main__":
    create_example_graph()
