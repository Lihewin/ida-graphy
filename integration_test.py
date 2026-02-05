"""
IDA-Graphy 集成测试脚本
测试核心模块功能（不依赖IDA）
"""

import os
import sys
import hashlib
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_module_imports():
    """测试所有模块是否可以正常导入"""
    print("\n" + "="*70)
    print("测试1: 模块导入")
    print("="*70)
    
    try:
        from core.mapping.id_generator import NodeIDGenerator
        print("✅ core.mapping.id_generator 导入成功")
        
        from core.models import (
            BinaryNode, FunctionNode, DataSlotNode, StringNode,
            ContainsEdge, CallsEdge, WritesEdge, ReadsEdge
        )
        print("✅ core.models 导入成功")
        
        from core.extraction.engine import ExtractionEngine
        print("✅ core.extraction.engine 导入成功")

        from core.mapping.graph_mapper import GraphMapper
        print("✅ core.mapping.graph_mapper 导入成功")
        
        return True
    except Exception as e:
        print(f"❌ 导入失败: {e}")
        return False

def test_id_generation():
    """测试ID生成功能"""
    print("\n" + "="*70)
    print("测试2: ID生成功能")
    print("="*70)
    
    from core.mapping.id_generator import NodeIDGenerator
    
    # 测试Binary ID
    test_content = b"test binary content"
    id_gen = NodeIDGenerator(binary_content=test_content)
    
    binary_id = id_gen.get_binary_id()
    print(f"Binary ID: {binary_id[:16]}...")
    
    # 测试Function ID
    func_id = id_gen.get_function_id(0x401000)
    print(f"Function ID (RVA=0x401000): {func_id[:16]}...")
    
    # 测试DataSlot ID（结构体）
    struct_id = id_gen.get_struct_slot_id("SessionEntry", 8)
    print(f"Struct Slot ID (SessionEntry, offset=8): {struct_id[:16]}...")
    
    # 测试跨二进制一致性
    id_gen2 = NodeIDGenerator(binary_content=b"different binary")
    struct_id2 = id_gen2.get_struct_slot_id("SessionEntry", 8)
    
    if struct_id == struct_id2:
        print("✅ 跨二进制一致性验证通过（结构体DataSlot ID相同）")
    else:
        print("❌ 跨二进制一致性验证失败")
        return False
    
    # 测试全局变量ID
    global_id = id_gen.get_global_slot_id(0x403000)
    print(f"Global Slot ID (RVA=0x403000): {global_id[:16]}...")
    
    # 测试String ID
    string_id = id_gen.get_string_id("Hello World")
    print(f"String ID: {string_id[:16]}...")
    
    return True

def test_data_models():
    """测试数据模型"""
    print("\n" + "="*70)
    print("测试3: 数据模型")
    print("="*70)
    
    from core.models import (
        BinaryNode, FunctionNode, DataSlotNode, StringNode,
        WritesEdge, ReadsEdge
    )
    
    # 创建测试节点
    binary = BinaryNode(
        hash="abc123",
        name="test.exe",
        orig_name="test.exe",
        base_addr=0x400000,
        arch="x86_64",
        compile_ts=0
    )
    print(f"✅ BinaryNode 创建成功: {binary.name}")
    
    func = FunctionNode(
        uid="func_001",
        rva=0x1000,
        name="main",
        orig_name="main",
        size=256,
        is_lib=False,
        func_type="NORMAL",
        signature="int main(void)",
        complexity=5,
        binary_id="abc123"
    )
    print(f"✅ FunctionNode 创建成功: {func.name}")
    
    slot = DataSlotNode(
        uid="slot_001",
        base_type="SessionEntry",
        base_type_orig="SessionEntry",
        offset=8,
        size=4,
        name="status",
        orig_name="status",
        is_global=False
    )
    print(f"✅ DataSlotNode 创建成功: {slot.name}")
    
    # 创建测试边
    write_edge = WritesEdge(
        from_id="func_001",
        to_id="slot_001",
        op_type="ASSIGN",
        const_val="0x1",
        loc=0x1050
    )
    print(f"✅ WritesEdge 创建成功: {write_edge.op_type}")
    
    read_edge = ReadsEdge(
        from_id="func_001",
        to_id="slot_001",
        condition=True,
        op_type="CMP",
        const_val="0x3",
        loc=0x1054
    )
    print(f"✅ ReadsEdge 创建成功: condition={read_edge.condition}")
    
    return True

def test_pe_file_analysis():
    """测试PE文件哈希计算"""
    print("\n" + "="*70)
    print("测试4: PE文件哈希计算")
    print("="*70)
    
    test_binaries_dir = project_root / "test_binaries"
    
    if not test_binaries_dir.exists():
        print("⚠️  test_binaries 目录不存在，跳过此测试")
        return True
    
    from core.mapping.id_generator import NodeIDGenerator
    
    for pe_file in test_binaries_dir.glob("*.exe"):
        try:
            with open(pe_file, 'rb') as f:
                content = f.read()
            
            id_gen = NodeIDGenerator(binary_content=content)
            binary_id = id_gen.get_binary_id()
            
            print(f"✅ {pe_file.name:15} -> {binary_id[:32]}...")
            
        except Exception as e:
            print(f"❌ {pe_file.name} 处理失败: {e}")
            return False
    
    return True

def test_project_structure():
    """验证项目结构完整性"""
    print("\n" + "="*70)
    print("测试5: 项目结构验证")
    print("="*70)
    
    required_files = [
        "core/__init__.py",
        "core/mapping/id_generator.py",
        "core/mapping/struct_normalizer.py",
        "core/mapping/graph_mapper.py",
        "core/extraction/raw_data.py",
        "core/extraction/engine.py",
        "core/project/metadata.py",
        "core/project/manager.py",
        "core/project/file_tracker.py",
        "core/models.py",
        "analyzers/__init__.py",
        "analyzers/dataflow_analyzer.py",
        "exporters/__init__.py",
        "ida_graphy.py",
        "config.yaml",
        "requirements.txt",
        "pyproject.toml",
    ]
    
    missing = []
    for file_path in required_files:
        full_path = project_root / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} (缺失)")
            missing.append(file_path)
    
    if missing:
        print(f"\n⚠️  缺失 {len(missing)} 个文件")
        return False
    
    return True

def main():
    """运行所有测试"""
    print("\n" + "="*70)
    print("IDA-Graphy 集成测试套件")
    print("="*70)
    
    tests = [
        ("模块导入", test_module_imports),
        ("ID生成", test_id_generation),
        ("数据模型", test_data_models),
        ("PE文件分析", test_pe_file_analysis),
        ("项目结构", test_project_structure),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ 测试异常: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # 打印总结
    print("\n" + "="*70)
    print("测试总结")
    print("="*70)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:10} | {test_name}")
    
    print("="*70)
    print(f"总计: {passed}/{total} 测试通过")
    
    if passed == total:
        print("🎉 所有测试通过！")
        return 0
    else:
        print(f"⚠️  {total - passed} 个测试失败")
        return 1

if __name__ == "__main__":
    sys.exit(main())
