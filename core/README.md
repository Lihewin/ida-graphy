# Graph Extractor - 核心功能说明

## 概述

`core/graph_extractor.py` 是 ida-graphy 的核心图数据提取器，负责从 IDA 数据库中提取符合 Neo4j 模型的节点和边。

## 已实现功能

### ✅ 节点提取

1. **Binary 节点** (`extract_binary_node`)
   - 提取二进制文件的基本信息
   - 使用 `ida_nalt` 获取文件元数据
   - 属性：hash, name, base_addr, arch, compile_ts

2. **Function 节点** (`extract_function_nodes`)
   - 遍历所有函数（使用 `idautils.Functions()`）
   - 自动分类函数类型：NORMAL/IMPORT/EXPORT/THUNK
   - 提取函数签名、大小、复杂度
   - 识别库函数（is_lib标记）
   - 属性：uid, rva, name, size, is_lib, func_type, signature, complexity, binary_id

3. **String 节点** (`extract_string_nodes`)
   - 使用 `idautils.Strings()` 提取所有字符串
   - 自动去重和清洗
   - 识别编码类型（ASCII/UTF-16）
   - 属性：hash, content, encoding

### ✅ 边提取

1. **CONTAINS 边** (`extract_contains_edges`)
   - Binary 与其包含的节点的归属关系
   - Binary -> Function
   - Binary -> String
   - Binary -> DataSlot (全局变量)

2. **CALLS 边** (`extract_call_edges`)
   - 函数调用关系
   - 使用 `idautils.XrefsFrom` 分析调用指令
   - 统计调用次数
   - 检测调用类型：DIRECT/INDIRECT/TAIL
   - 属性：from_id, to_id, call_type, count

3. **REFERENCES 边** (`extract_reference_edges`)
   - 函数引用字符串的关系
   - Function -> String
   - 属性：from_id, to_id

### ⏳ 待实现功能（需要数据流分析模块）

1. **DataSlot 节点** (`extract_dataslot_nodes`)
   - 需要使用 Hex-Rays ctree visitor
   - 识别结构体成员
   - 识别全局变量
   - 扁平化嵌套结构体

2. **WRITES 边** (`extract_dataflow_edges`)
   - 需要 ctree 分析
   - 识别赋值操作（ASSIGN/OR/AND/ADD）
   - 提取写入的常量值
   - 记录操作位置

3. **READS 边** (`extract_dataflow_edges`)
   - 需要 ctree 分析
   - 识别读取操作
   - 判断是否在条件语句中（关键特性）
   - 提取比较常量值

## 核心设计特点

### 1. 函数类型分类逻辑

基于改造.md中的分类算法：

```python
def classify_function(func_ea):
    # 1. 检查是否在导出表
    if is_in_export_table(func_ea):
        return "EXPORT"
    
    # 2. 检查是否为 Thunk 类型
    flags = ida_funcs.get_func(func_ea).flags
    if flags & ida_funcs.FUNC_THUNK:
        # 判断是否跳转到导入表
        if is_in_idata(...) or "__imp_" in func_name:
            return "IMPORT"
        return "THUNK"
    
    # 3. 普通业务函数
    return "NORMAL"
```

### 2. ID 生成规则

使用 `NodeIDGenerator` 确保跨二进制的一致性：

- **Binary**: `SHA256(文件内容)`
- **Function**: `MD5(BinaryHash + "_" + RVA)`
- **DataSlot (结构体)**: `MD5(StructName + "_" + Offset)` ✨ 跨二进制共享
- **DataSlot (全局)**: `MD5(BinaryHash + "_GLOBAL_" + RVA)`
- **String**: `MD5(Content)`

### 3. 性能优化

- 使用 `tqdm` 显示进度条
- 缓存函数 ID 和字符串 ID
- 批量处理调用关系统计
- 异常处理确保部分失败不影响整体

### 4. 日志记录

使用 Python `logging` 模块：
- INFO: 正常流程信息
- WARNING: 非致命错误（如单个函数分析失败）
- ERROR: 严重错误

## 使用方法

### 方法1：在 IDA 中运行（推荐）

```python
# 在 IDA 中：Alt+F7 运行脚本
import sys
sys.path.append('/path/to/ida-graphy')

from core.graph_extractor import GraphExtractor
import ida_nalt

# 获取当前二进制
binary_path = ida_nalt.get_input_file_path()
with open(binary_path, 'rb') as f:
    binary_content = f.read()

# 创建提取器
extractor = GraphExtractor(binary_content, binary_path)

# 执行提取
graph_data = extractor.extract_all()

# 访问结果
print(f"Functions: {len(graph_data.functions)}")
print(f"Calls: {len(graph_data.calls)}")
```

### 方法2：使用 idalib（批处理）

```python
# standalone.py
import idapro as idalib
import ida_auto
from core.graph_extractor import GraphExtractor

# 打开数据库
idalib.open_database('target.exe', True)
ida_auto.auto_wait()

# 提取图数据
with open('target.exe', 'rb') as f:
    binary_content = f.read()

extractor = GraphExtractor(binary_content, 'target.exe')
graph_data = extractor.extract_all()

# 导出到CSV/JSON等
# ...

idalib.close_database()
```

## 依赖关系

```
graph_extractor.py
    ├── node_id_generator.py  # ID生成算法
    ├── models.py             # 数据模型定义
    └── IDA SDK:
        ├── ida_funcs         # 函数分析
        ├── ida_nalt          # 文件信息
        ├── idautils          # 遍历工具
        ├── ida_xref          # 交叉引用
        └── idc               # 基础API
```

## 输出数据结构

```python
GraphData
├── binaries: List[BinaryNode]
├── functions: List[FunctionNode]
├── dataslots: List[DataSlotNode]  # 暂为空
├── strings: List[StringNode]
├── contains: List[ContainsEdge]
├── calls: List[CallsEdge]
├── links_to: List[LinksToEdge]    # 待实现（多组件分析）
├── references: List[ReferencesEdge]
├── writes: List[WritesEdge]       # 暂为空（需数据流分析）
└── reads: List[ReadsEdge]         # 暂为空（需数据流分析）
```

## 后续扩展

### 阶段2：数据流分析（需要 Hex-Rays）

创建 `analyzers/dataflow_analyzer.py`：

```python
class DataFlowAnalyzer:
    """使用 Hex-Rays ctree visitor 分析数据流"""
    
    def analyze_function(self, func_ea):
        # 反编译函数
        cfunc = ida_hexrays.decompile(func_ea)
        
        # 运行 visitor
        visitor = DataFlowVisitor()
        visitor.apply_to(cfunc.body, None)
        
        # 返回 WRITES/READS 边
        return visitor.writes, visitor.reads
```

集成到 `GraphExtractor.extract_dataflow_edges()` 中。

### 阶段3：CSV/Neo4j 导出

创建 `exporters/csv_exporter.py`：

```python
class CSVExporter:
    def export_all(self, graph_data, output_dir):
        # 导出节点CSV
        self._export_binary_nodes(graph_data.binaries)
        self._export_function_nodes(graph_data.functions)
        # ...
        
        # 导出边CSV
        self._export_calls_edges(graph_data.calls)
        # ...
        
        # 生成Neo4j导入脚本
        self._generate_import_script()
```

## 测试建议

1. **简单EXE测试**：先用小型可执行文件测试基本功能
2. **DLL测试**：测试导入/导出函数识别
3. **大型二进制**：测试性能和异常处理

## 已知限制

1. **不支持混淆代码**：严重混淆可能导致函数识别失败
2. **无数据流分析**：WRITES/READS边需要 Hex-Rays（下一阶段）
3. **不支持跨组件链接**：LINKS_TO边需要多文件分析（阶段4）

## 贡献者

- 基于改造.md和改造计划.md的设计规范
- 使用 IDA SDK 9.0+ API
- 遵循 Neo4j 图数据模型

---

**状态**: ✅ 基础框架完成 | ⏳ 数据流分析待实现 | ⏳ CSV导出待实现
