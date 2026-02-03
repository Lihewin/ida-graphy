# IDA-Graphy 模块化重构报告

> 生成日期: 2026-02-02  
> 版本: v2.0 重构计划

## 1. 重构概述

### 1.1 目标

将现有 IDA-Graphy 代码库重构为四个清晰分离的模块：

1. **ProjectManager (项目管理器)** - 工作目录、配置和数据库连接
2. **ExtractionEngine (IDALib 提取引擎)** - 从 idalib 提取原始数据
3. **GraphMapper (图映射器)** - 原始数据转换为图模型
4. **ExportManager (导出管理器)** - Neo4j/CSV/文件导出

### 1.2 核心设计决策

| 决策项 | 选择 | 理由 |
|--------|------|------|
| 数据流分离 | **严格分离** | 提取引擎返回原始 DTO，映射器负责所有 ID 生成 |
| 文件导出时机 | **sync 时自动导出** | 每次项目同步自动生成伪C、结构体、表文件 |
| 数据库隔离 | **保持独立数据库** | 每个项目维护 `idg-project-{name}` |
| DataFlow 集成 | **集成到提取引擎** | Hex-Rays 可用时自动启用 ctree 分析 |

---

## 2. 新架构

### 2.1 模块架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        ida_graphy.py (CLI)                       │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│               1. ProjectManager (项目管理器)                      │
│   core/project/                                                  │
│   - 工作目录/项目生命周期管理                                      │
│   - Neo4j 数据库连接协调                                          │
│   - files_manifest.json 维护                                     │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│            2. ExtractionEngine (IDALib 提取引擎)                  │
│   core/extraction/                                               │
│   - 从 idalib 提取原始数据 (RawBinaryData DTO)                    │
│   - DataFlow 分析集成 (Hex-Rays 可用时自动启用)                    │
│   - 返回原始 DTO 而非图模型                                        │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│               3. GraphMapper (图映射器)                           │
│   core/mapping/                                                  │
│   - 原始数据 → 图模型 (节点/边)                                    │
│   - ID 生成 (NodeIDGenerator)                                    │
│   - 结构体规范化 (StructNameNormalizer)                           │
│   - 跨二进制符号解析 (SymbolResolver)                              │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│              4. ExportManager (导出管理器)                        │
│   exporters/                                                     │
│   - Neo4j 数据库导出                                              │
│   - CSV 兼容导出                                                  │
│   - 文件导出 (伪C、结构体、导入导出表、字符串表)                     │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 模块职责边界

| 模块 | 输入 | 输出 | 职责 |
|------|------|------|------|
| **ProjectManager** | CLI 命令 | 协调其他模块 | 项目 CRUD、文件变更追踪、sync 流程编排 |
| **ExtractionEngine** | 二进制文件路径 | `RawBinaryData` DTO | IDA API 调用、原始数据收集、DataFlow 分析 |
| **GraphMapper** | `RawBinaryData` | `GraphData` | ID 生成、模型构建、结构体规范化 |
| **ExportManager** | `GraphData` | Neo4j/CSV/文件 | 数据持久化、文件生成 |

### 2.3 数据流

```
Binary File
    │
    ▼
┌───────────────────┐
│ ExtractionEngine  │ ──► RawBinaryData (DTO)
└───────────────────┘          │
                               ▼
                    ┌───────────────────┐
                    │   GraphMapper     │ ──► GraphData (节点/边模型)
                    └───────────────────┘          │
                                                   ▼
                                        ┌───────────────────┐
                                        │  ExportManager    │
                                        └───────────────────┘
                                                   │
                              ┌────────────────────┼────────────────────┐
                              ▼                    ▼                    ▼
                           Neo4j                 CSV                 文件
                        (图数据库)           (兼容导出)         (伪C/结构体/表)
```

---

## 3. 目录结构

### 3.1 新目录布局

```
ida-graphy/
├── ida_graphy.py               # CLI 入口
├── config.yaml                 # 全局配置
├── core/
│   ├── __init__.py
│   ├── models.py               # 图模型定义 (节点/边)
│   ├── project/                # 项目管理模块
│   │   ├── __init__.py
│   │   ├── manager.py          # ProjectManager 主类
│   │   ├── metadata.py         # ProjectMetadata, BinaryFile
│   │   └── file_tracker.py     # 文件变更追踪
│   ├── extraction/             # 提取引擎模块
│   │   ├── __init__.py
│   │   ├── engine.py           # ExtractionEngine 主入口
│   │   ├── raw_data.py         # RawBinaryData 等 DTO 定义
│   │   ├── ida_adapter.py      # idalib API 封装
│   │   └── dataflow.py         # DataFlow 分析
│   └── mapping/                # 图映射器模块
│       ├── __init__.py
│       ├── graph_mapper.py     # GraphMapper 主类
│       ├── id_generator.py     # NodeIDGenerator
│       ├── struct_normalizer.py # 结构体名称规范化
│       └── symbol_resolver.py  # 跨二进制符号解析
├── exporters/
│   ├── __init__.py
│   ├── export_manager.py       # ExportManager 统一接口
│   ├── neo4j_exporter.py       # Neo4j 导出
│   ├── csv_exporter.py         # CSV 导出
│   └── file_exporter.py        # 文件导出 (伪C/结构体/表)
├── database/
│   ├── __init__.py
│   └── neo4j_manager.py        # Neo4j 连接管理
├── tests/
│   ├── test_raw_data.py        # DTO 测试
│   ├── test_graph_mapper.py    # 映射器测试
│   └── ...
└── projects/                   # 项目数据目录
```

### 3.2 文件迁移计划

| 源文件 | 目标位置 | 操作 |
|--------|----------|------|
| `core/project_manager.py` | `core/project/manager.py` | 拆分 + 简化 |
| `core/models.py` (ProjectMetadata, BinaryFile) | `core/project/metadata.py` | 拆分 |
| `core/models.py` (节点/边) | `core/models.py` | 保留 |
| `core/graph_extractor.py` | `core/extraction/engine.py` | 重构 |
| `analyzers/dataflow_analyzer.py` | `core/extraction/dataflow.py` | 迁移 |
| `core/node_id_generator.py` | `core/mapping/id_generator.py` | 迁移 |
| `core/struct_normalizer.py` | `core/mapping/struct_normalizer.py` | 迁移 |
| `core/symbol_resolver.py` | `core/mapping/symbol_resolver.py` | 迁移 |
| `exporters/project_exporter.py` | `exporters/neo4j_exporter.py` | 拆分 |
| `core/file_watcher.py` | `core/project/file_tracker.py` | 重构 |

---

## 4. 原始数据 DTO 定义

### 4.1 DTO 概览

位于 `core/extraction/raw_data.py`，**只包含地址和原始名称，不包含计算后的 ID**：

```python
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class RawBinaryInfo:
    """二进制元信息"""
    name: str
    base_addr: int
    arch: str
    compile_ts: int = 0

@dataclass
class RawFunction:
    """函数原始数据"""
    ea: int                     # 有效地址 (VA)
    name: str
    size: int
    flags: int                  # IDA 函数标志
    signature: str = ""
    is_thunk: bool = False
    is_export: bool = False

@dataclass
class RawString:
    """字符串原始数据"""
    ea: int
    content: str
    encoding: str = "ASCII"

@dataclass
class RawGlobal:
    """全局变量原始数据"""
    ea: int
    name: str
    size: int

@dataclass
class RawStructMember:
    """结构体成员"""
    struct_name: str            # 原始结构体名（未规范化）
    offset: int
    name: str
    size: int

@dataclass
class RawCall:
    """调用关系"""
    caller_ea: int
    callee_ea: int
    call_addr: int              # 调用指令地址
    call_type: str = "DIRECT"   # DIRECT/INDIRECT/TAIL

@dataclass
class RawStringRef:
    """字符串引用"""
    func_ea: int
    string_ea: int

@dataclass  
class RawDataAccess:
    """数据访问（READS/WRITES）"""
    func_ea: int
    target_ea: int              # 全局变量地址或结构体成员标识
    is_write: bool
    op_type: str                # ASSIGN/OR/AND/ADD/CMP/TEST/MOV
    const_val: Optional[str] = None
    is_condition: bool = False  # 是否在条件判断中
    loc: int = 0                # 指令 RVA

@dataclass
class RawBinaryData:
    """聚合容器"""
    binary_info: RawBinaryInfo = None
    functions: List[RawFunction] = field(default_factory=list)
    strings: List[RawString] = field(default_factory=list)
    globals: List[RawGlobal] = field(default_factory=list)
    struct_members: List[RawStructMember] = field(default_factory=list)
    calls: List[RawCall] = field(default_factory=list)
    string_refs: List[RawStringRef] = field(default_factory=list)
    data_accesses: List[RawDataAccess] = field(default_factory=list)
```

### 4.2 关键设计点

1. **无 ID 字段** - DTO 只包含原始地址 (`ea`)，ID 由 GraphMapper 计算
2. **原始名称** - `struct_name` 未规范化，由映射器处理
3. **扁平化** - 每个 DTO 是独立数据单元，便于序列化和测试

---

## 5. 核心模块接口

### 5.1 ExtractionEngine

```python
# core/extraction/engine.py

class ExtractionEngine:
    """IDALib 数据提取引擎"""
    
    def __init__(self, binary_path: str, enable_dataflow: bool = True):
        """
        初始化提取引擎
        
        Args:
            binary_path: 二进制文件路径
            enable_dataflow: 是否启用 DataFlow 分析（需要 Hex-Rays）
        """
        pass
    
    def extract(self) -> RawBinaryData:
        """
        执行完整提取流程
        
        Returns:
            RawBinaryData 包含所有原始数据
        """
        pass
    
    def extract_binary_info(self) -> RawBinaryInfo:
        """提取二进制元信息"""
        pass
    
    def extract_functions(self) -> List[RawFunction]:
        """提取所有函数"""
        pass
    
    def extract_strings(self) -> List[RawString]:
        """提取所有字符串"""
        pass
    
    def extract_globals(self) -> List[RawGlobal]:
        """提取全局变量"""
        pass
    
    def extract_struct_members(self) -> List[RawStructMember]:
        """提取结构体成员"""
        pass
    
    def extract_calls(self) -> List[RawCall]:
        """提取调用关系"""
        pass
    
    def extract_dataflow(self) -> List[RawDataAccess]:
        """提取数据流（需要 Hex-Rays）"""
        pass
```

### 5.2 GraphMapper

```python
# core/mapping/graph_mapper.py

class GraphMapper:
    """图数据映射器"""
    
    def __init__(self, binary_content: bytes, struct_normalizer: StructNameNormalizer = None):
        """
        初始化映射器
        
        Args:
            binary_content: 二进制文件内容（用于计算 binary_hash）
            struct_normalizer: 结构体名称规范化器
        """
        self.id_gen = NodeIDGenerator(binary_content=binary_content)
        self.normalizer = struct_normalizer or StructNameNormalizer()
    
    def map(self, raw_data: RawBinaryData) -> GraphData:
        """
        将原始数据转换为图模型
        
        Args:
            raw_data: 提取引擎返回的原始数据
            
        Returns:
            GraphData 包含所有节点和边
        """
        pass
    
    def _map_binary(self, info: RawBinaryInfo) -> BinaryNode:
        """映射 Binary 节点"""
        pass
    
    def _map_function(self, func: RawFunction) -> FunctionNode:
        """映射 Function 节点（包含 func_type 分类）"""
        pass
    
    def _map_string(self, string: RawString) -> StringNode:
        """映射 String 节点"""
        pass
    
    def _map_dataslot(self, global_var: RawGlobal) -> DataSlotNode:
        """映射全局变量 DataSlot"""
        pass
    
    def _map_struct_member(self, member: RawStructMember) -> DataSlotNode:
        """映射结构体成员 DataSlot（应用规范化）"""
        pass
    
    def _map_call_edge(self, call: RawCall, func_map: Dict[int, str]) -> CallsEdge:
        """映射 CALLS 边"""
        pass
```

### 5.3 ExportManager

```python
# exporters/export_manager.py

class ExportManager:
    """统一导出管理器"""
    
    def __init__(self, config: Dict, project_metadata: ProjectMetadata):
        """
        初始化导出管理器
        
        Args:
            config: 全局配置
            project_metadata: 项目元数据
        """
        pass
    
    def export_all(self, graph_data: GraphData, binary_path: str):
        """
        sync 时自动调用：导出到 Neo4j + 生成文件
        
        Args:
            graph_data: 图数据
            binary_path: 二进制文件路径（用于文件导出）
        """
        self.export_to_neo4j(graph_data)
        self.export_files(binary_path)
    
    def export_to_neo4j(self, graph_data: GraphData) -> Dict[str, int]:
        """导出到 Neo4j 数据库"""
        pass
    
    def export_to_csv(self, graph_data: GraphData) -> Dict[str, str]:
        """导出为 CSV 文件"""
        pass
    
    def export_files(self, binary_path: str):
        """
        导出文件（伪C、结构体、导入导出表、字符串表）
        
        需要在 IDA 环境中运行
        """
        pass
```

### 5.4 ProjectManager.sync()

```python
# core/project/manager.py

class ProjectManager:
    def sync(self, project_name: str, force: bool = False) -> Dict[str, any]:
        """
        同步项目：提取 → 映射 → 导出
        
        Args:
            project_name: 项目名称
            force: 强制重新分析所有文件
            
        Returns:
            同步统计信息
        """
        project = self.get_project(project_name)
        changed_files = self._get_changed_files(project) if not force else project.binaries
        
        stats = {'processed': 0, 'errors': []}
        
        for binary in changed_files:
            try:
                # 读取二进制内容
                with open(binary.path, 'rb') as f:
                    binary_content = f.read()
                
                # 1. 提取
                engine = ExtractionEngine(binary.path)
                raw_data = engine.extract()
                
                # 2. 映射
                mapper = GraphMapper(binary_content)
                graph_data = mapper.map(raw_data)
                
                # 3. 导出
                exporter = ExportManager(self.config, project.metadata)
                exporter.export_all(graph_data, binary.path)
                
                # 4. 更新分析时间
                self.update_binary_analysis_time(project_name, binary.path)
                stats['processed'] += 1
                
            except Exception as e:
                stats['errors'].append({'file': binary.path, 'error': str(e)})
        
        return stats
```

---

## 6. 实施步骤

### Phase 1: 创建目录结构和 DTO

1. [ ] 创建 `core/project/` 目录
2. [ ] 创建 `core/extraction/` 目录
3. [ ] 创建 `core/mapping/` 目录
4. [ ] 实现 `core/extraction/raw_data.py` (DTO 定义)
5. [ ] 添加 `__init__.py` 文件

### Phase 2: 重构提取引擎

1. [ ] 从 `graph_extractor.py` 提取 IDA API 调用到 `extraction/engine.py`
2. [ ] 移除所有 `NodeIDGenerator` 和模型构建代码
3. [ ] 迁移 `dataflow_analyzer.py` 到 `extraction/dataflow.py`
4. [ ] 创建 `extraction/ida_adapter.py` 封装 IDA API

### Phase 3: 实现图映射器

1. [ ] 创建 `mapping/graph_mapper.py`
2. [ ] 迁移 `node_id_generator.py` 到 `mapping/id_generator.py`
3. [ ] 迁移 `struct_normalizer.py` 到 `mapping/struct_normalizer.py`
4. [ ] 迁移 `symbol_resolver.py` 到 `mapping/symbol_resolver.py`

### Phase 4: 重构导出管理器

1. [ ] 创建 `exporters/export_manager.py` 统一接口
2. [ ] 从 `project_exporter.py` 拆分 Neo4j 导出到 `neo4j_exporter.py`
3. [ ] 增强 `file_exporter.py` 添加导入导出表和字符串表导出

### Phase 5: 重构项目管理器

1. [ ] 拆分 `ProjectMetadata` 和 `BinaryFile` 到 `project/metadata.py`
2. [ ] 重构 `project_manager.py` 到 `project/manager.py`
3. [ ] 实现 `project/file_tracker.py`
4. [ ] 实现 `sync()` 方法集成完整流程

### Phase 6: 更新 CLI 和测试

1. [ ] 更新 `ida_graphy.py` 导入路径
2. [ ] 更新现有测试
3. [ ] 添加新模块测试
4. [ ] 集成测试

---

## 7. 验证清单

### 功能验证

- [ ] `project create/delete/list` 命令正常工作
- [ ] `project add/remove` 命令正常工作
- [ ] `project sync` 完成完整流程（提取→映射→导出）
- [ ] Neo4j 数据库正确创建和填充
- [ ] CSV 导出格式与旧版本兼容
- [ ] 文件导出（伪C、结构体、表）正常生成

### 数据一致性

- [ ] 节点 ID 生成与旧版本一致
- [ ] 结构体成员跨二进制共享 ID
- [ ] 全局变量 ID 二进制私有
- [ ] 字符串去重正确

### 性能验证

- [ ] 大型二进制文件（>10MB）处理时间合理
- [ ] 增量同步只处理变更文件
- [ ] Neo4j 导入使用批量操作

---

## 8. 风险和缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| IDA API 变更 | 提取引擎失效 | `ida_adapter.py` 集中封装，便于适配 |
| ID 生成不一致 | 数据关联断裂 | 保留现有算法，添加单元测试 |
| 文件导出依赖 IDA | 无法独立运行 | 文件导出标记为可选，仅在 IDA 环境执行 |
| 迁移过程中断 | 代码不可用 | 分阶段迁移，每阶段保持可运行状态 |

---

## 附录 A: ID 生成算法汇总

| 节点类型 | 算法 | 输入 | 作用域 |
|----------|------|------|--------|
| Binary | SHA-256 | 文件内容 | 全局唯一 |
| Function | MD5 | `{binary_hash}_{rva_hex}` | 二进制私有 |
| DataSlot (结构体) | MD5 | `{struct_name}_{offset}` | **跨二进制共享** |
| DataSlot (全局) | MD5 | `{binary_hash}_GLOBAL_{rva_hex}` | 二进制私有 |
| String | MD5 | 字符串内容 | 全局去重 |

---

## 附录 B: 配置文件更新建议

```yaml
# config.yaml 新增/修改项

# 提取引擎配置
extraction:
  enable_dataflow: true        # 启用 DataFlow 分析（需要 Hex-Rays）
  max_function_size: 100000    # 跳过过大函数
  skip_lib_functions: true     # 跳过库函数

# 导出配置
export:
  auto_export_files: true      # sync 时自动导出文件
  file_types:                  # 导出文件类型
    - pseudo_c
    - structures
    - import_table
    - export_table
    - string_table
```
