# IDA-Graphy Copilot 指导文档

## 项目概述

IDA-Graphy 是一个模块化的二进制分析框架，使用 IDA Pro 从可执行文件创建图数据库。这是一个**双层项目**：

1. **表层**："IDA Export" - 简单的反编译文件导出，供 AI IDE 使用
2. **核心层**："IDA-Graphy" - 基于项目的高级二进制分析，集成 Neo4j 图数据库

## 模块化架构

项目采用四层模块化设计，数据流向清晰：

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

### 模块职责边界

| 模块 | 输入 | 输出 | 职责 |
|------|------|------|------|
| **ProjectManager** | CLI 命令 | 协调其他模块 | 项目 CRUD、文件变更追踪、sync 流程编排 |
| **ExtractionEngine** | 二进制文件路径 | `RawBinaryData` DTO | IDA API 调用、原始数据收集、DataFlow 分析 |
| **GraphMapper** | `RawBinaryData` | `GraphData` | ID 生成、模型构建、结构体规范化 |
| **ExportManager** | `GraphData` | Neo4j/CSV/文件 | 数据持久化、文件生成 |

### 关键设计原则

1. **严格分层**：提取引擎只返回原始数据（地址、名称），不生成 ID；图映射器负责所有 ID 计算
2. **sync 自动导出**：每次项目同步时自动生成所有文件（伪C、结构体、导入导出表、字符串表）
3. **独立数据库**：每个项目维护独立 Neo4j 数据库（`idg-project-{name}`）
4. **DataFlow 集成**：Hex-Rays 可用时自动启用 ctree 分析，提取 READS/WRITES 边

## 目录结构

```
core/
├── extraction/                 # 提取引擎模块
│   ├── __init__.py
│   ├── engine.py               # ExtractionEngine 主入口
│   ├── raw_data.py             # RawBinaryData 等 DTO 定义
│   ├── ida_adapter.py          # idalib API 封装
│   └── dataflow.py             # DataFlow 分析
├── mapping/                    # 图映射器模块
│   ├── __init__.py
│   ├── graph_mapper.py         # GraphMapper 主类
│   ├── id_generator.py         # NodeIDGenerator
│   ├── struct_normalizer.py    # 结构体名称规范化
│   └── symbol_resolver.py      # 跨二进制符号解析
├── project/                    # 项目管理模块
│   ├── __init__.py
│   ├── manager.py              # ProjectManager 主类
│   ├── metadata.py             # ProjectMetadata, BinaryFile
│   └── file_tracker.py         # 文件变更追踪
└── models.py                   # 图模型定义 (节点/边)

exporters/
├── __init__.py
├── export_manager.py           # ExportManager 统一接口
├── neo4j_exporter.py           # Neo4j 导出
├── csv_exporter.py             # CSV 导出
└── file_exporter.py            # 文件导出 (伪C/结构体/表)

database/
├── __init__.py
└── neo4j_manager.py            # Neo4j 连接管理

# 兼容性与历史文件
已移除旧兼容层与历史实现，请直接使用 core/mapping 和 core/extraction 下的新模块。
```

## 原始数据 DTO

提取引擎返回的原始数据结构位于 `core/extraction/raw_data.py`，**只包含地址和原始名称，不包含计算后的 ID**：

| DTO | 说明 |
|-----|------|
| `RawBinaryInfo` | 二进制元信息 (name, base_addr, arch, compile_ts) |
| `RawFunction` | 函数原始数据 (ea, name, size, flags, signature) |
| `RawString` | 字符串原始数据 (ea, content, encoding) |
| `RawGlobal` | 全局变量原始数据 (ea, name, size) |
| `RawStructMember` | 结构体成员 (struct_name, offset, name, size) |
| `RawCall` | 调用关系 (caller_ea, callee_ea, call_addr, call_type) |
| `RawDataAccess` | 数据访问 (func_ea, target_ea, is_write, op_type, const_val, is_condition) |
| `RawBinaryData` | 聚合容器 |

## 图数据模型（`core/models.py`）

项目围绕丰富的图数据模型构建，设计侧重于**"动作意图"**，这是 AI Agent 理解代码逻辑的关键。

#### 节点类型定义

##### 1. `BinaryNode` - 容器节点（物理层）
代表一个可执行文件或动态库。

**Label**: `:Binary`  
**ID 生成**: `SHA256(file_content)` - 文件内容的完整二进制哈希

| 属性 | 类型 | 说明 |
|------|------|------|
| `hash` | String | **主键**，全局唯一标识 |
| `name` | String | 文件名（如 `fw_engine.exe`）|
| `base_addr` | Long | 加载基址（如 `0x140000000`），用于 RVA ↔ VA 转换 |
| `arch` | String | 架构（如 `x86_64`、`MIPS`、`ARM`）|
| `compile_ts` | Long | 编译时间戳，用于版本迭代判断 |

##### 2. `FunctionNode` - 行为节点（逻辑层）
代码的执行单元。

**Label**: `:Function`  
**ID 生成**: `MD5(binary_hash + "_" + rva_hex)` - 跨二进制唯一

| 属性 | 类型 | 说明 |
|------|------|------|
| `uid` | String | **主键**，跨二进制唯一标识 |
| `rva` | Long | 相对虚拟地址（函数起始 RVA）|
| `name` | String | 符号名（如 `Process_Packet`）或 `sub_XXXX` |
| `size` | Int | 函数长度（字节）|
| `is_lib` | Boolean | **AI 过滤器** - `True` 表示标准库函数（应忽略）|
| `func_type` | String | `NORMAL`（普通）、`IMPORT`（导入）、`EXPORT`（导出）、`THUNK`（跳转）|
| `signature` | String | 函数原型（如 `int func(void* ctx)`）|
| `complexity` | Int | 圈复杂度 |
| `binary_id` | String | **[冗余优化]** 所属 Binary 的 hash，用于快速过滤 |

**func_type 分类规则**：
- `EXPORT`: 在导出表中的函数
- `IMPORT`: Thunk 函数且跳转到 .idata 段或名称包含 `__imp_`
- `THUNK`: IDA 标记的跳转函数但不是 IMPORT
- `NORMAL`: 普通业务函数

##### 3. `DataSlotNode` - 状态节点（数据层）
业务逻辑的持久化载体，分为"结构体成员"和"全局变量"。

**Label**: `:DataSlot`  
**ID 生成**:
- **结构体成员**: `MD5(struct_name + "_" + offset_decimal)` - **跨二进制共享**
- **全局变量**: `MD5(binary_hash + "_GLOBAL_" + rva_hex)` - 二进制私有

| 属性 | 类型 | 说明 |
|------|------|------|
| `uid` | String | **主键** |
| `base_type` | String | 结构体名（如 `SessionEntry`）或 `GLOBAL` |
| `offset` | Int | 扁平化的绝对偏移量（十进制）|
| `size` | Int | 数据宽度（1, 2, 4, 8 字节）|
| `name` | String | 可读名称（如 `status`、`flags`、`g_Config`）|
| `is_global` | Boolean | `True` = 全局变量，`False` = 结构体成员 |

##### 4. `StringNode` - 语义节点（语义层）
常量字符串，用于"锚定"业务含义。

**Label**: `:String`  
**ID 生成**: `MD5(content)` - 基于内容去重

| 属性 | 类型 | 说明 |
|------|------|------|
| `hash` | String | **主键** |
| `content` | String | 字符串实际内容（需清洗，去除乱码）|
| `encoding` | String | `ASCII`、`UTF-16` 等 |

#### 边类型定义

##### 1. `CONTAINS` - 物理归属
**用途**: 维护物理拓扑，用于"模块级"分析

**路径**:
- `(:Binary) -[:CONTAINS]-> (:Function)`
- `(:Binary) -[:CONTAINS]-> (:DataSlot {is_global:True})`
- `(:Binary) -[:CONTAINS]-> (:String)`

| 属性 | 说明 |
|------|------|
| `from_id` | Binary 节点 hash |
| `to_id` | 被包含节点 ID |

##### 2. `CALLS` - 控制流
**用途**: 函数调用关系

**路径**: `(:Function) -[:CALLS]-> (:Function)`

| 属性 | 类型 | 说明 |
|------|------|------|
| `from_id` | String | 调用者函数 UID |
| `to_id` | String | 被调用函数 UID |
| `call_type` | String | `DIRECT`（直接调用）、`INDIRECT`（虚表/指针）、`TAIL`（尾调用）|
| `count` | Int | 调用次数（高频可能暗示循环）|

##### 3. `LINKS_TO` - 动态链接
**用途**: 将不同二进制的逻辑缝合起来（IAT → EAT）

**路径**: `(:Function {type:'IMPORT'}) -[:LINKS_TO]-> (:Function {type:'EXPORT'})`

| 属性 | 类型 | 说明 |
|------|------|------|
| `from_id` | String | IMPORT 函数 UID |
| `to_id` | String | EXPORT 函数 UID |
| `dll_name` | String | DLL 名称（如 `kernel32.dll`）|
| `func_name` | String | 函数名称（如 `CreateFileW`）|

##### 4. `REFERENCES` - 语义引用
**用途**: 函数使用了该字符串

**路径**: `(:Function) -[:REFERENCES]-> (:String)`

| 属性 | 说明 |
|------|------|
| `from_id` | 函数 UID |
| `to_id` | 字符串 hash |

##### 5. `WRITES` - 写操作（核心业务流）
**定义**: 函数**修改**了某个状态

**路径**: `(:Function) -[:WRITES]-> (:DataSlot)`

| 属性 | 类型 | 说明 |
|------|------|------|
| `from_id` | String | 函数 UID |
| `to_id` | String | DataSlot UID |
| `op_type` | String | `ASSIGN`（赋值）、`OR`（置位）、`AND`（清位）、`ADD`（累加）|
| `const_val` | String | **关键**：写入的具体值（如 `0x80`、`1`）|
| `loc` | Long | 操作发生的指令 RVA |

##### 6. `READS` - 读操作（核心业务流）
**定义**: 函数**使用**了某个状态

**路径**: `(:Function) -[:READS]-> (:DataSlot)`

| 属性 | 类型 | 说明 |
|------|------|------|
| `from_id` | String | 函数 UID |
| `to_id` | String | DataSlot UID |
| `condition` | Boolean | **关键**：`True` = 发生在 if/switch/loop 判断中（控制流依赖），`False` = 仅用于数据计算或传递 |
| `op_type` | String | `CMP`、`TEST`、`MOV` 等 |
| `const_val` | String | 比较的常量值（如 `if (state == 3)` 中的 `3`）|
| `loc` | Long | 操作发生的指令 RVA |

### 项目管理（`core/project/`）
- **项目中心式工作流**：将多个二进制文件组织到统一的分析任务中
- **Neo4j 数据库隔离**：每个项目获得独立数据库（前缀：`idg-project-`）
- **变更跟踪**：基于 SHA256 的文件修改检测（`file_tracker.py`）
- **元数据持久化**：`files_manifest.json` + 项目元数据
- **sync 流程编排**：协调提取→映射→导出的完整流程

### IDA 集成（`core/extraction/`）
- **要求**：IDA Pro 9.0+ 及 idalib Python 绑定
- **自动分析**：使用 `idalib.open_database()` 进行无头处理
- **图提取**：自动化的函数/字符串/结构分析

### 存储层
- **主要方式**：Neo4j 图数据库（可配置连接）
- **备用方案**：CSV 导出（兼容 Neo4j）
- **事务支持**：原子操作确保数据一致性

## 关键开发工作流

### 环境设置
```bash
# 安装依赖
pip install -e .

# 在 config.yaml 中配置 IDA 路径
ida:
  path: "C:\\Program Files\\IDA Professional 9.2"
  idalib_python: "C:\\Program Files\\IDA Professional 9.2\\idalib\\python"

# 配置 Neo4j（可选）
neo4j:
  connection:
    uri: "neo4j://127.0.0.1:7687"
    user: "neo4j"
    password: "your_password"
```

### 项目工作流
```bash
# 创建项目
ida-graphy project create malware_analysis --description "APT 活动分析"

# 添加二进制文件
ida-graphy project add malware_analysis sample1.exe
ida-graphy project add malware_analysis sample2.dll

# 分析并同步到数据库
ida-graphy project sync malware_analysis

# 检查状态
ida-graphy project status malware_analysis
```

### 测试与验证
```bash
# 测试 Neo4j 连接
ida-graphy neo4j test

# 列出项目数据库
ida-graphy neo4j databases

# 运行项目测试
pytest tests/
```

## 项目特定约定

### ID 生成算法详解

为保证数据一致性和跨二进制的逻辑关联，严格遵守以下 ID 生成规则（使用 UTF-8 编码）：

#### 1. Binary 节点（容器）
物理文件的唯一指纹。

**算法**: `SHA-256`  
**输入**: 文件的完整二进制内容（Raw Bytes）  
**示例**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

```python
import hashlib
binary_id = hashlib.sha256(file_content).hexdigest()
```

#### 2. Function 节点（行为）
函数必须绑定到特定 Binary，因为不同版本的库中同一 RVA 可能对应完全不同的代码。

**算法**: `MD5`  
**输入**: `{binary_sha256}_{rva_hex}`
- `binary_sha256`: Binary 节点的 ID
- `rva_hex`: 函数起始相对虚拟地址（小写 hex，不带 `0x`）

```python
input_str = f"{binary_sha256}_{hex(func_rva)[2:].lower()}"
node_id = hashlib.md5(input_str.encode()).hexdigest()
```

#### 3. DataSlot 节点 - 结构体成员（通用型）
**关键设计**: 结构体成员 ID **不包含** Binary Hash，使不同二进制中对同一结构体的访问能汇聚到同一节点。

**算法**: `MD5`  
**输入**: `{struct_name}_{absolute_offset_decimal}`
- `struct_name`: 标准化的结构体名称（去除 `struct` 前缀）
- `absolute_offset_decimal`: 扁平化后的绝对偏移量（十进制整数）

```python
input_str = f"{struct_name}_{int(offset)}"
node_id = hashlib.md5(input_str.encode()).hexdigest()
```

#### 4. DataSlot 节点 - 全局变量（私有型）
全局变量必须绑定到 Binary，避免不同 DLL 的同名全局变量冲突。

**算法**: `MD5`  
**输入**: `{binary_sha256}_GLOBAL_{rva_hex}`

```python
input_str = f"{binary_sha256}_GLOBAL_{hex(global_rva)[2:].lower()}"
node_id = hashlib.md5(input_str.encode()).hexdigest()
```

#### 5. String 节点（语义锚点）
用于去重存储字符串。

**算法**: `MD5`  
**输入**: `string_content`（UTF-8 编码）

```python
node_id = hashlib.md5(string_content.encode('utf-8')).hexdigest()
```

#### 完整示例代码

参考 `core/mapping/id_generator.py` 中的 `NodeIDGenerator` 类：

```python
class NodeIDGenerator:
    def __init__(self, binary_content=None, binary_hash=None):
        """初始化：必须提供 binary_content 或已计算的 binary_hash"""
        if binary_hash:
            self.binary_hash = binary_hash
        elif binary_content:
            self.binary_hash = hashlib.sha256(binary_content).hexdigest()
        else:
            raise ValueError("Must provide binary content or hash")
    
    def get_binary_id(self):
        """获取 Binary 节点 ID (SHA256)"""
        return self.binary_hash
    
    def get_function_id(self, rva):
        """获取 Function 节点 ID - Binary 私有"""
        rva_str = hex(rva)[2:].lower()
        return hashlib.md5(f"{self.binary_hash}_{rva_str}".encode()).hexdigest()
    
    def get_struct_slot_id(self, struct_name, offset):
        """获取结构体 DataSlot ID - 全局通用（跨 Binary）"""
        return hashlib.md5(f"{struct_name}_{int(offset)}".encode()).hexdigest()
    
    def get_global_slot_id(self, rva):
        """获取全局变量 DataSlot ID - Binary 私有"""
        rva_str = hex(rva)[2:].lower()
        return hashlib.md5(f"{self.binary_hash}_GLOBAL_{rva_str}".encode()).hexdigest()
    
    def get_string_id(self, content):
        """获取 String 节点 ID"""
        return hashlib.md5(content.encode('utf-8')).hexdigest()
```

**使用示例**:
```python
# 分析 kernel32.dll
gen = NodeIDGenerator(binary_hash="a1b2c3d4e5f6...")

# 生成函数 ID (0x1000)
func_id = gen.get_function_id(0x1000)

# 生成结构体成员 ID (Session.status, offset 8)
# 注意：即便在 user32.dll 中调用，生成的 ID 也相同，从而实现关联
slot_id = gen.get_struct_slot_id("SessionEntry", 8)
```

### 配置管理
- **主配置**：`config.yaml` 包含完整设置
- **项目级覆盖**：存储在项目元数据中
- **环境检测**：自动验证 IDA/idalib 可用性

### 错误处理模式
- **自定义异常**：`ProjectError`、`Neo4jError`、`ProjectExportError`
- **优雅降级**：Neo4j 不可用时回退到 CSV
- **事务回滚**：失败时保证数据库一致性

## 集成点

### 外部依赖
- **IDA Pro 9.0+**：二进制分析必需（不可通过 pip 安装）
- **Neo4j**：可选但推荐用于图操作
- **Python 包**：PyYAML、neo4j、pandas、tqdm（见 requirements.txt）

### 跨组件通信
- **数据流**：`ExtractionEngine` → `RawBinaryData` → `GraphMapper` → `GraphData` → `ExportManager` → Neo4j/CSV/文件
- **项目生命周期**：`ProjectManager` 编排整个 sync 流程，协调各模块
- **配置级联**：全局配置 → 项目覆盖 → 运行时参数

## 常见开发任务

### 添加新节点类型
1. 在 `core/extraction/raw_data.py` 中添加原始 DTO
2. 在 `core/extraction/engine.py` 中添加提取逻辑
3. 在 `core/mapping/graph_mapper.py` 中添加映射逻辑
4. 在 `core/models.py` 中定义带 `to_dict()` 方法的 dataclass
5. 更新 `exporters/` 中的导出器

### 扩展分析能力
1. 修改 `core/extraction/engine.py` 提取新的原始数据
2. 在 `core/extraction/raw_data.py` 中定义对应 DTO
3. 在 `core/mapping/graph_mapper.py` 中添加映射逻辑
4. 如需要，更新 `core/models.py` 中的边类型
5. 在 `exporters/` 中添加相应的导出逻辑

### 添加新命令
1. 在 `ida_graphy.py` 中添加命令解析器
2. 遵循 `cmd_*` 模式实现命令函数
3. 使用自定义异常添加错误处理

## 理解关键文件

- [`core/models.py`]：完整的数据模型定义
- [`ida_graphy.py`]：CLI 接口和命令实现
- [`config.yaml`]：综合配置模板
- [`core/project/manager.py`]：项目生命周期管理
- [`core/extraction/engine.py`]：IDA 数据提取引擎
- [`core/extraction/raw_data.py`]：原始数据 DTO 定义
- [`core/mapping/graph_mapper.py`]：图模型映射器
- [`core/mapping/id_generator.py`]：节点 ID 生成器
- [`database/neo4j_manager.py`]：图数据库操作
- [`exporters/export_manager.py`]：统一导出管理器

在使用此代码库时，始终理解项目中心式的特性和四层模块化架构。数据流向：`提取引擎(RawData)` → `图映射器(GraphData)` → `导出管理器(Neo4j/CSV/文件)`。图数据模型是基础——所有操作都围绕创建、操作和存储这些结构化的二进制分析结果表示。