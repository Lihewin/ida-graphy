# IDA-Graphy

**基于 IDA Pro 与 LadybugDB 的模块化二进制分析框架。**

将可执行文件转化为结构化图数据库，为 AI 辅助逆向工程提供深度语义支撑。

---

## 概述
* 想要AI逆向二进制？请用ida-pro-mcp。
* 你认同“终端命令即答案”？请用ida-no-mcp。
* 你想读懂一个巨大的商业二进制模块吗？苦于代码量过大塞不进上下文，又不知道怎么让AI拥有全局视野？试试引入IDA-Graphy吧。

IDA-Graphy 是一个**双层**项目：

- **IDA Export**：将 IDA 反编译结果导出为源码文件，直接投入任意 AI IDE（Cursor / Claude Code / ...），零配置，天然适配索引与并行分析。
- **IDA-Graphy**：基于项目的高级二进制分析，将函数调用关系、数据流、结构体成员、导入/导出表等统一写入 LadybugDB（项目内 `graph.lbug`），支持跨二进制符号关联与多维度查询。

---

## 架构

```
ida_graphy.py (CLI)
      │
      ▼
ProjectManager          # 项目生命周期管理、图数据库文件协调
      │
      ▼
ExtractionEngine        # idalib 调用，返回 RawBinaryData DTO
      │
      ▼
GraphMapper             # 原始数据 → 图节点/边，ID 生成，结构体规范化
      │
      ▼
ExportManager           # 写入 LadybugDB / 生成文件 artifact / 运行 Ghidra fallback
```

| 模块 | 路径 | 职责 |
|------|------|------|
| ProjectManager | `core/project/` | 项目 CRUD、变更追踪、sync 编排 |
| ExtractionEngine | `core/extraction/` | IDA API 调用、Hex-Rays single-cfunc harvest、DataFlow 分析 |
| GraphMapper | `core/mapping/` | ID 生成、模型构建、跨二进制解析 |
| ExportManager | `exporters/` | LadybugDB 持久化、文件 artifact、Ghidra fallback 补充导出 |

---

## 环境要求

- **IDA Pro 9.0+**
- **Python 3.8+**
- **LadybugDB Python bindings**（推荐：`real-ladybug`）
- **Ghidra + Java/JDK**（仅当 Hex-Rays 触发 `stack frame is too big` fallback 时需要）

---

## 安装

```bash
# 推荐：创建本地 .venv 并安装运行/开发依赖
uv sync --extra dev

# 或使用 pip
pip install -e ".[dev]"
```

---

## 配置

编辑 `config.yaml`（LadybugDB 为嵌入式数据库，无需额外连接配置）：

```yaml
ida:
  path: "C:\\Program Files\\IDA Professional 9.2"
  idalib_python: "C:\\Program Files\\IDA Professional 9.2\\idalib\\python"

export:
  enable_file_export: true
  ghidra_fallback:
    # 仅用于 Hex-Rays 硬限制函数的补充反编译。
    path: "/opt/ghidra"
    # 可选：直接指定 analyzeHeadless。
    # analyze_headless: "/opt/ghidra/support/analyzeHeadless"

projects:
      root_dir: "projects"

# 图数据库文件默认写入：<projects.root_dir>/<project>/graph.lbug
# 每次 `ida-graphy project sync` 会全量重建该文件。
```

---

## 使用

### IDA Export（快速导出，供 AI IDE 使用）

```bash
ida-graphy export <二进制文件路径>
```

导出内容：

| 文件/目录 | 内容 |
|-----------|------|
| `decompile/` | 反编译伪 C 代码（含调用关系） |
| `structs.h` | 结构体定义 |
| `strings.txt` | 字符串表 |
| `imports.txt` | 导入表 |
| `exports.txt` | 导出表 |

项目式分析不会把导出文件建成图节点。函数伪代码路径写入 `Function.decompiled_file`，结构体定义路径写入非 global `DataSlot.struct_file`。每个二进制目录还会生成 `exports/<binary>/_export_manifest.json`，其路径和 SHA-256 写入 `Binary.export_manifest_file` / `Binary.export_manifest_hash`，用于快速校验数据库路径与磁盘文件是否一致。

示例查询：

```cypher
MATCH (f:Function)
WHERE f.name = "target_function"
RETURN f.name, f.decompiled_file, f.pseudocode_hash;
```

### IDA-Graphy（项目式分析，写入图数据库）

```bash
# 创建项目
ida-graphy project create <项目名> --description "描述"

# 添加二进制文件
ida-graphy project add <项目名> <二进制路径>

# 分析并同步到 LadybugDB（写入项目内 graph.lbug）
ida-graphy project sync <项目名>

# 查看状态
ida-graphy project status <项目名>

# 快速校验数据库路径、manifest 和导出文件
ida-graphy project verify-exports <项目名>
```

### LadybugDB 管理

```bash
# 测试 LadybugDB bindings
ida-graphy ladybugdb test

# 列出项目 LadybugDB 文件（graph.lbug）
ida-graphy ladybugdb databases

# 执行 Cypher 查询并以表格输出结果
ida-graphy ladybugdb query <项目名> "MATCH (n) RETURN n LIMIT 5"

# 以 JSON 输出结果
ida-graphy ladybugdb query <项目名> "MATCH (n) RETURN n LIMIT 5" --output-format json
```

---

## 图数据模型

| 节点 | 说明 |
|------|------|
| `:Binary` | 可执行文件容器，ID = `SHA256(文件内容)`，记录 manifest 路径和哈希 |
| `:Function` | 函数节点，区分 NORMAL / IMPORT / EXPORT / THUNK |
| `:DataSlot` | 结构体成员或全局变量，结构体成员 ID 跨二进制共享 |
| `:String` | 常量字符串，基于内容去重 |

| 边 | 说明 |
|----|------|
| `CONTAINS` | Binary → Function / DataSlot / String 归属关系 |
| `CALLS` | 函数调用关系，含调用类型与次数 |
| `LINKS_TO` | 跨二进制动态链接（IAT → EAT） |
| `READS` | 函数读取 DataSlot，含条件判断标记 |
| `WRITES` | 函数写入 DataSlot，含操作类型与常量值 |
| `REFERENCES` | 函数引用 String |

### Hex-Rays 与 Ghidra fallback

Hex-Rays 是主语义来源。`ExtractionEngine` 对每个函数只保留一次 single-cfunc harvest，普通真实函数反编译失败会作为硬错误阻断分析，避免生成看似完整但缺失语义的数据库。

`stack frame is too big` 属于 Hex-Rays 硬限制。这类函数会进入 Ghidra fallback 队列，在 IDA 数据库关闭后由 Ghidra headless 单独导出，artifact 类型为 `ghidra_decompile`，文件头保留 `Source: Ghidra fallback` 与原 Hex-Rays 错误原因。Ghidra 输出是补充上下文，不会伪装成 Hex-Rays ctree 等价结果。

详细 Schema 见 [GRAPH_SCHEMA.md](GRAPH_SCHEMA.md)。

---

## Tips

分析目录中可额外放置以下内容，AI 将获得更完整的上下文：

| 目录 | 内容 |
|------|------|
| `docs/` | 逆向分析报告、协议文档、笔记 |
| `codes/` | exp、Frida scripts、解密脚本 |
| `apk/` | APK 反编译目录（APKLab 一键导出） |

---

## 开发

```bash
# 安装依赖
uv sync --extra dev

# 运行全量单元测试
uv run python -m unittest discover tests

# 运行 pytest
uv run pytest tests/
```

项目级 AI 规则位于 `.cursor/rules/`。旧的 Copilot 指令和历史备份/样本文件已从仓库清理，运行产物默认通过 `.gitignore` 排除。

## 感谢
Ida-Export模块受到[ida-no-mcp](https://github.com/P4nda0s/IDA-NO-MCP.git)项目启发。