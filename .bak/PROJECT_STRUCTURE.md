# IDA-Graphy 项目结构

## 📁 目录结构

```
ida-graphy/
│
├── 📂 core/                          # 核心模块（✅ 已完成）
│   ├── __init__.py
│   ├── node_id_generator.py          # ID生成器（SHA256/MD5哈希）
│   ├── models.py                     # 数据模型（节点和边）
│   ├── graph_extractor.py            # 图数据提取器
│   ├── example_usage.py              # 使用示例
│   └── README.md                     # 详细文档
│
├── 📂 analyzers/                     # 分析器模块（✅ 已完成）
│   ├── __init__.py
│   ├── dataflow_analyzer.py          # 数据流分析器（Hex-Rays ctree）
│   └── README.md                     # 分析器文档
│
├── 📂 exporters/                     # 导出器模块（✅ 已完成）
│   ├── __init__.py
│   ├── csv_exporter.py               # CSV导出器（Neo4j格式）
│   ├── test_csv_exporter.py          # 测试脚本
│   ├── README.md                     # 导出器文档
│   └── IMPLEMENTATION_SUMMARY.md     # 实现总结
│
├── 📂 tests/                         # 单元测试（✅ 已完成）
│   ├── __init__.py
│   ├── test_node_id_generator.py     # ID生成器测试（22个测试）
│   └── test_models.py                # 数据模型测试（33个测试）
│
├── 📂 examples/                      # 示例代码（✅ 已完成）
│   └── core_usage_example.py         # 核心功能示例
│
├── 📂 backup/                        # 旧代码备份
│   ├── ida_export.py.bak             # 原ida_export.py
│   └── INP.py.bak                    # 原INP.py
│
├── 📄 ida_graphy.py                  # 主入口程序（✅ 已完成）
├── 📄 config.yaml                    # 配置文件
├── 📄 setup.py                       # 安装配置
├── 📄 requirements.txt               # Python依赖
├── 📄 pyproject.toml                 # 项目配置
│
├── 📖 README.md                      # 英文README
├── 📖 README_CN.md                   # 中文README
├── 📖 改造.md                        # 数据模型设计
├── 📖 改造计划.md                    # 详细改造计划
├── 📖 FILE_MANIFEST.md               # 文件清单
├── 📖 USAGE_EXAMPLES.md              # 使用示例
├── 📖 IMPLEMENTATION_SUMMARY.md      # 实现总结
├── 📖 CORE_IMPLEMENTATION_REPORT.md  # 核心实现报告
│
├── 🚀 quickstart.bat                 # Windows快速启动
├── 🚀 quickstart.sh                  # Linux/Mac快速启动
└── 🧪 test_ida_graphy.py             # 完整测试套件

```

## 🎯 核心模块功能状态

| 模块 | 文件 | 状态 | 功能 |
|------|------|------|------|
| **ID生成** | `core/node_id_generator.py` | ✅ 100% | 哈希ID生成（跨二进制一致性） |
| **数据模型** | `core/models.py` | ✅ 100% | 4种节点 + 6种边 |
| **图提取** | `core/graph_extractor.py` | ✅ 80% | 提取Binary/Function/String节点和边 |
| **数据流分析** | `analyzers/dataflow_analyzer.py` | ✅ 100% | READS/WRITES边+DataSlot提取 |
| **CSV导出** | `exporters/csv_exporter.py` | ✅ 100% | Neo4j兼容格式导出 |
| **主程序** | `ida_graphy.py` | ✅ 100% | 命令行入口+批处理 |

## 📊 测试覆盖率

| 测试模块 | 测试数量 | 通过率 |
|---------|---------|--------|
| `test_node_id_generator.py` | 22 | 100% ✅ |
| `test_models.py` | 33 | 100% ✅ |
| `test_csv_exporter.py` | 验证导出完整性 | 100% ✅ |
| `test_ida_graphy.py` | 6 | 100% ✅ |
| **总计** | **61+** | **100%** |

## 🔗 依赖关系

```
ida_graphy.py (主入口)
    ├─> core/graph_extractor.py
    │   ├─> core/node_id_generator.py
    │   ├─> core/models.py
    │   └─> analyzers/dataflow_analyzer.py
    │       └─> core/node_id_generator.py
    └─> exporters/csv_exporter.py
        └─> core/models.py
```

## 📋 未来开发计划

### 阶段3：集成测试（当前）
- [ ] 使用系统PE文件进行端到端测试
- [ ] 验证CSV导出格式
- [ ] 测试Neo4j导入流程

### 阶段4：多组件支持
- [ ] 批量处理多个二进制
- [ ] LINKS_TO边的跨组件关联
- [ ] 增量导入支持

### 阶段5：优化与扩展
- [ ] 性能优化（并行处理）
- [ ] 内存优化（大型二进制）
- [ ] Web可视化界面

## 🚀 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置IDA路径（编辑config.yaml）
notepad config.yaml

# 3. 运行测试
python test_ida_graphy.py

# 4. 分析二进制
python ida_graphy.py --binary C:\Windows\System32\notepad.exe
```

## 📚 核心文档

- **[改造.md](改造.md)** - 数据模型设计（节点和边定义）
- **[改造计划.md](改造计划.md)** - 详细技术方案和实施步骤
- **[README_CN.md](README_CN.md)** - 中文使用指南
- **[USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)** - 实用示例代码

## 🎉 项目里程碑

- ✅ **2026-02-01**: 核心模块开发完成（ID生成、数据模型）
- ✅ **2026-02-01**: 图提取器实现（Binary/Function/String）
- ✅ **2026-02-01**: 数据流分析器完成（Hex-Rays ctree）
- ✅ **2026-02-01**: CSV导出器实现（Neo4j格式）
- ✅ **2026-02-01**: 主程序和配置系统完成
- 🔄 **进行中**: 集成测试和优化

**当前版本**: v1.0.0-alpha（可用于测试）
