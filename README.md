[English](README_EN.md) | 简体中文

# IDA Export

**告别 IDA MCP 复杂、冗长、卡顿的交互模式。**  

**AI 逆向，无需额外配置。**  

Simple · Fast · Intelligent · Low Cost

## 核心理念

Text、Source Code、Shell 是 LLM 原生语言。

AI 飞速发展，没有固定模式，工具应该保持简单。

把 IDA 反编译结果导出为源码文件，直接丢进任意 AI IDE（Cursor / Claude Code / ...），天然适配索引、并行、切片（反编译超大函数）等优化。

## 使用 (命令行模式 - 推荐)

1. 安装模块：

   ```bash
   pip install -e .
   ```

2. 运行导出：

   ```bash
   ida-export <二进制文件路径>
   ```

## 使用 (IDA 插件模式)

## 导出内容

| 文件/目录 | 内容 |
|-----------|------|
| `decompile/` | 反编译 C 代码（含调用关系） |
| `strings.txt` | 字符串表 |
| `imports.txt` | 导入表 |
| `exports.txt` | 导出表 |
| `memory/` | 内存 hexdump（1MB 分片） |

## Tips

在 IDB 目录下可以同时添加更多上下文，让 AI 获得完整视角：

| 目录 | 内容 |
|------|------|
| `apk/` | APK 反编译目录（APKLab 一键导出） |
| `docs/` | 逆向分析报告、笔记 |
| `codes/` | exp、Frida scripts、decryptor 等脚本 |

最先进的 AI 模型能够利用所有信息与脚本，为你提供最强力的逆向工程辅助。
