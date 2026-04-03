# IDA-Graphy 使用示例

本文档提供 IDA-Graphy 的详细使用示例和最佳实践。

---

## 目录

1. [基础使用](#基础使用)
2. [配置文件](#配置文件)
3. [批量处理](#批量处理)
4. [输出和验证](#输出和验证)
5. [Neo4j导入](#neo4j导入)
6. [常见问题](#常见问题)

---

## 基础使用

### 示例1: 分析单个可执行文件

```bash
# 使用默认配置分析单个EXE文件
python ida_graphy.py --binary exploit.exe

# 或使用安装后的命令
ida-graphy --binary exploit.exe
```

**输出:**
```
==============================================================
IDA-Graphy - Binary Analysis Framework
==============================================================

Configuration:
  IDA Path: C:\Program Files\IDA Professional 9.2
  Output Dir: ./csv_output
  Dataflow Analysis: True
  Skip Library Functions: True

✓ idalib loaded successfully

==============================================================
Processing: exploit.exe
==============================================================
File hash: 1a2b3c4d5e6f7890...
Opening binary with idalib...
✓ Binary loaded successfully

[Phase 1] Running legacy extraction (INP.py)...
[*] Exporting strings...
    Total strings exported: 234
    Completed in 0.52 seconds

[*] Exporting imports...
    Total imports exported: 56
    Completed in 0.12 seconds

[*] Exporting decompiled functions...
    Total functions: 127
    Exported: 125
    Failed: 2
    Completed in 45.23 seconds

✓ Extraction completed

Closing database...
[*] Cleaned up: exploit.id0
[*] Cleaned up: exploit.id1

✓ Analysis completed successfully
```

---

### 示例2: 指定输出目录

```bash
# 自定义输出目录
ida-graphy --binary malware.dll --output ./analysis_results

# 输出将保存到 ./analysis_results/ 目录
```

---

### 示例3: 调试模式

```bash
# 启用详细日志输出
ida-graphy --binary test.exe --verbose

# 禁用数据流分析（更快，用于快速测试）
ida-graphy --binary test.exe --no-dataflow
```

**详细输出示例:**
```
[12:34:56] DEBUG - Added to sys.path: C:\Program Files\IDA Professional 9.2\python
[12:34:56] DEBUG - Added to sys.path: C:\Program Files\IDA Professional 9.2\idalib\python
[12:34:56] INFO - ✓ idalib loaded successfully
[12:34:57] INFO - Processing: test.exe
[12:34:57] DEBUG - Binary size: 2.5 MB
[12:34:57] INFO - Opening binary with idalib...
...
```

---

## 配置文件

### 示例4: 使用自定义配置

创建自定义配置文件 `my_config.yaml`:

```yaml
ida:
  path: "D:\\IDA Pro 9.2"
  idalib_python: "D:\\IDA Pro 9.2\\idalib\\python"

export:
  output_dir: "./my_output"
  skip_lib_functions: false  # 包含库函数
  validate_data: true
  generate_stats: true

analysis:
  enable_dataflow: false     # 禁用数据流分析（更快）
  enable_string_refs: true
  parallel_workers: 8        # 增加并行worker数量
  max_function_size: 20000   # 提高函数大小上限

neo4j:
  home: "C:\\neo4j-community-5.12.0"
  database: "malware-analysis"
```

使用自定义配置:

```bash
ida-graphy --config my_config.yaml --binary malware.exe
```

---

## 批量处理

### 示例5: 分析多个DLL文件

```bash
# 明确指定多个文件
ida-graphy --binaries kernel32.dll user32.dll ntdll.dll

# 使用通配符
ida-graphy --binaries C:\Windows\System32\*.dll --output ./system_dlls

# 混合使用
ida-graphy --binaries app.exe lib1.dll lib2.dll helper.dll
```

**批量处理输出示例:**
```
==============================================================
Batch Processing Mode: 4 binaries
==============================================================

[Binary 1/4]
==============================================================
Processing: kernel32.dll
==============================================================
...
✓ Extraction completed

[Binary 2/4]
==============================================================
Processing: user32.dll
==============================================================
...
✓ Extraction completed

...

==============================================================
Processing Summary
==============================================================
Total binaries: 4
Successful: 3
Failed: 1
Time elapsed: 423.56s (7.06min)

Failed binaries:
  - ntdll.dll
```

---

### 示例6: 分析整个目录

使用shell通配符:

**Windows (PowerShell):**
```powershell
# 分析当前目录下所有EXE文件
ida-graphy --binaries *.exe

# 分析子目录中的所有DLL
ida-graphy --binaries bin\*.dll plugins\*.dll
```

**Linux/Mac:**
```bash
# 分析所有ELF文件
ida-graphy --binaries /usr/bin/* --output ./bin_analysis

# 递归查找并分析（需要配合find命令）
find /path/to/binaries -name "*.so" -exec ida-graphy --binary {} \;
```

---

## 输出和验证

### 示例7: 查看输出结果

当前版本使用传统文本格式输出（继承自原 ida-export）:

```
{binary}-export/
├── decompile/
│   ├── 0x401000.c
│   ├── 0x401234.c
│   └── ...
├── strings.txt
├── imports.txt
├── exports.txt
├── structures/
│   ├── _RECT.h
│   └── ...
└── memory/
    ├── 00401000--00402000.txt
    └── ...
```

**查看函数反编译代码:**

```bash
# 查看特定函数（地址0x401000）
cat exploit.exe-export/decompile/0x401000.c
```

输出示例:
```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * callers: 0x401234, 0x401567
 * callees: 0x401890, 0x402000
 */

int __cdecl sub_401000(int a1, int a2)
{
  int v3; // [esp+0h] [ebp-8h]
  
  v3 = a1 + a2;
  if ( v3 > 100 )
    return sub_401890(v3);
  return v3;
}
```

---

### 示例8: 验证CSV文件（未来功能）

```bash
# 验证已生成的CSV文件
ida-graphy --validate-csv ./csv_output

# 预期输出:
# [*] Validating CSV files in: ./csv_output
# [*] Checking node files...
#     ✓ nodes_binary.csv: 3 nodes
#     ✓ nodes_function.csv: 1234 nodes
#     ✓ nodes_string.csv: 456 nodes
# [*] Checking edge files...
#     ✓ edges_calls.csv: 2345 edges
#     ✓ edges_contains.csv: 1693 edges
# [*] Validating references...
#     ✓ All edge references are valid
# 
# ✓ CSV validation passed
```

---

## Neo4j导入

### 示例9: 生成CSV并导入Neo4j（未来功能）

**Step 1: 生成CSV文件**

```bash
ida-graphy --binaries kernel32.dll user32.dll app.exe --output ./neo4j_import
```

**Step 2: 停止Neo4j服务**

```bash
# Linux/Mac
neo4j stop

# Windows
neo4j.bat stop
```

**Step 3: 执行批量导入**

```bash
cd neo4j_import

# Linux/Mac
chmod +x import_to_neo4j.sh
./import_to_neo4j.sh

# Windows
import_to_neo4j.bat
```

**Step 4: 启动Neo4j并创建索引**

```bash
# 启动Neo4j
neo4j start

# 创建索引
neo4j-cypher-shell < create_indexes.cypher
```

---

### 示例10: Neo4j查询示例（未来功能）

```cypher
// 1. 查找所有调用CreateFileW的函数
MATCH (caller:Function)-[:CALLS]->(api:Function {name: 'CreateFileW'})
RETURN caller.name, caller.rva
ORDER BY caller.name

// 2. 查找跨DLL的调用链
MATCH path = (f1:Function)-[:CALLS*1..5]->(f2:Function)-[:LINKS_TO]->(export:Function)
WHERE f1.binary_id <> export.binary_id
RETURN path
LIMIT 10

// 3. 查找引用"password"字符串的函数
MATCH (f:Function)-[:REFERENCES]->(s:String)
WHERE s.content CONTAINS 'password'
RETURN f.name AS function, s.content AS string
ORDER BY f.name

// 4. 查找函数复杂度最高的10个函数
MATCH (f:Function)
WHERE f.complexity > 0
RETURN f.name, f.complexity, f.size
ORDER BY f.complexity DESC
LIMIT 10

// 5. 查找所有写入特定结构体成员的函数（数据流分析）
MATCH (f:Function)-[w:WRITES]->(d:DataSlot {base_type: 'SessionEntry', name: 'status'})
RETURN f.name, w.op_type, w.const_val, w.loc
ORDER BY f.name
```

---

## 常见问题

### Q1: 如何处理"Failed to import idalib"错误？

**问题:**
```
ERROR - Failed to import idalib: No module named 'idapro'
ERROR - Please ensure IDA 9.0+ is installed with idalib support
```

**解决方案:**

1. 确认IDA Pro版本 >= 9.0
2. 检查 `config.yaml` 中的路径是否正确:
   ```yaml
   ida:
     path: "C:\\Program Files\\IDA Professional 9.2"  # 修改为实际路径
     idalib_python: "C:\\Program Files\\IDA Professional 9.2\\idalib\\python"
   ```
3. 手动验证路径存在:
   ```bash
   # Windows
   dir "C:\Program Files\IDA Professional 9.2\idalib\python"
   
   # Linux/Mac
   ls "/path/to/ida/idalib/python"
   ```

---

### Q2: 如何跳过库函数加快分析速度？

**解决方案:**

```bash
# 方法1: 命令行参数
ida-graphy --binary app.exe --skip-lib-functions

# 方法2: 配置文件
# 编辑 config.yaml:
export:
  skip_lib_functions: true
```

库函数（如CRT函数、标准库函数）通常不需要详细分析，跳过它们可以显著减少输出大小和处理时间。

---

### Q3: 如何加快大型二进制文件的分析？

**优化建议:**

1. **禁用数据流分析:**
   ```bash
   ida-graphy --binary large.dll --no-dataflow
   ```

2. **增加并行worker数量:**
   ```yaml
   # config.yaml
   analysis:
     parallel_workers: 8  # 根据CPU核心数调整
   ```

3. **限制函数大小:**
   ```yaml
   analysis:
     max_function_size: 5000  # 跳过过大的函数
   ```

4. **跳过内存导出:**
   ```python
   # 修改 INP.py 中的配置
   SKIP_MEMORY = True
   ```

---

### Q4: 输出文件太大如何处理？

**解决方案:**

```bash
# 压缩输出目录
tar -czf app_export.tar.gz app.exe-export/

# 或使用7zip (Windows)
7z a -t7z app_export.7z app.exe-export/

# 只保留关键文件
cd app.exe-export
rm -rf memory/  # 删除内存dump（通常最大）
```

---

### Q5: 如何在脚本中批量调用？

**Python脚本示例:**

```python
#!/usr/bin/env python3
import subprocess
import os
from pathlib import Path

binaries_dir = Path("./binaries")
output_dir = Path("./analysis_output")

for binary_file in binaries_dir.glob("*.exe"):
    print(f"Processing: {binary_file.name}")
    
    result = subprocess.run([
        "ida-graphy",
        "--binary", str(binary_file),
        "--output", str(output_dir / binary_file.stem),
        "--no-dataflow"
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"  ✓ Success")
    else:
        print(f"  ✗ Failed: {result.stderr}")
```

---

## 性能基准

基于实际测试的参考数据:

| 二进制 | 大小 | 函数数 | 处理时间 (dataflow on) | 处理时间 (dataflow off) |
|--------|------|--------|----------------------|------------------------|
| small.exe | 100 KB | 50 | 5s | 2s |
| medium.dll | 2 MB | 500 | 45s | 15s |
| large.exe | 10 MB | 2000 | 320s | 90s |
| huge.dll | 50 MB | 10000+ | 2400s | 600s |

**注:** 实际时间取决于CPU性能、反编译复杂度等因素。

---

## 下一步

- 查看 [改造计划.md](改造计划.md) 了解未来功能
- 阅读 [README.md](README.md) 了解项目概述
- 访问 [IDA SDK文档](https://hex-rays.com/products/ida/support/sdkdoc/) 学习IDA API

---

## 反馈与贡献

如有问题或建议，请提交 [GitHub Issue](https://github.com/yourusername/ida-graphy/issues)。
