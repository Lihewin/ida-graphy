# CSV Exporter for Neo4j

将IDA逆向分析的图数据导出为Neo4j兼容的CSV格式，支持使用`neo4j-admin import`进行高效批量导入。

## 功能特性

### 📦 节点导出（4种类型）

1. **Binary节点** (`nodes_binary.csv`)
   - 可执行文件容器节点
   - 属性：hash、name、base_addr、arch、compile_ts

2. **Function节点** (`nodes_function.csv`)
   - 函数行为节点
   - 属性：uid、rva、name、size、is_lib、func_type、signature、complexity、binary_id

3. **DataSlot节点** (`nodes_dataslot.csv`)
   - 数据状态节点（结构体成员/全局变量）
   - 属性：uid、base_type、offset、size、name、is_global

4. **String节点** (`nodes_string.csv`)
   - 字符串语义节点
   - 属性：hash、content、encoding

### 🔗 边导出（6种关系）

1. **CONTAINS** (`edges_contains.csv`)
   - 物理归属：Binary包含Function/DataSlot/String

2. **CALLS** (`edges_calls.csv`)
   - 控制流：Function调用Function
   - 属性：call_type（DIRECT/INDIRECT/TAIL）、count

3. **LINKS_TO** (`edges_links_to.csv`)
   - 动态链接：IMPORT Function链接到EXPORT Function

4. **REFERENCES** (`edges_references.csv`)
   - 语义引用：Function引用String

5. **WRITES** (`edges_writes.csv`) ⭐ **核心**
   - 写操作：Function写入DataSlot
   - 属性：op_type（ASSIGN/OR/AND/ADD）、const_val、loc

6. **READS** (`edges_reads.csv`) ⭐ **核心**
   - 读操作：Function读取DataSlot
   - 属性：condition（是否在条件判断中）、op_type（CMP/TEST/MOV）、const_val

### 🛠️ 辅助功能

- ✅ **数据验证**：检查节点ID唯一性、边的起止ID存在性
- 📊 **统计报告**：生成节点数、边数的详细统计
- 🚀 **导入脚本**：自动生成Shell和Batch脚本
- 🔍 **索引脚本**：生成Neo4j索引创建Cypher脚本

## 使用方法

### 基本使用

```python
from exporters.csv_exporter import CSVExporter, NodeIDGenerator

# 1. 初始化导出器
exporter = CSVExporter(
    output_dir='./neo4j_export',
    binary_hash='a1b2c3d4e5f6...'  # 可选
)

# 2. 准备节点数据
binaries = [
    {
        'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'name': 'fw_engine.exe',
        'base_addr': 0x140000000,
        'arch': 'x86_64',
        'compile_ts': 1234567890
    }
]

# 设置ID生成器
exporter.set_binary_hash(binaries[0]['hash'])

functions = [
    {
        'uid': exporter.id_generator.get_function_id(0x1000),
        'rva': 0x1000,
        'name': 'Process_Packet',
        'size': 256,
        'is_lib': False,
        'func_type': 'NORMAL',
        'signature': 'int Process_Packet(void* ctx)',
        'complexity': 5,
        'binary_id': binaries[0]['hash']
    }
]

dataslots = [
    {
        'uid': exporter.id_generator.get_struct_slot_id('SessionEntry', 8),
        'base_type': 'SessionEntry',
        'offset': 8,
        'size': 4,
        'name': 'status',
        'is_global': False
    }
]

strings = [
    {
        'hash': exporter.id_generator.get_string_id('Connection established'),
        'content': 'Connection established',
        'encoding': 'ASCII'
    }
]

# 3. 准备边数据
contains_edges = [
    {
        'from_id': binaries[0]['hash'],
        'to_id': functions[0]['uid'],
        'to_type': 'Function'
    }
]

writes_edges = [
    {
        'from_id': functions[0]['uid'],
        'to_id': dataslots[0]['uid'],
        'op_type': 'ASSIGN',
        'const_val': '0x1',
        'loc': 0x1020
    }
]

reads_edges = [
    {
        'from_id': functions[0]['uid'],
        'to_id': dataslots[0]['uid'],
        'condition': True,
        'op_type': 'CMP',
        'const_val': '0x3'
    }
]

# 4. 执行导出
result = exporter.export_all(
    binaries=binaries,
    functions=functions,
    dataslots=dataslots,
    strings=strings,
    contains_edges=contains_edges,
    calls_edges=[],
    links_to_edges=[],
    references_edges=[],
    writes_edges=writes_edges,
    reads_edges=reads_edges,
    validate=True  # 启用数据验证
)

print(f"Export completed! Output: {result['output_dir']}")
```

### ID生成规则

根据`改造.md`规范，ID生成遵循以下规则：

#### Binary节点
```python
# SHA-256(文件内容)
binary_hash = hashlib.sha256(file_content).hexdigest()
```

#### Function节点
```python
# MD5(BinaryHash + "_" + RVA)
id_gen = NodeIDGenerator(binary_hash=binary_hash)
func_id = id_gen.get_function_id(rva=0x1000)
# 示例：MD5("a1b2c3d4..._1000")
```

#### DataSlot节点

**结构体成员**（跨Binary共享）：
```python
# MD5(StructName + "_" + Offset)
slot_id = id_gen.get_struct_slot_id('SessionEntry', 8)
# 示例：MD5("SessionEntry_8")
```

**全局变量**（Binary私有）：
```python
# MD5(BinaryHash + "_GLOBAL_" + RVA)
slot_id = id_gen.get_global_slot_id(rva=0x5000)
# 示例：MD5("a1b2c3d4..._GLOBAL_5000")
```

#### String节点
```python
# MD5(字符串内容)
string_id = id_gen.get_string_id('Hello World')
# 示例：MD5("Hello World")
```

## 导出流程

### 1. 数据导出

```bash
python your_script.py  # 运行你的导出脚本
```

输出目录结构：
```
neo4j_export/
├── nodes/
│   ├── nodes_binary.csv
│   ├── nodes_function.csv
│   ├── nodes_dataslot.csv
│   └── nodes_string.csv
├── edges/
│   ├── edges_contains.csv
│   ├── edges_calls.csv
│   ├── edges_links_to.csv
│   ├── edges_references.csv
│   ├── edges_writes.csv
│   └── edges_reads.csv
├── import_to_neo4j.sh      # Linux/Mac导入脚本
├── import_to_neo4j.bat     # Windows导入脚本
├── create_indexes.cypher   # 索引创建脚本
└── export_stats.txt        # 统计报告
```

### 2. 导入到Neo4j

#### Linux/Mac:
```bash
# 1. 编辑脚本，设置NEO4J_HOME
vim import_to_neo4j.sh

# 2. 停止Neo4j服务
sudo systemctl stop neo4j

# 3. 运行导入脚本
chmod +x import_to_neo4j.sh
./import_to_neo4j.sh

# 4. 启动Neo4j服务
sudo systemctl start neo4j
```

#### Windows:
```batch
# 1. 编辑脚本，设置NEO4J_HOME
notepad import_to_neo4j.bat

# 2. 停止Neo4j服务（管理员权限）
net stop neo4j

# 3. 运行导入脚本
import_to_neo4j.bat

# 4. 启动Neo4j服务
net start neo4j
```

### 3. 创建索引

在Neo4j Browser中执行：
```cypher
// 拷贝create_indexes.cypher的内容并执行
// 或使用cypher-shell
cat create_indexes.cypher | cypher-shell -d ida-graphy
```

## CSV格式规范

### 节点CSV Header格式

```csv
uid:ID(Label), property:type, ..., :LABEL
```

示例（Function节点）：
```csv
uid:ID(Function),rva:long,name:string,is_lib:boolean,:LABEL
5d41402abc4b2a76b9719d911017c592,4096,Process_Packet,false,Function
```

### 边CSV Header格式

```csv
:START_ID(Label), :END_ID(Label), property:type, ..., :TYPE
```

示例（WRITES边）：
```csv
:START_ID(Function),:END_ID(DataSlot),op_type:string,const_val:string,:TYPE
5d41402abc4b2a76b9719d911017c592,7d793037a0760186574b0282f2f435e7,ASSIGN,0x1,WRITES
```

### 数据类型映射

| Neo4j类型 | Python类型 | 说明 |
|-----------|-----------|------|
| `string` | `str` | 字符串 |
| `int` | `int` | 整数（32位） |
| `long` | `int` | 长整数（64位） |
| `boolean` | `bool` | 布尔值（必须小写：true/false） |

## 数据验证

导出器内置数据验证功能，检查：

1. **节点ID唯一性**
   - 自动通过Set数据结构保证

2. **边的引用完整性**
   - CONTAINS边：起始Binary ID和结束节点ID必须存在
   - CALLS边：起始和结束Function ID必须存在
   - WRITES/READS边：Function ID和DataSlot ID必须存在

验证错误会记录到`export_stats.txt`中。

## 性能优化建议

1. **CSV分块写入**
   - 对于大规模数据，建议分批次写入CSV
   - 每10万行刷新一次缓冲区

2. **Neo4j导入优化**
   ```bash
   # 增加JVM内存
   export JAVA_OPTS="-Xmx8G -Xms8G"
   
   # 使用SSD存储
   # 调整neo4j.conf中的dbms.memory参数
   ```

3. **索引策略**
   - 先导入数据，后创建索引
   - 高频查询字段优先创建索引
   - 使用复合索引加速多条件查询

## 常见查询示例

### 查询函数调用链
```cypher
// 查找调用深度为3的调用链
MATCH path = (f1:Function)-[:CALLS*3]->(f4:Function)
WHERE f1.name = 'main'
RETURN path
LIMIT 10;
```

### 查询写入特定结构体成员的函数
```cypher
// 查找所有写入SessionEntry.status的函数
MATCH (f:Function)-[w:WRITES]->(d:DataSlot)
WHERE d.base_type = 'SessionEntry' AND d.offset = 8
RETURN f.name, w.op_type, w.const_val, w.loc
ORDER BY f.name;
```

### 查询条件判断中的读操作
```cypher
// 查找在条件判断中读取DataSlot的函数（控制流依赖）
MATCH (f:Function)-[r:READS]->(d:DataSlot)
WHERE r.condition = true
RETURN f.name, d.name, r.op_type, r.const_val
ORDER BY f.name;
```

### 跨Binary关联分析
```cypher
// 查找通过动态链接连接的函数对
MATCH (b1:Binary)-[:CONTAINS]->(f1:Function)-[:LINKS_TO]->(f2:Function)<-[:CONTAINS]-(b2:Binary)
RETURN b1.name AS import_binary, f1.name AS import_func, 
       b2.name AS export_binary, f2.name AS export_func
LIMIT 20;
```

## 问题排查

### 导入失败
1. 检查CSV文件编码（必须是UTF-8）
2. 检查CSV分隔符（必须是逗号）
3. 检查Boolean值格式（必须是小写true/false）
4. 查看neo4j-admin输出的错误日志

### 性能问题
1. 确保已创建必要的索引
2. 增大Neo4j JVM内存配置
3. 使用PROFILE分析慢查询
4. 考虑添加更多复合索引

### 数据不一致
1. 运行`validate=True`进行完整性检查
2. 查看`export_stats.txt`中的错误信息
3. 检查ID生成规则是否正确

## 扩展开发

### 添加新的节点类型

```python
def _export_custom_nodes(self, nodes: List[Dict]) -> str:
    filepath = os.path.join(self.output_dir, 'nodes', 'nodes_custom.csv')
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(['uid:ID(CustomNode)', 'property:string', ':LABEL'])
        
        for node in nodes:
            writer.writerow([node['uid'], node['property'], 'CustomNode'])
            self.stats['nodes']['CustomNode'] = self.stats['nodes'].get('CustomNode', 0) + 1
    
    return filepath
```

### 添加新的边类型

```python
def _export_custom_edges(self, edges: List[Dict]) -> str:
    filepath = os.path.join(self.output_dir, 'edges', 'edges_custom.csv')
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
        writer.writerow([':START_ID(Node1)', ':END_ID(Node2)', 'weight:float', ':TYPE'])
        
        for edge in edges:
            writer.writerow([edge['from_id'], edge['to_id'], edge['weight'], 'CUSTOM_RELATION'])
            self.stats['edges']['CUSTOM_RELATION'] = self.stats['edges'].get('CUSTOM_RELATION', 0) + 1
    
    return filepath
```

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！

## 联系方式

- 项目：IDA-Graphy
- 文档：改造.md
