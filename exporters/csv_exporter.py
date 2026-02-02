"""
CSV Exporter for Neo4j
======================
将图数据导出为Neo4j兼容的CSV文件，支持使用neo4j-admin import进行批量导入。

作者：IDA-Graphy Project
日期：2026-02-01
"""

import os
import csv
import hashlib
from typing import Dict, List, Set, Any, Tuple


class NodeIDGenerator:
    """节点ID生成器，遵循改造.md中定义的哈希规则"""
    
    def __init__(self, binary_content=None, binary_hash=None):
        """
        初始化ID生成器
        
        Args:
            binary_content: 二进制文件内容（bytes）
            binary_hash: 已计算的Binary SHA256哈希值
        """
        if binary_hash:
            self.binary_hash = binary_hash
        elif binary_content:
            self.binary_hash = hashlib.sha256(binary_content).hexdigest()
        else:
            raise ValueError("Must provide binary_content or binary_hash")
    
    def _md5(self, s: str) -> str:
        """计算MD5哈希"""
        return hashlib.md5(s.encode('utf-8')).hexdigest()
    
    def get_binary_id(self) -> str:
        """获取Binary节点ID (SHA256)"""
        return self.binary_hash
    
    def get_function_id(self, rva: int) -> str:
        """
        获取Function节点ID
        Scope: Binary私有
        Input: BinaryHash + RVA
        """
        rva_str = hex(rva)[2:].lower()
        return self._md5(f"{self.binary_hash}_{rva_str}")
    
    def get_struct_slot_id(self, struct_name: str, offset: int) -> str:
        """
        获取结构体DataSlot ID
        Scope: 全局通用（跨Binary）
        Input: StructName + Offset
        """
        return self._md5(f"{struct_name}_{int(offset)}")
    
    def get_global_slot_id(self, rva: int) -> str:
        """
        获取全局变量DataSlot ID
        Scope: Binary私有
        Input: BinaryHash + GLOBAL + RVA
        """
        rva_str = hex(rva)[2:].lower()
        return self._md5(f"{self.binary_hash}_GLOBAL_{rva_str}")
    
    def get_string_id(self, content: str) -> str:
        """获取String节点ID"""
        return self._md5(content)


class CSVExporter:
    """
    Neo4j兼容的CSV导出器
    
    导出格式符合neo4j-admin import工具的要求：
    - 节点CSV: ID列使用:ID(Label)格式
    - 边CSV: 使用:START_ID(Label)和:END_ID(Label)
    - 属性列使用:type格式指定数据类型
    """
    
    def __init__(self, output_dir: str, binary_hash: str = None):
        """
        初始化CSV导出器
        
        Args:
            output_dir: 输出目录路径
            binary_hash: Binary的SHA256哈希值（可选）
        """
        self.output_dir = output_dir
        self.binary_hash = binary_hash
        self.id_generator = None
        
        # 数据验证集合
        self.binary_ids: Set[str] = set()
        self.function_ids: Set[str] = set()
        self.dataslot_ids: Set[str] = set()
        self.string_ids: Set[str] = set()
        
        # 统计信息
        self.stats = {
            'nodes': {'Binary': 0, 'Function': 0, 'DataSlot': 0, 'String': 0},
            'edges': {'CONTAINS': 0, 'CALLS': 0, 'LINKS_TO': 0, 'REFERENCES': 0, 'WRITES': 0, 'READS': 0},
            'errors': []
        }
        
        # 确保输出目录存在
        self._ensure_directory()
    
    def _ensure_directory(self):
        """确保输出目录存在"""
        os.makedirs(self.output_dir, exist_ok=True)
        nodes_dir = os.path.join(self.output_dir, 'nodes')
        edges_dir = os.path.join(self.output_dir, 'edges')
        os.makedirs(nodes_dir, exist_ok=True)
        os.makedirs(edges_dir, exist_ok=True)
    
    def set_binary_hash(self, binary_hash: str):
        """设置当前Binary的哈希值"""
        self.binary_hash = binary_hash
        self.id_generator = NodeIDGenerator(binary_hash=binary_hash)
    
    def _escape_csv_value(self, value: Any) -> str:
        """
        转义CSV特殊字符
        
        Args:
            value: 要转义的值
            
        Returns:
            转义后的字符串
        """
        if value is None:
            return ''
        
        # 转换为字符串
        s = str(value)
        
        # 处理换行符和回车符
        s = s.replace('\n', '\\n').replace('\r', '\\r')
        
        # 处理反斜杠
        s = s.replace('\\', '\\\\')
        
        return s
    
    # ========================== 节点导出方法 ==========================
    
    def _export_binary_nodes(self, binaries: List[Dict[str, Any]]) -> str:
        """
        导出Binary节点
        
        Args:
            binaries: Binary节点列表，每个元素包含：
                - hash: Binary哈希（主键）
                - name: 文件名
                - base_addr: 加载基址
                - arch: 架构
                - compile_ts: 编译时间戳
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'nodes', 'nodes_binary.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header (Neo4j格式)
            writer.writerow([
                'hash:ID(Binary)',
                'name:string',
                'base_addr:long',
                'arch:string',
                'compile_ts:long',
                ':LABEL'
            ])
            
            for binary in binaries:
                writer.writerow([
                    binary['hash'],
                    self._escape_csv_value(binary.get('name', '')),
                    binary.get('base_addr', 0),
                    self._escape_csv_value(binary.get('arch', '')),
                    binary.get('compile_ts', 0),
                    'Binary'
                ])
                
                # 记录ID用于验证
                self.binary_ids.add(binary['hash'])
                self.stats['nodes']['Binary'] += 1
        
        return filepath
    
    def _export_function_nodes(self, functions: List[Dict[str, Any]]) -> str:
        """
        导出Function节点
        
        Args:
            functions: Function节点列表，每个元素包含：
                - uid: 函数唯一ID（主键）
                - rva: 相对虚拟地址
                - name: 函数名
                - size: 函数大小
                - is_lib: 是否为库函数
                - func_type: 函数类型（NORMAL/IMPORT/EXPORT/THUNK）
                - signature: 函数签名
                - complexity: 圈复杂度
                - binary_id: 所属Binary的hash（冗余优化）
                - decompiled_file: 反编译代码文件相对路径
                - pseudocode_hash: 伪代码哈希值
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'nodes', 'nodes_function.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                'uid:ID(Function)',
                'rva:long',
                'name:string',
                'size:int',
                'is_lib:boolean',
                'func_type:string',
                'signature:string',
                'complexity:int',
                'binary_id:string',
                'decompiled_file:string',  # File export integration
                'pseudocode_hash:string',  # File export integration
                ':LABEL'
            ])
            
            for func in functions:
                writer.writerow([
                    func['uid'],
                    func.get('rva', 0),
                    self._escape_csv_value(func.get('name', '')),
                    func.get('size', 0),
                    str(func.get('is_lib', False)).lower(),  # boolean必须小写
                    self._escape_csv_value(func.get('func_type', 'NORMAL')),
                    self._escape_csv_value(func.get('signature', '')),
                    func.get('complexity', 0),
                    self._escape_csv_value(func.get('binary_id', '')),
                    self._escape_csv_value(func.get('decompiled_file', '')),
                    self._escape_csv_value(func.get('pseudocode_hash', '')),
                    'Function'
                ])
                
                # 记录ID
                self.function_ids.add(func['uid'])
                self.stats['nodes']['Function'] += 1
        
        return filepath
    
    def _export_dataslot_nodes(self, dataslots: List[Dict[str, Any]]) -> str:
        """
        导出DataSlot节点
        
        Args:
            dataslots: DataSlot节点列表，每个元素包含：
                - uid: DataSlot唯一ID（主键）
                - base_type: 结构体名或'GLOBAL'
                - offset: 扁平化的绝对偏移量
                - size: 数据宽度
                - name: 可读名称
                - is_global: 是否为全局变量
                - struct_file: 结构体定义文件相对路径
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'nodes', 'nodes_dataslot.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                'uid:ID(DataSlot)',
                'base_type:string',
                'offset:int',
                'size:int',
                'name:string',
                'is_global:boolean',
                'struct_file:string',  # File export integration
                ':LABEL'
            ])
            
            for slot in dataslots:
                writer.writerow([
                    slot['uid'],
                    self._escape_csv_value(slot.get('base_type', '')),
                    slot.get('offset', 0),
                    slot.get('size', 0),
                    self._escape_csv_value(slot.get('name', '')),
                    str(slot.get('is_global', False)).lower(),
                    self._escape_csv_value(slot.get('struct_file', '')),
                    'DataSlot'
                ])
                
                # 记录ID
                self.dataslot_ids.add(slot['uid'])
                self.stats['nodes']['DataSlot'] += 1
        
        return filepath
    
    def _export_string_nodes(self, strings: List[Dict[str, Any]]) -> str:
        """
        导出String节点
        
        Args:
            strings: String节点列表，每个元素包含：
                - hash: String哈希（主键）
                - content: 字符串内容
                - encoding: 编码类型（ASCII/UTF-16等）
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'nodes', 'nodes_string.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                'hash:ID(String)',
                'content:string',
                'encoding:string',
                ':LABEL'
            ])
            
            for string in strings:
                writer.writerow([
                    string['hash'],
                    self._escape_csv_value(string.get('content', '')),
                    self._escape_csv_value(string.get('encoding', 'ASCII')),
                    'String'
                ])
                
                # 记录ID
                self.string_ids.add(string['hash'])
                self.stats['nodes']['String'] += 1
        
        return filepath
    
    # ========================== 边导出方法 ==========================
    
    def _export_contains_edges(self, edges: List[Dict[str, Any]]) -> str:
        """
        导出CONTAINS边（物理归属关系）
        
        Args:
            edges: 边列表，每个元素包含：
                - from_id: 起始节点ID（Binary）
                - to_id: 目标节点ID（Function/DataSlot/String）
                - to_type: 目标节点类型
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'edges', 'edges_contains.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                ':START_ID(Binary)',
                ':END_ID',
                ':TYPE'
            ])
            
            for edge in edges:
                writer.writerow([
                    edge['from_id'],
                    edge['to_id'],
                    'CONTAINS'
                ])
                
                self.stats['edges']['CONTAINS'] += 1
        
        return filepath
    
    def _export_calls_edges(self, edges: List[Dict[str, Any]]) -> str:
        """
        导出CALLS边（控制流调用）
        
        Args:
            edges: 边列表，每个元素包含：
                - from_id: 调用者Function ID
                - to_id: 被调用Function ID
                - call_type: 调用类型（DIRECT/INDIRECT/TAIL）
                - count: 调用次数
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'edges', 'edges_calls.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                ':START_ID(Function)',
                ':END_ID(Function)',
                'call_type:string',
                'count:int',
                ':TYPE'
            ])
            
            for edge in edges:
                writer.writerow([
                    edge['from_id'],
                    edge['to_id'],
                    self._escape_csv_value(edge.get('call_type', 'DIRECT')),
                    edge.get('count', 1),
                    'CALLS'
                ])
                
                self.stats['edges']['CALLS'] += 1
        
        return filepath
    
    def _export_links_to_edges(self, edges: List[Dict[str, Any]]) -> str:
        """
        导出LINKS_TO边（动态链接）
        
        Args:
            edges: 边列表，每个元素包含：
                - from_id: IMPORT Function ID
                - to_id: EXPORT Function ID (or virtual external ID)
                - dll_name: DLL name (optional, for debugging)
                - func_name: Function name (optional, for debugging)
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'edges', 'edges_links_to.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header - 添加dll_name和func_name字段用于调试
            writer.writerow([
                ':START_ID(Function)',
                ':END_ID(Function)',
                'dll_name:string',
                'func_name:string',
                ':TYPE'
            ])
            
            for edge in edges:
                writer.writerow([
                    edge['from_id'],
                    edge['to_id'],
                    self._escape_csv_value(edge.get('dll_name', '')),
                    self._escape_csv_value(edge.get('func_name', '')),
                    'LINKS_TO'
                ])
                
                self.stats['edges']['LINKS_TO'] += 1
        
        return filepath
    
    def _export_references_edges(self, edges: List[Dict[str, Any]]) -> str:
        """
        导出REFERENCES边（语义引用）
        
        Args:
            edges: 边列表，每个元素包含：
                - from_id: Function ID
                - to_id: String ID
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'edges', 'edges_references.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                ':START_ID(Function)',
                ':END_ID(String)',
                ':TYPE'
            ])
            
            for edge in edges:
                writer.writerow([
                    edge['from_id'],
                    edge['to_id'],
                    'REFERENCES'
                ])
                
                self.stats['edges']['REFERENCES'] += 1
        
        return filepath
    
    def _export_writes_edges(self, edges: List[Dict[str, Any]]) -> str:
        """
        导出WRITES边（核心业务流：写操作）
        
        这是最关键的边类型之一，记录函数对状态的修改。
        
        Args:
            edges: 边列表，每个元素包含：
                - from_id: Function ID
                - to_id: DataSlot ID
                - op_type: 操作类型（ASSIGN/OR/AND/ADD）
                - const_val: 写入的常量值
                - loc: 操作发生的指令RVA
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'edges', 'edges_writes.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                ':START_ID(Function)',
                ':END_ID(DataSlot)',
                'op_type:string',
                'const_val:string',
                'loc:long',
                ':TYPE'
            ])
            
            for edge in edges:
                writer.writerow([
                    edge['from_id'],
                    edge['to_id'],
                    self._escape_csv_value(edge.get('op_type', 'ASSIGN')),
                    self._escape_csv_value(edge.get('const_val', '')),
                    edge.get('loc', 0),
                    'WRITES'
                ])
                
                self.stats['edges']['WRITES'] += 1
        
        return filepath
    
    def _export_reads_edges(self, edges: List[Dict[str, Any]]) -> str:
        """
        导出READS边（核心业务流：读操作）
        
        这是最关键的边类型之一，记录函数对状态的使用。
        
        Args:
            edges: 边列表，每个元素包含：
                - from_id: Function ID
                - to_id: DataSlot ID
                - condition: 是否在条件判断中（控制流依赖）
                - op_type: 操作类型（CMP/TEST/MOV）
                - const_val: 比较的常量值
                - loc: 指令RVA
        
        Returns:
            生成的CSV文件路径
        """
        filepath = os.path.join(self.output_dir, 'edges', 'edges_reads.csv')
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
            
            # CSV Header
            writer.writerow([
                ':START_ID(Function)',
                ':END_ID(DataSlot)',
                'condition:boolean',
                'op_type:string',
                'const_val:string',
                'loc:long',
                ':TYPE'
            ])
            
            for edge in edges:
                writer.writerow([
                    edge['from_id'],
                    edge['to_id'],
                    str(edge.get('condition', False)).lower(),
                    self._escape_csv_value(edge.get('op_type', 'MOV')),
                    self._escape_csv_value(edge.get('const_val', '')),
                    edge.get('loc', 0),
                    'READS'
                ])
                
                self.stats['edges']['READS'] += 1
        
        return filepath
    
    # ========================== 脚本生成方法 ==========================
    
    def _generate_import_script(self) -> Tuple[str, str]:
        """
        生成Neo4j导入脚本（支持Windows和Linux）
        
        Returns:
            (sh_path, bat_path): Shell脚本和批处理脚本的路径
        """
        # Linux/Mac Shell脚本
        sh_path = os.path.join(self.output_dir, 'import_to_neo4j.sh')
        
        sh_content = """#!/bin/bash
# Neo4j CSV导入脚本
# 使用neo4j-admin import工具进行批量导入
# 
# 使用方法：
# 1. 停止Neo4j服务
# 2. 备份现有数据库（可选）
# 3. 运行此脚本
# 4. 启动Neo4j服务

# ============ 配置区 ============
NEO4J_HOME="/path/to/neo4j"  # 修改为你的Neo4j安装路径
DATABASE_NAME="ida-graphy"   # 数据库名称
CSV_DIR="$(cd "$(dirname "$0")" && pwd)"  # CSV文件目录

# ============ 导入命令 ============
echo "[*] Starting Neo4j Import..."
echo "[*] CSV Directory: $CSV_DIR"
echo "[*] Database Name: $DATABASE_NAME"
echo ""

$NEO4J_HOME/bin/neo4j-admin database import full \\
  --nodes=Binary="$CSV_DIR/nodes/nodes_binary.csv" \\
  --nodes=Function="$CSV_DIR/nodes/nodes_function.csv" \\
  --nodes=DataSlot="$CSV_DIR/nodes/nodes_dataslot.csv" \\
  --nodes=String="$CSV_DIR/nodes/nodes_string.csv" \\
  --relationships=CONTAINS="$CSV_DIR/edges/edges_contains.csv" \\
  --relationships=CALLS="$CSV_DIR/edges/edges_calls.csv" \\
  --relationships=LINKS_TO="$CSV_DIR/edges/edges_links_to.csv" \\
  --relationships=REFERENCES="$CSV_DIR/edges/edges_references.csv" \\
  --relationships=WRITES="$CSV_DIR/edges/edges_writes.csv" \\
  --relationships=READS="$CSV_DIR/edges/edges_reads.csv" \\
  --delimiter=',' \\
  --array-delimiter='|' \\
  --quote='"' \\
  --force \\
  $DATABASE_NAME

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Import completed successfully!"
    echo "[*] Next steps:"
    echo "    1. Start Neo4j: $NEO4J_HOME/bin/neo4j start"
    echo "    2. Create indexes: cat create_indexes.cypher | $NEO4J_HOME/bin/cypher-shell -d $DATABASE_NAME"
else
    echo ""
    echo "[!] Import failed! Check the error messages above."
    exit 1
fi
"""
        
        with open(sh_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(sh_content)
        
        # Windows批处理脚本
        bat_path = os.path.join(self.output_dir, 'import_to_neo4j.bat')
        
        bat_content = """@echo off
REM Neo4j CSV导入脚本（Windows）
REM 使用neo4j-admin import工具进行批量导入
REM 
REM 使用方法：
REM 1. 停止Neo4j服务
REM 2. 备份现有数据库（可选）
REM 3. 运行此脚本
REM 4. 启动Neo4j服务

REM ============ 配置区 ============
SET NEO4J_HOME=C:\\Neo4j\\neo4j-community-5.x
SET DATABASE_NAME=ida-graphy
SET CSV_DIR=%~dp0

REM ============ 导入命令 ============
echo [*] Starting Neo4j Import...
echo [*] CSV Directory: %CSV_DIR%
echo [*] Database Name: %DATABASE_NAME%
echo.

"%NEO4J_HOME%\\bin\\neo4j-admin.bat" database import full ^
  --nodes=Binary="%CSV_DIR%nodes\\nodes_binary.csv" ^
  --nodes=Function="%CSV_DIR%nodes\\nodes_function.csv" ^
  --nodes=DataSlot="%CSV_DIR%nodes\\nodes_dataslot.csv" ^
  --nodes=String="%CSV_DIR%nodes\\nodes_string.csv" ^
  --relationships=CONTAINS="%CSV_DIR%edges\\edges_contains.csv" ^
  --relationships=CALLS="%CSV_DIR%edges\\edges_calls.csv" ^
  --relationships=LINKS_TO="%CSV_DIR%edges\\edges_links_to.csv" ^
  --relationships=REFERENCES="%CSV_DIR%edges\\edges_references.csv" ^
  --relationships=WRITES="%CSV_DIR%edges\\edges_writes.csv" ^
  --relationships=READS="%CSV_DIR%edges\\edges_reads.csv" ^
  --delimiter="," ^
  --array-delimiter="|" ^
  --quote="\\"" ^
  --force ^
  %DATABASE_NAME%

IF %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Import completed successfully!
    echo [*] Next steps:
    echo     1. Start Neo4j service
    echo     2. Run create_indexes.cypher to create indexes
) ELSE (
    echo.
    echo [!] Import failed! Check the error messages above.
    exit /b 1
)

pause
"""
        
        with open(bat_path, 'w', encoding='utf-8', newline='\r\n') as f:
            f.write(bat_content)
        
        return sh_path, bat_path
    
    def _generate_index_script(self) -> str:
        """
        生成Neo4j索引创建脚本
        
        Returns:
            Cypher脚本的路径
        """
        cypher_path = os.path.join(self.output_dir, 'create_indexes.cypher')
        
        cypher_content = """// Neo4j索引创建脚本
// 为关键属性创建索引以优化查询性能
// 
// 使用方法（在Neo4j Browser中执行或使用cypher-shell）：
// cat create_indexes.cypher | cypher-shell -d ida-graphy

// ============ Binary节点索引 ============
CREATE INDEX binary_hash_idx IF NOT EXISTS FOR (b:Binary) ON (b.hash);
CREATE INDEX binary_name_idx IF NOT EXISTS FOR (b:Binary) ON (b.name);

// ============ Function节点索引 ============
CREATE INDEX function_uid_idx IF NOT EXISTS FOR (f:Function) ON (f.uid);
CREATE INDEX function_name_idx IF NOT EXISTS FOR (f:Function) ON (f.name);
CREATE INDEX function_rva_idx IF NOT EXISTS FOR (f:Function) ON (f.rva);
CREATE INDEX function_binary_idx IF NOT EXISTS FOR (f:Function) ON (f.binary_id);
CREATE INDEX function_type_idx IF NOT EXISTS FOR (f:Function) ON (f.func_type);
CREATE INDEX function_islib_idx IF NOT EXISTS FOR (f:Function) ON (f.is_lib);

// ============ DataSlot节点索引 ============
CREATE INDEX dataslot_uid_idx IF NOT EXISTS FOR (d:DataSlot) ON (d.uid);
CREATE INDEX dataslot_basetype_idx IF NOT EXISTS FOR (d:DataSlot) ON (d.base_type);
CREATE INDEX dataslot_isglobal_idx IF NOT EXISTS FOR (d:DataSlot) ON (d.is_global);

// ============ String节点索引 ============
CREATE INDEX string_hash_idx IF NOT EXISTS FOR (s:String) ON (s.hash);
CREATE INDEX string_content_idx IF NOT EXISTS FOR (s:String) ON (s.content);

// ============ 复合索引（高级查询优化）============
// 查询特定Binary中的非库函数
CREATE INDEX function_binary_islib_idx IF NOT EXISTS FOR (f:Function) ON (f.binary_id, f.is_lib);

// 查询特定结构体的成员
CREATE INDEX dataslot_type_global_idx IF NOT EXISTS FOR (d:DataSlot) ON (d.base_type, d.is_global);

// ============ 全文搜索索引 ============
// 函数名全文搜索
CREATE FULLTEXT INDEX function_name_fulltext IF NOT EXISTS 
FOR (f:Function) ON EACH [f.name];

// 字符串内容全文搜索
CREATE FULLTEXT INDEX string_content_fulltext IF NOT EXISTS 
FOR (s:String) ON EACH [s.content];

// ============ 验证索引创建 ============
SHOW INDEXES;
"""
        
        with open(cypher_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(cypher_content)
        
        return cypher_path
    
    # ========================== 数据验证方法 ==========================
    
    def validate_data(self) -> List[str]:
        """
        验证导出数据的完整性
        
        检查：
        1. 节点ID唯一性
        2. 边的起止节点ID存在性
        
        Returns:
            错误信息列表（如果为空则验证通过）
        """
        errors = []
        
        # 检查节点ID唯一性已通过Set自动保证
        # 这里主要检查边的引用完整性
        
        print("[*] Validating edge references...")
        
        # 检查CONTAINS边
        contains_path = os.path.join(self.output_dir, 'edges', 'edges_contains.csv')
        if os.path.exists(contains_path):
            with open(contains_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    start_id = row[':START_ID(Binary)']
                    end_id = row[':END_ID']
                    
                    if start_id not in self.binary_ids:
                        errors.append(f"CONTAINS edge references non-existent Binary: {start_id}")
                    
                    # END_ID可能是Function/DataSlot/String
                    if (end_id not in self.function_ids and 
                        end_id not in self.dataslot_ids and 
                        end_id not in self.string_ids):
                        errors.append(f"CONTAINS edge references non-existent node: {end_id}")
        
        # 检查CALLS边
        calls_path = os.path.join(self.output_dir, 'edges', 'edges_calls.csv')
        if os.path.exists(calls_path):
            with open(calls_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    start_id = row[':START_ID(Function)']
                    end_id = row[':END_ID(Function)']
                    
                    if start_id not in self.function_ids:
                        errors.append(f"CALLS edge references non-existent Function: {start_id}")
                    if end_id not in self.function_ids:
                        errors.append(f"CALLS edge references non-existent Function: {end_id}")
        
        # 检查WRITES边
        writes_path = os.path.join(self.output_dir, 'edges', 'edges_writes.csv')
        if os.path.exists(writes_path):
            with open(writes_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    start_id = row[':START_ID(Function)']
                    end_id = row[':END_ID(DataSlot)']
                    
                    if start_id not in self.function_ids:
                        errors.append(f"WRITES edge references non-existent Function: {start_id}")
                    if end_id not in self.dataslot_ids:
                        errors.append(f"WRITES edge references non-existent DataSlot: {end_id}")
        
        # 检查READS边
        reads_path = os.path.join(self.output_dir, 'edges', 'edges_reads.csv')
        if os.path.exists(reads_path):
            with open(reads_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    start_id = row[':START_ID(Function)']
                    end_id = row[':END_ID(DataSlot)']
                    
                    if start_id not in self.function_ids:
                        errors.append(f"READS edge references non-existent Function: {start_id}")
                    if end_id not in self.dataslot_ids:
                        errors.append(f"READS edge references non-existent DataSlot: {end_id}")
        
        return errors
    
    def generate_stats_report(self) -> str:
        """
        生成统计报告
        
        Returns:
            统计报告的文件路径
        """
        report_path = os.path.join(self.output_dir, 'export_stats.txt')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("Neo4j CSV Export Statistics\n")
            f.write("=" * 60 + "\n\n")
            
            # 节点统计
            f.write("Nodes:\n")
            f.write("-" * 40 + "\n")
            for node_type, count in self.stats['nodes'].items():
                f.write(f"  {node_type:15s}: {count:>10,}\n")
            total_nodes = sum(self.stats['nodes'].values())
            f.write(f"  {'Total':15s}: {total_nodes:>10,}\n\n")
            
            # 边统计
            f.write("Edges:\n")
            f.write("-" * 40 + "\n")
            for edge_type, count in self.stats['edges'].items():
                f.write(f"  {edge_type:15s}: {count:>10,}\n")
            total_edges = sum(self.stats['edges'].values())
            f.write(f"  {'Total':15s}: {total_edges:>10,}\n\n")
            
            # 总计
            f.write("=" * 40 + "\n")
            f.write(f"Grand Total: {total_nodes + total_edges:,} records\n")
            f.write("=" * 40 + "\n\n")
            
            # 错误信息
            if self.stats['errors']:
                f.write("\nErrors:\n")
                f.write("-" * 40 + "\n")
                for error in self.stats['errors']:
                    f.write(f"  - {error}\n")
        
        return report_path
    
    # ========================== 主导出方法 ==========================
    
    def export_all(self, 
                   binaries: List[Dict], 
                   functions: List[Dict],
                   dataslots: List[Dict],
                   strings: List[Dict],
                   contains_edges: List[Dict],
                   calls_edges: List[Dict],
                   links_to_edges: List[Dict],
                   references_edges: List[Dict],
                   writes_edges: List[Dict],
                   reads_edges: List[Dict],
                   validate: bool = True) -> Dict[str, Any]:
        """
        导出所有节点和边到CSV文件
        
        Args:
            binaries: Binary节点列表
            functions: Function节点列表
            dataslots: DataSlot节点列表
            strings: String节点列表
            contains_edges: CONTAINS边列表
            calls_edges: CALLS边列表
            links_to_edges: LINKS_TO边列表
            references_edges: REFERENCES边列表
            writes_edges: WRITES边列表
            reads_edges: READS边列表
            validate: 是否进行数据验证
        
        Returns:
            导出结果字典，包含文件路径和统计信息
        """
        print("=" * 60)
        print("Neo4j CSV Exporter")
        print("=" * 60)
        print()
        
        # 导出节点
        print("[1/4] Exporting nodes...")
        node_files = {
            'binary': self._export_binary_nodes(binaries),
            'function': self._export_function_nodes(functions),
            'dataslot': self._export_dataslot_nodes(dataslots),
            'string': self._export_string_nodes(strings)
        }
        print(f"  + Binary nodes: {self.stats['nodes']['Binary']}")
        print(f"  + Function nodes: {self.stats['nodes']['Function']}")
        print(f"  + DataSlot nodes: {self.stats['nodes']['DataSlot']}")
        print(f"  + String nodes: {self.stats['nodes']['String']}")
        print()
        
        # 导出边
        print("[2/4] Exporting edges...")
        edge_files = {
            'contains': self._export_contains_edges(contains_edges),
            'calls': self._export_calls_edges(calls_edges),
            'links_to': self._export_links_to_edges(links_to_edges),
            'references': self._export_references_edges(references_edges),
            'writes': self._export_writes_edges(writes_edges),
            'reads': self._export_reads_edges(reads_edges)
        }
        print(f"  + CONTAINS edges: {self.stats['edges']['CONTAINS']}")
        print(f"  + CALLS edges: {self.stats['edges']['CALLS']}")
        print(f"  + LINKS_TO edges: {self.stats['edges']['LINKS_TO']}")
        print(f"  + REFERENCES edges: {self.stats['edges']['REFERENCES']}")
        print(f"  + WRITES edges: {self.stats['edges']['WRITES']}")
        print(f"  + READS edges: {self.stats['edges']['READS']}")
        print()
        
        # 生成导入脚本
        print("[3/4] Generating import scripts...")
        sh_path, bat_path = self._generate_import_script()
        cypher_path = self._generate_index_script()
        print(f"  + Shell script: {os.path.basename(sh_path)}")
        print(f"  + Batch script: {os.path.basename(bat_path)}")
        print(f"  + Index script: {os.path.basename(cypher_path)}")
        print()
        
        # 数据验证
        if validate:
            print("[4/4] Validating data...")
            errors = self.validate_data()
            if errors:
                print(f"  ⚠ Found {len(errors)} validation errors!")
                self.stats['errors'] = errors
                # 前10个错误
                for i, error in enumerate(errors[:10]):
                    print(f"    - {error}")
                if len(errors) > 10:
                    print(f"    ... and {len(errors) - 10} more errors")
            else:
                print("  + Data validation passed!")
        else:
            print("[4/4] Skipping validation...")
        print()
        
        # 生成统计报告
        stats_path = self.generate_stats_report()
        
        print("=" * 60)
        print("Export completed!")
        print("=" * 60)
        print(f"Output directory: {self.output_dir}")
        print(f"Statistics report: {os.path.basename(stats_path)}")
        print()
        print("Next steps:")
        print("1. Review export_stats.txt for summary")
        print("2. Run import_to_neo4j.sh (Linux/Mac) or import_to_neo4j.bat (Windows)")
        print("3. Execute create_indexes.cypher in Neo4j Browser")
        print()
        
        return {
            'output_dir': self.output_dir,
            'node_files': node_files,
            'edge_files': edge_files,
            'import_scripts': {
                'shell': sh_path,
                'batch': bat_path,
                'cypher': cypher_path
            },
            'stats': self.stats,
            'stats_report': stats_path
        }


# ========================== 使用示例 ==========================

def example_usage():
    """使用示例"""
    
    # 1. 初始化导出器
    exporter = CSVExporter(
        output_dir='./neo4j_export',
        binary_hash='a1b2c3d4e5f6...'
    )
    
    # 2. 准备节点数据（示例）
    binaries = [
        {
            'hash': 'a1b2c3d4e5f6...',
            'name': 'fw_engine.exe',
            'base_addr': 0x140000000,
            'arch': 'x86_64',
            'compile_ts': 1234567890
        }
    ]
    
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
            'binary_id': 'a1b2c3d4e5f6...'
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
            'from_id': 'a1b2c3d4e5f6...',
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
        validate=True
    )
    
    print("Export completed!")
    print(f"Output: {result['output_dir']}")


if __name__ == '__main__':
    example_usage()
