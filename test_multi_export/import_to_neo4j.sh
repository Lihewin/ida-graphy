#!/bin/bash
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

$NEO4J_HOME/bin/neo4j-admin database import full \
  --nodes=Binary="$CSV_DIR/nodes/nodes_binary.csv" \
  --nodes=Function="$CSV_DIR/nodes/nodes_function.csv" \
  --nodes=DataSlot="$CSV_DIR/nodes/nodes_dataslot.csv" \
  --nodes=String="$CSV_DIR/nodes/nodes_string.csv" \
  --relationships=CONTAINS="$CSV_DIR/edges/edges_contains.csv" \
  --relationships=CALLS="$CSV_DIR/edges/edges_calls.csv" \
  --relationships=LINKS_TO="$CSV_DIR/edges/edges_links_to.csv" \
  --relationships=REFERENCES="$CSV_DIR/edges/edges_references.csv" \
  --relationships=WRITES="$CSV_DIR/edges/edges_writes.csv" \
  --relationships=READS="$CSV_DIR/edges/edges_reads.csv" \
  --delimiter=',' \
  --array-delimiter='|' \
  --quote='"' \
  --force \
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
