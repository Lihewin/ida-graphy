// Neo4j Browser 查询脚本 - 完整项目可视化
// 复制这些查询到Neo4j Browser中逐一执行

// === 第1步：概览项目统计 ===
MATCH (n) RETURN labels(n) as 节点类型, count(n) as 数量;

// === 第2步：查看二进制文件信息 ===
MATCH (b:Binary) RETURN b.name as 文件名, b.arch as 架构, b.base_addr as 基址;

// === 第3步：显示Binary到Function的包含关系（推荐先执行这个）===
MATCH (b:Binary)-[:CONTAINS]->(f:Function) 
RETURN b, f
LIMIT 100;

// === 第4步：显示函数调用网络 ===
MATCH (f1:Function)-[c:CALLS]->(f2:Function)
WHERE f1.binary_id = f2.binary_id  // 同文件内调用
RETURN f1, c, f2 
LIMIT 150;

// === 第5步：显示跨文件调用（如果有）===  
MATCH (f1:Function)-[c:CALLS]->(f2:Function)
WHERE f1.binary_id <> f2.binary_id  // 跨文件调用
RETURN f1, c, f2;

// === 第6步：显示完整的数据生态系统（小心：节点很多）===
MATCH (b:Binary)
MATCH (b)-[:CONTAINS]->(contained)
OPTIONAL MATCH (contained)-[r]-(other)
WHERE other IS NOT NULL
RETURN b, contained, r, other
LIMIT 300;

// === 第7步：查看特定二进制文件的完整结构 ===
MATCH (b:Binary {name: "at.exe"})    // 可以改为 "schedcli.dll"
MATCH (b)-[:CONTAINS]->(content)
OPTIONAL MATCH (content)-[rel]-(connected)
RETURN b, content, rel, connected
LIMIT 200;

// === 第8步：显示字符串引用关系 ===
MATCH (f:Function)-[r:REFERENCES]->(s:String)
RETURN f, r, s
LIMIT 50;

// === 第9步：显示数据读写关系 ===
MATCH (f:Function)-[rw]->(d:DataSlot)
WHERE type(rw) IN ["READS", "WRITES"]
RETURN f, rw, d
LIMIT 50;

// === 第10步：最终完整图（谨慎使用）===
// 注意：这个查询可能返回很多数据，建议先调整Browser设置
MATCH (n)-[r]-(m) 
RETURN n, r, m 
LIMIT 500;