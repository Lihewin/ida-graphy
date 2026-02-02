// Neo4j索引创建脚本
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
