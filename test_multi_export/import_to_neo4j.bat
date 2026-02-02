@echo off
REM Neo4j CSV导入脚本（Windows）
REM 使用neo4j-admin import工具进行批量导入
REM 
REM 使用方法：
REM 1. 停止Neo4j服务
REM 2. 备份现有数据库（可选）
REM 3. 运行此脚本
REM 4. 启动Neo4j服务

REM ============ 配置区 ============
SET NEO4J_HOME=C:\Neo4j\neo4j-community-5.x
SET DATABASE_NAME=ida-graphy
SET CSV_DIR=%~dp0

REM ============ 导入命令 ============
echo [*] Starting Neo4j Import...
echo [*] CSV Directory: %CSV_DIR%
echo [*] Database Name: %DATABASE_NAME%
echo.

"%NEO4J_HOME%\bin\neo4j-admin.bat" database import full ^
  --nodes=Binary="%CSV_DIR%nodes\nodes_binary.csv" ^
  --nodes=Function="%CSV_DIR%nodes\nodes_function.csv" ^
  --nodes=DataSlot="%CSV_DIR%nodes\nodes_dataslot.csv" ^
  --nodes=String="%CSV_DIR%nodes\nodes_string.csv" ^
  --relationships=CONTAINS="%CSV_DIR%edges\edges_contains.csv" ^
  --relationships=CALLS="%CSV_DIR%edges\edges_calls.csv" ^
  --relationships=LINKS_TO="%CSV_DIR%edges\edges_links_to.csv" ^
  --relationships=REFERENCES="%CSV_DIR%edges\edges_references.csv" ^
  --relationships=WRITES="%CSV_DIR%edges\edges_writes.csv" ^
  --relationships=READS="%CSV_DIR%edges\edges_reads.csv" ^
  --delimiter="," ^
  --array-delimiter="|" ^
  --quote="\"" ^
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
