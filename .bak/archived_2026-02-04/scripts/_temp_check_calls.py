import os
import sys
import yaml

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from core.project.manager import ProjectManager
from database.neo4j_manager import Neo4jManager

cfg = yaml.safe_load(open("config.yaml", "r", encoding="utf-8"))
pm = ProjectManager(cfg["projects"]["root_dir"])
proj = pm.get_project("reftest")
conn = cfg["neo4j"]["connection"]

mgr = Neo4jManager(
    uri=conn["uri"],
    user=conn["user"],
    password=conn["password"],
    max_connection_pool_size=conn.get("max_connection_pool_size", 50),
    connection_timeout=conn.get("connection_timeout", 30.0),
)

db = proj.database_name

with mgr.get_session(db) as session:
    main_nodes = session.run(
        "MATCH (b:Binary {name:'at.exe'})-[:CONTAINS]->(f:Function) "
        "WHERE toLower(f.name) = 'main' RETURN f.uid as uid, f.name as name, f.rva as rva, f.func_type as func_type"
    ).data()

    import_nodes = session.run(
        "MATCH (b:Binary {name:'at.exe'})-[:CONTAINS]->(f:Function) "
        "WHERE toLower(f.name) CONTAINS 'netschedulejobdel' "
        "RETURN f.uid as uid, f.name as name, f.rva as rva, f.func_type as func_type"
    ).data()

    calls = session.run(
        "MATCH (m:Function)-[r:CALLS]->(c:Function) "
        "WHERE toLower(m.name) = 'main' AND toLower(c.name) CONTAINS 'netschedulejobdel' "
        "RETURN m.uid as from_uid, c.uid as to_uid, r.type as type, r.count as count"
    ).data()

    links = session.run(
        "MATCH (i:Function {func_type:'IMPORT'})-[r:LINKS_TO]->(e:Function) "
        "WHERE toLower(r.func_name) = 'netschedulejobdel' "
        "RETURN i.name as import_name, i.uid as import_uid, r.dll_name as dll, r.func_name as func_name, e.uid as export_uid"
    ).data()

print("main nodes:", main_nodes)
print("import nodes (NetScheduleJobDel):", import_nodes)
print("CALLS main -> NetScheduleJobDel:", calls)
print("LINKS_TO for NetScheduleJobDel:", links)

mgr.close()
