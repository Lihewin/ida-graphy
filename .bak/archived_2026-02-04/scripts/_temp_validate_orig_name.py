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
    orig_counts = session.run(
        "MATCH (n) WHERE n.orig_name IS NOT NULL RETURN labels(n)[0] as label, count(n) as c"
    ).data()
    thunk_counts = session.run(
        "MATCH (f:Function {func_type:'THUNK'}) RETURN count(f) as c"
    ).single()["c"]
    import_counts = session.run(
        "MATCH (f:Function {func_type:'IMPORT'}) RETURN count(f) as c"
    ).single()["c"]
    call_counts = session.run(
        "MATCH ()-[r:CALLS]->() RETURN count(r) as c"
    ).single()["c"]

print("orig_name counts:", orig_counts)
print("THUNK functions:", thunk_counts)
print("IMPORT functions:", import_counts)
print("CALLS edges:", call_counts)

mgr.close()
