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
    name_counts = session.run(
        "MATCH (n) WHERE n.orig_name IS NOT NULL RETURN labels(n)[0] as label, count(n) as c"
    ).data()
    empty_orig = session.run(
        "MATCH (n) WHERE n.orig_name IS NULL OR n.orig_name = '' RETURN labels(n)[0] as label, count(n) as c"
    ).data()
    struct_samples = session.run(
        "MATCH (d:DataSlot {is_global:false}) "
        "RETURN d.base_type as base_type, d.base_type_orig as base_type_orig, d.name as name, d.orig_name as orig_name "
        "LIMIT 10"
    ).data()

print("orig_name counts:", name_counts)
print("empty orig_name counts:", empty_orig)
print("struct samples:")
for row in struct_samples:
    print("  ", row)

mgr.close()
