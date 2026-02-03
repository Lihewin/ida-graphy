from neo4j import GraphDatabase

URI = "neo4j://127.0.0.1:7687"
USER = "neo4j"
PASSWORD = "Njupt@241"
DB = "idg-project-reftest"

query_direct = (
    "MATCH (b1:Binary {name:'at.exe'})-[:CONTAINS]->(i:Function {func_type:'IMPORT'})"
    "-[r:LINKS_TO]->(e:Function {func_type:'EXPORT'})<-[:CONTAINS]-(b2:Binary {name:'schedcli.dll'}) "
    "RETURN i.name AS import_name, r.dll_name AS dll, r.func_name AS func, e.name AS export_name "
    "ORDER BY func"
)

query_by_dll = (
    "MATCH (b1:Binary {name:'at.exe'})-[:CONTAINS]->(i:Function {func_type:'IMPORT'})"
    "-[r:LINKS_TO]->(e:Function {func_type:'EXPORT'}) "
    "WHERE toLower(r.dll_name) CONTAINS 'schedcli' "
    "RETURN i.name AS import_name, r.dll_name AS dll, r.func_name AS func, e.name AS export_name "
    "ORDER BY func"
)

query_imports_in_at = (
    "MATCH (b:Binary {name:'at.exe'})-[:CONTAINS]->(f:Function {func_type:'IMPORT'}) "
    "RETURN count(f) AS c"
)

query_exports_in_schedcli = (
    "MATCH (b:Binary {name:'schedcli.dll'})-[:CONTAINS]->(f:Function {func_type:'EXPORT'}) "
    "RETURN count(f) AS c"
)

query_schedcli_links_total = (
    "MATCH ()-[r:LINKS_TO]->() WHERE r.dll_name = 'schedcli' RETURN count(r) AS c"
)

query_schedcli_links_sample = (
    "MATCH ()-[r:LINKS_TO]->(e:Function) WHERE r.dll_name = 'schedcli' "
    "RETURN r.func_name AS func, e.name AS export_name LIMIT 10"
)

query_at_imports = (
    "MATCH (b:Binary {name:'at.exe'})-[:CONTAINS]->(f:Function {func_type:'IMPORT'}) "
    "RETURN f.uid AS uid, f.name AS name"
)

query_schedcli_links = (
    "MATCH (f:Function)-[r:LINKS_TO]->(e:Function) WHERE r.dll_name = 'schedcli' "
    "RETURN f.uid AS uid, f.name AS name, r.func_name AS func"
)

driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))

with driver.session(database=DB) as session:
    row = session.run(query_imports_in_at).single()
    print("at.exe IMPORT count (CONTAINS):", row["c"] if row else 0)

    row = session.run(query_exports_in_schedcli).single()
    print("schedcli.dll EXPORT count (CONTAINS):", row["c"] if row else 0)

    rows = list(session.run(query_direct))
    print("at.exe -> schedcli.dll LINKS_TO (direct binary match):", len(rows))
    for row in rows:
        print(dict(row))

    rows = list(session.run(query_by_dll))
    print("at.exe -> schedcli LINKS_TO (by dll_name):", len(rows))
    for row in rows:
        print(dict(row))

    row = session.run(query_schedcli_links_total).single()
    print("schedcli LINKS_TO total:", row["c"] if row else 0)

    rows = list(session.run(query_schedcli_links_sample))
    print("schedcli LINKS_TO sample:")
    for row in rows:
        print(dict(row))

    at_imports = list(session.run(query_at_imports))
    schedcli_links = list(session.run(query_schedcli_links))

    at_import_uids = {row["uid"] for row in at_imports}
    link_from_uids = {row["uid"] for row in schedcli_links}

    print("at.exe IMPORT uids:", len(at_import_uids))
    print("schedcli LINKS_TO from uids:", len(link_from_uids))
    print("intersection:", len(at_import_uids & link_from_uids))

    print("at.exe IMPORT names:")
    for row in at_imports:
        print(row["name"], row["uid"])

    print("schedcli LINKS_TO from names:")
    for row in schedcli_links:
        print(row["name"], row["uid"], row["func"])

driver.close()
