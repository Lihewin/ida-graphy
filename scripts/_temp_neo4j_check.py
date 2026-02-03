from neo4j import GraphDatabase

URI = "neo4j://127.0.0.1:7687"
USER = "neo4j"
PASSWORD = "Njupt@241"
DB = "idg-project-reftest"

queries = {
    "links_to_count": "MATCH ()-[r:LINKS_TO]->() RETURN count(r) AS c",
    "import_count": "MATCH (f:Function {func_type:'IMPORT'}) RETURN count(f) AS c",
    "export_count": "MATCH (f:Function {func_type:'EXPORT'}) RETURN count(f) AS c",
    "imports_without_links": "MATCH (f:Function {func_type:'IMPORT'}) WHERE NOT (f)-[:LINKS_TO]->() RETURN count(f) AS c",
    "sample_links": "MATCH (i:Function {func_type:'IMPORT'})-[r:LINKS_TO]->(e:Function) RETURN i.name AS import_name, r.dll_name AS dll, r.func_name AS func, e.name AS export_name LIMIT 10",
    "schedcli_links": "MATCH ()-[r:LINKS_TO]->(e:Function) WHERE toLower(r.dll_name) CONTAINS 'schedcli' RETURN r.dll_name AS dll, r.func_name AS func, e.name AS export_name LIMIT 10",
}

driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))

with driver.session(database=DB) as session:
    for name, q in queries.items():
        print(f"{name}:")
        for row in session.run(q):
            print(dict(row))
        print("-" * 40)

driver.close()
