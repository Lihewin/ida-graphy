"""Check remaining .dynsym LINKS_TO edges."""
from neo4j import GraphDatabase

driver = GraphDatabase.driver("neo4j://127.0.0.1:7687", auth=("neo4j", "Njupt@241"), database="idg-project-elf-test")
with driver.session() as s:
    r = s.run(
        'MATCH (a)-[l:LINKS_TO]->(b) WHERE l.dll_name = ".dynsym" '
        'RETURN a.name AS imp, b.name AS exp, l.func_name AS fn ORDER BY a.name'
    )
    for rec in r:
        print(f"{rec['imp']:40s} -> {rec['exp']:40s} fn={rec['fn']}")
    print()
    r2 = s.run('MATCH (a)-[l:LINKS_TO]->(b) WHERE l.dll_name = ".dynsym" RETURN count(*) AS cnt')
    print(f"Total remaining .dynsym: {r2.single()['cnt']}")

driver.close()
