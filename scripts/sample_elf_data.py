"""Data sampling script for elf-test project.

Queries Neo4j to verify data quality, especially:
1. LINKS_TO edges: dll_name should be real library names, not .dynsym
2. DataSlot nodes: struct member vs global variable distribution
3. READS/WRITES edges: check for struct member edges from Hex-Rays
4. Overall graph health
"""

from neo4j import GraphDatabase

URI = "neo4j://127.0.0.1:7687"
USER = "neo4j"
PASSWORD = "Njupt@241"
DB = "idg-project-elf-test"


def run_query(driver, query, db=DB):
    with driver.session(database=db) as session:
        result = session.run(query)
        return [dict(r) for r in result]


def main():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    print("=" * 80)
    print("ELF-TEST PROJECT DATA SAMPLING")
    print("=" * 80)

    # 1. Node counts by label
    print("\n--- 1. Node Counts ---")
    for label in ["Binary", "Function", "DataSlot", "String"]:
        rows = run_query(driver, f"MATCH (n:{label}) RETURN count(n) as cnt")
        print(f"  {label}: {rows[0]['cnt']}")

    # 2. Edge counts by type
    print("\n--- 2. Edge Counts ---")
    rows = run_query(driver, """
        MATCH ()-[r]->()
        RETURN type(r) as rtype, count(r) as cnt
        ORDER BY cnt DESC
    """)
    for r in rows:
        print(f"  {r['rtype']}: {r['cnt']}")

    # 3. Binary overview
    print("\n--- 3. Binary Nodes ---")
    rows = run_query(driver, "MATCH (b:Binary) RETURN b.name as name, b.arch as arch, b.hash as hash")
    for r in rows:
        print(f"  {r['name']} (arch={r['arch']}, hash={r['hash'][:16]}...)")

    # 4. LINKS_TO dll_name distribution (KEY CHECK for ELF fix)
    print("\n--- 4. LINKS_TO dll_name Distribution (ELF CHECK) ---")
    rows = run_query(driver, """
        MATCH ()-[r:LINKS_TO]->()
        RETURN r.dll_name as dll_name, count(r) as cnt
        ORDER BY cnt DESC
        LIMIT 20
    """)
    has_dynsym = False
    for r in rows:
        marker = ""
        if r["dll_name"] and ".dynsym" in str(r["dll_name"]):
            marker = " *** PROBLEM: still .dynsym ***"
            has_dynsym = True
        print(f"  {r['dll_name']}: {r['cnt']}{marker}")
    
    if has_dynsym:
        print("\n  ⚠️  WARNING: .dynsym still appears in LINKS_TO edges!")
    else:
        print("\n  ✅ No .dynsym found in LINKS_TO edges")

    # 5. Sample LINKS_TO edges
    print("\n--- 5. Sample LINKS_TO Edges (10) ---")
    rows = run_query(driver, """
        MATCH (f:Function)-[r:LINKS_TO]->(t)
        RETURN f.name as caller, r.dll_name as dll, r.func_name as func
        LIMIT 10
    """)
    for r in rows:
        print(f"  {r['caller']} --LINKS_TO--> {r['dll']}::{r['func']}")

    # 6. Function type distribution
    print("\n--- 6. Function Types ---")
    rows = run_query(driver, """
        MATCH (f:Function)
        RETURN f.func_type as type, count(f) as cnt
        ORDER BY cnt DESC
    """)
    for r in rows:
        print(f"  {r['type']}: {r['cnt']}")

    # 7. DataSlot distribution (struct vs global)
    print("\n--- 7. DataSlot Distribution ---")
    rows = run_query(driver, """
        MATCH (d:DataSlot)
        RETURN d.is_global as is_global, count(d) as cnt
    """)
    for r in rows:
        label = "Global" if r["is_global"] else "Struct Member"
        print(f"  {label}: {r['cnt']}")

    # 8. READS/WRITES edges - struct vs global
    print("\n--- 8. READS/WRITES Edge Analysis ---")
    for rel_type in ["READS", "WRITES"]:
        rows = run_query(driver, f"""
            MATCH (f:Function)-[r:{rel_type}]->(d:DataSlot)
            RETURN d.is_global as is_global, count(r) as cnt
        """)
        for r in rows:
            target = "global" if r["is_global"] else "struct member"
            print(f"  {rel_type} -> {target}: {r['cnt']}")

    # 9. Sample struct member READS/WRITES (Hex-Rays dataflow check)
    print("\n--- 9. Sample Struct Member READS (Hex-Rays) ---")
    rows = run_query(driver, """
        MATCH (f:Function)-[r:READS]->(d:DataSlot {is_global: false})
        RETURN f.name as func, d.base_type as struct, d.name as member,
               d.offset as offset, r.op_type as op, r.const_val as const
        LIMIT 10
    """)
    for r in rows:
        print(f"  {r['func']} READS {r['struct']}.{r['member']}(+{r['offset']}) op={r['op']} const={r['const']}")

    print("\n--- 10. Sample Struct Member WRITES (Hex-Rays) ---")
    rows = run_query(driver, """
        MATCH (f:Function)-[r:WRITES]->(d:DataSlot {is_global: false})
        RETURN f.name as func, d.base_type as struct, d.name as member,
               d.offset as offset, r.op_type as op, r.const_val as const
        LIMIT 10
    """)
    for r in rows:
        print(f"  {r['func']} WRITES {r['struct']}.{r['member']}(+{r['offset']}) op={r['op']} const={r['const']}")

    # 10. String references sample
    print("\n--- 11. Sample String References ---")
    rows = run_query(driver, """
        MATCH (f:Function)-[:REFERENCES]->(s:String)
        RETURN f.name as func, s.content as str
        LIMIT 10
    """)
    for r in rows:
        content = r["str"][:60] + "..." if len(r["str"]) > 60 else r["str"]
        print(f"  {r['func']} -> \"{content}\"")

    # 11. Cross-binary symbol resolution check
    print("\n--- 12. Cross-Binary Symbol Resolution ---")
    rows = run_query(driver, """
        MATCH (f:Function)-[r:LINKS_TO]->(t:Function)
        WHERE f.binary_id <> t.binary_id
        RETURN f.name as imp, t.name as exp, r.dll_name as dll
        LIMIT 10
    """)
    if rows:
        for r in rows:
            print(f"  {r['imp']} --LINKS_TO--> {r['exp']} (dll={r['dll']})")
    else:
        print("  No cross-binary links resolved (expected for non-overlapping binaries)")

    driver.close()
    print("\n" + "=" * 80)
    print("SAMPLING COMPLETE")


if __name__ == "__main__":
    main()
