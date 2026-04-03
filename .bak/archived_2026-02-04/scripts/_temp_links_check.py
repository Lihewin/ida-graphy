import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
idalib_path = r"C:\Program Files\IDA Professional 9.2\idalib\python"
if idalib_path not in sys.path:
    sys.path.insert(0, idalib_path)

import idapro as idalib
import ida_auto

if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.extraction.engine import ExtractionEngine
from core.mapping.graph_mapper import GraphMapper
from core.mapping.symbol_resolver import resolve_symbols
from core.models import GraphData

binaries = [
    ("at.exe", "test_binaries/at.exe"),
    ("schedcli.dll", "test_binaries/schedcli.dll"),
]

merged_graph = GraphData()

for name, path in binaries:
    print("=" * 60)
    print("Binary:", name)
    result = idalib.open_database(path, True)
    if result != 0:
        print("Failed to open", path, result)
        continue

    ida_auto.auto_wait()

    with open(path, "rb") as f:
        binary_content = f.read()

    engine = ExtractionEngine(path)
    raw_data = engine.extract()

    mapper = GraphMapper(binary_content=binary_content)
    graph_data = mapper.map(raw_data)

    print("links_to edges in this binary:", len(graph_data.links_to))

    merged_graph.merge(graph_data)
    idalib.close_database()

binary_names = {b.hash: b.name for b in merged_graph.binaries}
merged_graph.links_to = resolve_symbols(
    merged_graph.functions,
    merged_graph.links_to,
    binary_names,
)

function_uids = {f.uid for f in merged_graph.functions}
resolved_to_existing = [e for e in merged_graph.links_to if e.to_id in function_uids]

print("=" * 60)
print("Merged links_to edges:", len(merged_graph.links_to))
print("Resolved to existing functions:", len(resolved_to_existing))
print("Sample links:")
for edge in resolved_to_existing[:10]:
    print(edge.from_id, "->", edge.to_id, edge.dll_name, edge.func_name)
