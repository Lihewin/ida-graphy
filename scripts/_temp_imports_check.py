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

binaries = [
    ("at.exe", "test_binaries/at.exe"),
    ("schedcli.dll", "test_binaries/schedcli.dll"),
]

for name, path in binaries:
    print("=" * 60)
    print("Binary:", name)
    result = idalib.open_database(path, True)
    if result != 0:
        print("Failed to open", path, result)
        continue

    ida_auto.auto_wait()

    engine = ExtractionEngine(path)
    imports = engine.extract_imports()
    funcs = engine.extract_functions()

    modules = sorted({imp.module for imp in imports})
    export_funcs = [f for f in funcs if f.is_export]

    print("Import modules:", modules)
    print("Import count:", len(imports))
    print("Export count:", len(export_funcs))
    print("Sample exports:", [f.name for f in export_funcs[:10]])

    if name == "at.exe":
        schedcli_imports = sorted({imp.name for imp in imports if imp.module.lower() in ["schedcli", "schedcli.dll"]})
        print("schedcli imports:", schedcli_imports)

    if name == "schedcli.dll":
        export_names = sorted({f.name for f in export_funcs})
        print("schedcli exports:", export_names)

    idalib.close_database()
