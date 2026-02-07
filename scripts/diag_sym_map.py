"""Diagnostic: check .gnu.version indices for unresolved symbols."""
import struct as _struct
from core.extraction.engine import _parse_elf_import_maps

elf_path = r"C:\Users\vm\Desktop\pan_os_1_img\usr\sbin\sshd"

tag_map, sym_map = _parse_elf_import_maps(elf_path)
print(f"tag_to_lib: {len(tag_map)} entries")
print(f"sym_to_lib: {len(sym_map)} entries")
print()

# Check specific unresolved symbols
unresolved = ["deflateInit_", "deflate", "deflateEnd", "inflate", "inflateEnd",
              "inflateInit_", "audit_open", "audit_close", "pcre_compile",
              "_ITM_registerTMCloneTable", "__gmon_start__", "freecon", "getcon"]

for sym in unresolved:
    lib = sym_map.get(sym, "NOT FOUND")
    print(f"  {sym:40s} -> {lib}")

print()
print("--- Full sym_to_lib (first 30) ---")
for i, (k, v) in enumerate(sorted(sym_map.items())):
    if i >= 30:
        print(f"  ... and {len(sym_map) - 30} more")
        break
    print(f"  {k:40s} -> {v}")
