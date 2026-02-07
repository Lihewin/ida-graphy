"""Quick check: what does RawImport.name vs ida_name look like for ELF?

Runs a partial extraction (imports only) via idalib headless on sshd.
Also checks what segments IDA sees.
"""
import sys
import os

# Add project root
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import yaml
config = yaml.safe_load(open("config.yaml"))
ida_path = config["ida"]["idalib_python"]
ida_install = config["ida"]["path"]
if ida_path not in sys.path:
    sys.path.insert(0, ida_path)
if ida_install not in sys.path:
    sys.path.insert(0, ida_install)

import idalib
try:
    import idapro as idalib
except ImportError:
    import idalib
binary_path = r"C:\Users\vm\Desktop\pan_os_1_img\usr\sbin\sshd"
print(f"Opening: {binary_path}")
idalib.open_database(binary_path, True)

import ida_nalt, ida_segment, idc, idautils, idaapi

# 1. List all segments
print("\n=== SEGMENTS ===")
for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    name = ida_segment.get_segm_name(seg)
    print(f"  {name}: 0x{seg.start_ea:X} - 0x{seg.end_ea:X} (sz={seg.end_ea - seg.start_ea})")

# 2. Check import data
print("\n=== IMPORTS (first 20) ===")
nimps = ida_nalt.get_import_module_qty()
print(f"Module count: {nimps}")
count = 0
for i in range(nimps):
    module_name = ida_nalt.get_import_module_name(i)
    print(f"\n  Module[{i}]: '{module_name}'")
    
    def cb(ea, name, ordinal):
        global count
        if count >= 20:
            return False
        ida_name_val = idc.get_name(ea) or ""
        func_name = idc.get_func_name(ea) or ""
        print(f"    ea=0x{ea:X}  name='{name}'  ida_name='{ida_name_val}'  func_name='{func_name}'")
        count += 1
        return True
    
    ida_nalt.enum_import_names(i, cb)
    if count >= 20:
        break

# 3. Check file type
print(f"\n=== FILE TYPE ===")
print(f"  idaapi.inf_get_filetype() = {idaapi.inf_get_filetype()}")
print(f"  idaapi.f_ELF = {idaapi.f_ELF}")
print(f"  Is ELF: {idaapi.inf_get_filetype() == idaapi.f_ELF}")

# 4. Check .gnu.version_r segment
print("\n=== .gnu.version_r check ===")
for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    name = ida_segment.get_segm_name(seg)
    if "version" in name.lower() or "gnu" in name.lower():
        print(f"  Found: {name} at 0x{seg.start_ea:X}")

idalib.close_database(False)
print("\nDone.")
