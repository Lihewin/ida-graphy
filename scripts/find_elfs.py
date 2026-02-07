"""Scan pan_os_1_img for medium-sized ELF binaries."""
import os

def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

BASE = r"C:\Users\vm\Desktop\pan_os_1_img"
MIN_KB, MAX_KB = 200, 5000

results = []
for root, dirs, files in os.walk(BASE):
    # Skip debug/src dirs
    if "debug" in root or "src" in root or "python" in root:
        continue
    for f in files:
        fp = os.path.join(root, f)
        try:
            sz = os.path.getsize(fp)
        except Exception:
            continue
        if MIN_KB * 1024 < sz < MAX_KB * 1024 and is_elf(fp):
            rel = os.path.relpath(fp, BASE)
            results.append((sz, rel, fp))

results.sort()
print(f"Found {len(results)} ELF files ({MIN_KB}KB-{MAX_KB}KB)")
print("=" * 80)
for sz, rel, fp in results:
    print(f"  {sz // 1024:>5}KB  {rel}")
