"""Cross-binary symbol resolver for LINKS_TO edges."""

import logging
import re
from typing import Dict, List, Tuple, Optional

from core.models import LinksToEdge, FunctionNode

logger = logging.getLogger(__name__)


class SymbolResolver:
    """Resolve LINKS_TO edges from IMPORT to EXPORT functions."""

    def __init__(self):
        self.export_table: Dict[Tuple[str, str], str] = {}
        self.resolved_count = 0
        self.unresolved_count = 0

    @staticmethod
    def _has_binary_extension(name: str) -> bool:
        """Check whether *name* already carries a known binary extension."""
        lower = name.lower()
        return (
            lower.endswith(".dll")
            or lower.endswith(".exe")
            or lower.endswith(".sys")
            or lower.endswith(".drv")
            or lower.endswith(".dylib")
            or ".so" in lower  # covers .so, .so.6, etc.
        )

    def build_export_table(self, functions: List[FunctionNode], binary_name: str) -> None:
        dll_name = binary_name.lower()
        if not self._has_binary_extension(dll_name):
            dll_name = dll_name + ".dll"

        export_count = 0
        for func in functions:
            if func.func_type != "EXPORT":
                continue
            for name_variant in self._name_variants(func.name, func.orig_name):
                key = (dll_name, name_variant)
                if key not in self.export_table:
                    self.export_table[key] = func.uid
            export_count += 1

        if export_count > 0:
            logger.info("Added %d exports from %s", export_count, dll_name)

    def resolve_links_to_edges(self, edges: List[LinksToEdge]) -> List[LinksToEdge]:
        if len(self.export_table) == 0:
            logger.info("No EXPORT functions available, skipping symbol resolution")
            return edges

        logger.info("Resolving %d LINKS_TO edges against %d exports...", len(edges), len(self.export_table))
        resolved_edges = []
        seen = set()

        for edge in edges:
            dll_func = self._reverse_lookup_virtual_id(edge)

            if dll_func:
                dll_name, func_name = dll_func

                real_func_uid = None
                for dll_variant in self._get_dll_name_variants(dll_name):
                    for name_variant in self._name_variants(func_name, None):
                        key = (dll_variant, name_variant)
                        if key in self.export_table:
                            real_func_uid = self.export_table[key]
                            break
                    if real_func_uid:
                        break

                if real_func_uid:
                    edge.to_id = real_func_uid
                    self.resolved_count += 1
                else:
                    self.unresolved_count += 1
            else:
                self.unresolved_count += 1

            dedupe_key = (edge.from_id, edge.to_id, edge.dll_name, edge.func_name)
            if dedupe_key not in seen:
                resolved_edges.append(edge)
                seen.add(dedupe_key)

        logger.info("Symbol resolution completed:")
        logger.info("  - Resolved: %d", self.resolved_count)
        logger.info("  - Unresolved: %d (external DLLs not in analysis)", self.unresolved_count)

        return resolved_edges

    def _reverse_lookup_virtual_id(self, edge: LinksToEdge) -> Optional[Tuple[str, str]]:
        if edge.dll_name and edge.func_name:
            return (edge.dll_name, edge.func_name)
        return None

    def _get_dll_name_variants(self, dll_name: str) -> List[str]:
        variants = [dll_name.lower()]

        lower_name = dll_name.lower()
        if lower_name.endswith(".dll"):
            variants.append(lower_name.replace(".dll", ""))
        elif lower_name.endswith(".exe"):
            variants.append(lower_name.replace(".exe", ""))
        elif ".so" in lower_name:
            # ELF shared library: libc.so.6 → libc.so → libc
            m = re.match(r'(.+\.so)(\.\d+)*$', lower_name)
            if m:
                variants.append(m.group(1))             # libc.so
                variants.append(m.group(1).rsplit('.so', 1)[0])  # libc
            else:
                variants.append(lower_name.rsplit('.so', 1)[0])
        elif lower_name.endswith(".dylib"):
            variants.append(lower_name.replace(".dylib", ""))
            variants.append(lower_name.replace(".dylib", ".so"))
        else:
            variants.append(lower_name + ".dll")

        variants.append(dll_name.upper())
        if lower_name.endswith(".dll"):
            variants.append(dll_name.upper().replace(".DLL", ".dll"))
        if lower_name.endswith(".exe"):
            variants.append(dll_name.upper().replace(".EXE", ".exe"))

        return list(set(variants))

    def _name_variants(self, name: Optional[str], orig_name: Optional[str]) -> List[str]:
        variants = set()

        for source in [name, orig_name]:
            if not source:
                continue
            variants.add(source)

            for prefix in ["__imp_", "_imp_"]:
                if source.startswith(prefix):
                    variants.add(source[len(prefix):])

            if source.startswith("_"):
                variants.add(source[1:])

            if "@" in source:
                base = source.split("@", 1)[0]
                variants.add(base)

            cleaned = source.lstrip("_")
            if "@" in cleaned:
                cleaned = cleaned.split("@", 1)[0]
            variants.add(cleaned)

        return [v for v in variants if v]

def resolve_symbols(
    all_functions: List[FunctionNode],
    all_links_to_edges: List[LinksToEdge],
    binary_names: Dict[str, str],
) -> List[LinksToEdge]:
    resolver = SymbolResolver()

    binary_functions: Dict[str, List[FunctionNode]] = {}
    for func in all_functions:
        if func.binary_id not in binary_functions:
            binary_functions[func.binary_id] = []
        binary_functions[func.binary_id].append(func)

    for binary_hash, functions in binary_functions.items():
        binary_name = binary_names.get(binary_hash, "unknown")
        resolver.build_export_table(functions, binary_name)

    return resolver.resolve_links_to_edges(all_links_to_edges)
