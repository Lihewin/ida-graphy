"""Cross-binary symbol resolver for LINKS_TO edges."""

import logging
from typing import Dict, List, Tuple, Optional

from core.models import LinksToEdge, FunctionNode

logger = logging.getLogger(__name__)


class SymbolResolver:
    """Resolve LINKS_TO edges from IMPORT to EXPORT functions."""

    def __init__(self):
        self.export_table: Dict[Tuple[str, str], str] = {}
        self.resolved_count = 0
        self.unresolved_count = 0

    def build_export_table(self, functions: List[FunctionNode], binary_name: str) -> None:
        dll_name = binary_name.lower()
        if not dll_name.endswith(".dll") and not dll_name.endswith(".exe"):
            dll_name = dll_name + ".dll"

        export_count = 0
        for func in functions:
            if func.func_type == "EXPORT":
                key = (dll_name, func.name)
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

        for edge in edges:
            dll_func = self._reverse_lookup_virtual_id(edge)

            if dll_func:
                dll_name, func_name = dll_func

                real_func_uid = None
                for variant in self._get_dll_name_variants(dll_name):
                    key = (variant, func_name)
                    if key in self.export_table:
                        real_func_uid = self.export_table[key]
                        break

                if real_func_uid:
                    edge.to_id = real_func_uid
                    self.resolved_count += 1
                else:
                    self.unresolved_count += 1
            else:
                self.unresolved_count += 1

            resolved_edges.append(edge)

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

        if not dll_name.lower().endswith(".dll"):
            variants.append(dll_name.lower() + ".dll")
        else:
            variants.append(dll_name.lower().replace(".dll", ""))

        variants.append(dll_name.upper())
        if dll_name.lower().endswith(".dll"):
            variants.append(dll_name.upper().replace(".DLL", ".dll"))

        return list(set(variants))


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
