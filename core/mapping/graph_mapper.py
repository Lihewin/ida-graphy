"""Graph mapper from raw DTOs to graph models."""

import hashlib
from typing import Dict, List

from core.models import (
    GraphData,
    BinaryNode,
    FunctionNode,
    DataSlotNode,
    StringNode,
    ContainsEdge,
    CallsEdge,
    LinksToEdge,
    ReferencesEdge,
    WritesEdge,
    ReadsEdge,
)
from core.extraction.raw_data import (
    RawBinaryData,
    RawBinaryInfo,
    RawFunction,
    RawString,
    RawGlobal,
    RawStructMember,
    RawCall,
    RawStringRef,
    RawImport,
    RawDataAccess,
)
from .id_generator import NodeIDGenerator
from .struct_normalizer import StructNameNormalizer


class GraphMapper:
    """Map raw data into graph models."""

    def __init__(self, binary_content: bytes, struct_normalizer: StructNameNormalizer = None):
        self.id_gen = NodeIDGenerator(binary_content=binary_content)
        self.normalizer = struct_normalizer or StructNameNormalizer()

    def map(self, raw_data: RawBinaryData) -> GraphData:
        graph = GraphData()

        base_addr = raw_data.binary_info.base_addr if raw_data.binary_info else 0

        binary_node = self._map_binary(raw_data.binary_info)
        graph.binaries.append(binary_node)
        graph.binary_name = raw_data.binary_info.name if raw_data.binary_info else None

        func_map: Dict[int, FunctionNode] = {}
        import_uids_by_name: Dict[str, str] = {}
        func_uid_set = set()
        for func in raw_data.functions:
            node = self._map_function(func, base_addr)
            func_map[func.ea] = node
            graph.functions.append(node)
            func_uid_set.add(node.uid)
            if node.func_type == "IMPORT":
                for variant in self._import_name_variants(node.name):
                    if variant and variant not in import_uids_by_name:
                        import_uids_by_name[variant] = node.uid

        for imp in raw_data.imports:
            if not imp.name:
                continue
            import_uid = self.id_gen.get_function_id(imp.ea - base_addr)
            if import_uid not in func_uid_set:
                import_node = FunctionNode(
                    uid=import_uid,
                    rva=imp.ea - base_addr,
                    name=imp.name,
                    size=0,
                    is_lib=True,
                    func_type="IMPORT",
                    signature="",
                    complexity=0,
                    binary_id=self.id_gen.get_binary_id(),
                )
                graph.functions.append(import_node)
                func_uid_set.add(import_uid)
            for variant in self._import_name_variants(imp.name):
                if variant and variant not in import_uids_by_name:
                    import_uids_by_name[variant] = import_uid

        string_map: Dict[int, StringNode] = {}
        for s in raw_data.strings:
            node = self._map_string(s)
            string_map[s.ea] = node
            graph.strings.append(node)

        global_map: Dict[int, DataSlotNode] = {}
        for g in raw_data.globals:
            node = self._map_global(g, base_addr)
            global_map[g.ea] = node
            graph.dataslots.append(node)

        for member in raw_data.struct_members:
            node = self._map_struct_member(member)
            graph.dataslots.append(node)

        for func in graph.functions:
            graph.contains.append(ContainsEdge(from_id=binary_node.hash, to_id=func.uid))
        for s in graph.strings:
            graph.contains.append(ContainsEdge(from_id=binary_node.hash, to_id=s.hash))
        for ds in graph.dataslots:
            if ds.is_global:
                graph.contains.append(ContainsEdge(from_id=binary_node.hash, to_id=ds.uid))

        for call in raw_data.calls:
            edge = self._map_call_edge(call, func_map)
            if edge:
                graph.calls.append(edge)

        for ref in raw_data.string_refs:
            edge = self._map_string_ref(ref, func_map, string_map)
            if edge:
                graph.references.append(edge)

        for imp in raw_data.imports:
            edge = self._map_import_edge(imp, base_addr, import_uids_by_name)
            if edge:
                graph.links_to.append(edge)

        for access in raw_data.data_accesses:
            edge = self._map_data_access(access, func_map, global_map)
            if edge:
                if isinstance(edge, WritesEdge):
                    graph.writes.append(edge)
                else:
                    graph.reads.append(edge)

        return graph

    def _map_binary(self, info: RawBinaryInfo) -> BinaryNode:
        return BinaryNode(
            hash=self.id_gen.get_binary_id(),
            name=info.name,
            base_addr=info.base_addr,
            arch=info.arch,
            compile_ts=info.compile_ts,
        )

    def _map_function(self, func: RawFunction, base_addr: int) -> FunctionNode:
        rva = func.ea - base_addr
        func_uid = self.id_gen.get_function_id(rva)
        func_type = self._classify_function(func)
        return FunctionNode(
            uid=func_uid,
            rva=rva,
            name=func.name,
            size=func.size,
            is_lib=self._is_library_function(func.name, func.flags),
            func_type=func_type,
            signature=func.signature,
            complexity=0,
            binary_id=self.id_gen.get_binary_id(),
        )

    def _map_string(self, string: RawString) -> StringNode:
        return StringNode(
            hash=self.id_gen.get_string_id(string.content),
            content=string.content,
            encoding=string.encoding,
        )

    def _map_global(self, global_var: RawGlobal, base_addr: int) -> DataSlotNode:
        rva = global_var.ea - base_addr
        return DataSlotNode(
            uid=self.id_gen.get_global_slot_id(rva),
            base_type="GLOBAL",
            offset=rva,
            size=global_var.size,
            name=global_var.name,
            is_global=True,
        )

    def _map_struct_member(self, member: RawStructMember) -> DataSlotNode:
        normalized_name = self.normalizer.normalize(member.struct_name)
        return DataSlotNode(
            uid=self.id_gen.get_struct_slot_id(normalized_name, member.offset),
            base_type=normalized_name,
            offset=member.offset,
            size=member.size,
            name=member.name,
            is_global=False,
        )

    def _map_call_edge(self, call: RawCall, func_map: Dict[int, FunctionNode]) -> CallsEdge:
        caller = func_map.get(call.caller_ea)
        callee = func_map.get(call.callee_ea)
        if not caller or not callee:
            return None
        return CallsEdge(
            from_id=caller.uid,
            to_id=callee.uid,
            call_type=call.call_type,
            count=1,
        )

    def _map_string_ref(
        self,
        ref: RawStringRef,
        func_map: Dict[int, FunctionNode],
        string_map: Dict[int, StringNode],
    ) -> ReferencesEdge:
        func = func_map.get(ref.func_ea)
        string = string_map.get(ref.string_ea)
        if not func or not string:
            return None
        return ReferencesEdge(from_id=func.uid, to_id=string.hash)

    def _map_import_edge(
        self,
        imp: RawImport,
        base_addr: int,
        import_uids_by_name: Dict[str, str],
    ) -> LinksToEdge:
        if not imp.name:
            return None
        import_uid = None
        for variant in self._import_name_variants(imp.name):
            import_uid = import_uids_by_name.get(variant)
            if import_uid:
                break
        if not import_uid:
            import_uid = self.id_gen.get_function_id(imp.ea - base_addr)
        external_id = hashlib.md5(f"{imp.module}!{imp.name}".encode("utf-8")).hexdigest()
        return LinksToEdge(
            from_id=import_uid,
            to_id=external_id,
            dll_name=imp.module,
            func_name=imp.name,
        )

    def _import_name_variants(self, name: str) -> List[str]:
        if not name:
            return []

        variants = {name}

        for prefix in ["__imp_", "_imp_"]:
            if name.startswith(prefix):
                variants.add(name[len(prefix) :])

        if name.startswith("_"):
            variants.add(name[1:])

        if "@" in name:
            base = name.split("@", 1)[0]
            variants.add(base)

        cleaned = name.lstrip("_")
        if "@" in cleaned:
            cleaned = cleaned.split("@", 1)[0]
        variants.add(cleaned)

        return [v for v in variants if v]

    def _map_data_access(
        self,
        access: RawDataAccess,
        func_map: Dict[int, FunctionNode],
        global_map: Dict[int, DataSlotNode],
    ):
        func = func_map.get(access.func_ea)
        target = global_map.get(access.target_ea)
        if not func or not target:
            return None

        if access.is_write:
            return WritesEdge(
                from_id=func.uid,
                to_id=target.uid,
                op_type=access.op_type,
                const_val=access.const_val,
                loc=access.loc,
            )

        return ReadsEdge(
            from_id=func.uid,
            to_id=target.uid,
            condition=access.is_condition,
            op_type=access.op_type,
            const_val=access.const_val,
            loc=access.loc,
        )

    def _classify_function(self, func: RawFunction) -> str:
        if func.is_export:
            return "EXPORT"
        if func.is_import:
            return "IMPORT"
        if func.is_thunk:
            return "THUNK"
        return "NORMAL"

    def _is_library_function(self, name: str, flags: int) -> bool:
        lib_prefixes = ["__", "_imp_", "std::", "operator"]
        for prefix in lib_prefixes:
            if name.startswith(prefix):
                return True
        return False
