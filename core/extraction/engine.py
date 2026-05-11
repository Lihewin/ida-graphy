"""IDA data extraction engine.

Collects raw DTOs from IDA without generating graph IDs.
"""

import logging
import os
import struct as _struct
import time
from typing import Dict, List, Optional

from .raw_data import (
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
from .hexrays_harvest import HexraysHarvestResult, harvest_hexrays_ctree

try:
    import ida_funcs
    import ida_nalt
    import ida_segment
    import ida_bytes
    import ida_entry
    import idautils
    import idc
    import ida_xref
    import idaapi
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

logger = logging.getLogger("ida-graphy")


def _log_perf(stage: str, start: float, binary: str, **fields) -> None:
    elapsed = time.perf_counter() - start
    extra = " ".join(f"{key}={value}" for key, value in fields.items())
    logger.info(
        "[PERF] stage=%s binary=%s seconds=%.6f%s%s",
        stage,
        binary,
        elapsed,
        " " if extra else "",
        extra,
    )


# ---------------------------------------------------------------------------
# Standalone ELF file parser  (no IDA dependency — reads raw bytes from disk)
# ---------------------------------------------------------------------------

def _parse_elf_verneed(elf_path: str) -> Dict[str, str]:
    """Parse ``.gnu.version_r`` from an ELF file on disk.

    Returns ``{version_tag: library_filename}``, e.g.::

        {"GLIBC_2.3.4": "libc.so.6", "OPENSSL_1_1_0": "libssl.so.1.1"}
    """
    tag_map, _ = _parse_elf_import_maps(elf_path)
    return tag_map


def _parse_elf_import_maps(elf_path: str):
    """Parse ELF to build comprehensive import resolution maps.

    Returns ``(tag_to_lib, sym_to_lib)``:

    - ``tag_to_lib``: ``{version_tag: lib_name}`` from ``.gnu.version_r``
    - ``sym_to_lib``: ``{symbol_name: lib_name}`` by cross-referencing
      ``.dynsym``, ``.gnu.version``, and ``.gnu.version_r``

    This resolves ALL dynamic imports including those **without**
    ``@@VERSION_TAG`` annotations (e.g. zlib, libaudit, libselinux).
    """
    SHT_STRTAB = 3
    SHT_DYNSYM = 11
    SHT_GNU_VERSYM = 0x6FFFFFFF
    SHT_GNU_VERNEED = 0x6FFFFFFE

    tag_to_lib: Dict[str, str] = {}
    sym_to_lib: Dict[str, str] = {}

    try:
        with open(elf_path, "rb") as f:
            data = f.read()
    except Exception:
        return tag_to_lib, sym_to_lib

    if len(data) < 64 or data[:4] != b"\x7fELF":
        return tag_to_lib, sym_to_lib

    is_64 = data[4] == 2
    is_le = data[5] == 1
    endian = "<" if is_le else ">"

    if is_64:
        e_shoff = _struct.unpack_from(f"{endian}Q", data, 40)[0]
        e_shentsize = _struct.unpack_from(f"{endian}H", data, 58)[0]
        e_shnum = _struct.unpack_from(f"{endian}H", data, 60)[0]
    else:
        e_shoff = _struct.unpack_from(f"{endian}I", data, 32)[0]
        e_shentsize = _struct.unpack_from(f"{endian}H", data, 46)[0]
        e_shnum = _struct.unpack_from(f"{endian}H", data, 48)[0]

    if e_shoff == 0 or e_shnum == 0:
        return tag_to_lib, sym_to_lib

    def _read_sh(idx: int):
        """Return (sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize, sh_info)."""
        off = e_shoff + idx * e_shentsize
        if is_64:
            sh_name = _struct.unpack_from(f"{endian}I", data, off)[0]
            sh_type = _struct.unpack_from(f"{endian}I", data, off + 4)[0]
            sh_offset = _struct.unpack_from(f"{endian}Q", data, off + 24)[0]
            sh_size = _struct.unpack_from(f"{endian}Q", data, off + 32)[0]
            sh_link = _struct.unpack_from(f"{endian}I", data, off + 40)[0]
            sh_info = _struct.unpack_from(f"{endian}I", data, off + 44)[0]
            sh_entsize = _struct.unpack_from(f"{endian}Q", data, off + 56)[0]
        else:
            sh_name = _struct.unpack_from(f"{endian}I", data, off)[0]
            sh_type = _struct.unpack_from(f"{endian}I", data, off + 4)[0]
            sh_offset = _struct.unpack_from(f"{endian}I", data, off + 16)[0]
            sh_size = _struct.unpack_from(f"{endian}I", data, off + 20)[0]
            sh_link = _struct.unpack_from(f"{endian}I", data, off + 24)[0]
            sh_info = _struct.unpack_from(f"{endian}I", data, off + 28)[0]
            sh_entsize = _struct.unpack_from(f"{endian}I", data, off + 36)[0]
        return sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize, sh_info

    def _read_cstring(strtab_data: bytes, offset: int) -> str:
        end = strtab_data.find(b"\x00", offset)
        if end == -1:
            end = len(strtab_data)
        return strtab_data[offset:end].decode("utf-8", errors="replace")

    # --- Collect all section headers by type ---
    verneed_sh = None          # (offset, size, link)
    versym_sh = None           # (offset, size)
    dynsym_sh = None           # (offset, size, link, entsize)
    strtab_sections: Dict[int, bytes] = {}  # section_idx → raw data

    for i in range(e_shnum):
        sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize, sh_info = _read_sh(i)
        if sh_type == SHT_GNU_VERNEED:
            verneed_sh = (sh_offset, sh_size, sh_link)
        elif sh_type == SHT_GNU_VERSYM:
            versym_sh = (sh_offset, sh_size)
        elif sh_type == SHT_DYNSYM:
            dynsym_sh = (sh_offset, sh_size, sh_link, sh_entsize or (24 if is_64 else 16))
        if sh_type == SHT_STRTAB:
            strtab_sections[i] = data[sh_offset : sh_offset + sh_size]

    # --- 1. Parse .gnu.version_r → tag_to_lib + idx_to_lib ---
    idx_to_lib: Dict[int, str] = {}  # version_index → lib_name

    if verneed_sh is not None:
        vn_offset, vn_size, vn_strtab_idx = verneed_sh
        strtab_data = strtab_sections.get(vn_strtab_idx)
        if strtab_data is None:
            _, _, st_off, st_sz, _, _, _ = _read_sh(vn_strtab_idx)
            strtab_data = data[st_off : st_off + st_sz]

        if strtab_data:
            pos = vn_offset
            vn_end = vn_offset + vn_size
            while pos < vn_end:
                vn_cnt = _struct.unpack_from(f"{endian}H", data, pos + 2)[0]
                vn_file = _struct.unpack_from(f"{endian}I", data, pos + 4)[0]
                vn_aux = _struct.unpack_from(f"{endian}I", data, pos + 8)[0]
                vn_next = _struct.unpack_from(f"{endian}I", data, pos + 12)[0]

                lib_name = _read_cstring(strtab_data, vn_file)

                aux_pos = pos + vn_aux
                for _ in range(vn_cnt):
                    vna_flags = _struct.unpack_from(f"{endian}H", data, aux_pos + 4)[0]
                    vna_other = _struct.unpack_from(f"{endian}H", data, aux_pos + 6)[0]
                    vna_name_off = _struct.unpack_from(f"{endian}I", data, aux_pos + 8)[0]
                    vna_next = _struct.unpack_from(f"{endian}I", data, aux_pos + 12)[0]

                    version_tag = _read_cstring(strtab_data, vna_name_off)
                    if version_tag and lib_name:
                        tag_to_lib[version_tag] = lib_name
                    if vna_other and lib_name:
                        idx_to_lib[vna_other] = lib_name

                    if vna_next == 0:
                        break
                    aux_pos += vna_next

                if vn_next == 0:
                    break
                pos += vn_next

    # --- 2. Parse .gnu.version + .dynsym → sym_to_lib ---
    if versym_sh and dynsym_sh and idx_to_lib:
        vs_offset, vs_size = versym_sh
        ds_offset, ds_size, ds_strtab_idx, ds_entsize = dynsym_sh

        dynstr_data = strtab_sections.get(ds_strtab_idx)
        if dynstr_data is None:
            _, _, st_off, st_sz, _, _, _ = _read_sh(ds_strtab_idx)
            dynstr_data = data[st_off : st_off + st_sz]

        if dynstr_data:
            num_syms = ds_size // ds_entsize
            # .gnu.version has one uint16 per .dynsym entry
            num_vers = vs_size // 2

            for i in range(min(num_syms, num_vers)):
                # Read version index from .gnu.version
                ver_idx = _struct.unpack_from(f"{endian}H", data, vs_offset + i * 2)[0]
                # Mask out the hidden bit (bit 15)
                ver_idx_clean = ver_idx & 0x7FFF

                if ver_idx_clean < 2:
                    # 0 = VER_NDX_LOCAL, 1 = VER_NDX_GLOBAL — unversioned
                    continue

                lib = idx_to_lib.get(ver_idx_clean)
                if not lib:
                    continue

                # Read symbol name from .dynsym
                sym_off = ds_offset + i * ds_entsize
                if is_64:
                    st_name = _struct.unpack_from(f"{endian}I", data, sym_off)[0]
                else:
                    st_name = _struct.unpack_from(f"{endian}I", data, sym_off)[0]

                sym_name = _read_cstring(dynstr_data, st_name)
                if sym_name:
                    sym_to_lib[sym_name] = lib

    return tag_to_lib, sym_to_lib


class ExtractionEngine:
    """IDALib data extraction engine."""

    def __init__(self, binary_path: str, enable_dataflow: bool = True):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path)
        self.enable_dataflow = enable_dataflow

        self._ensure_ida_imports()
        if not IDA_AVAILABLE:
            raise RuntimeError("IDA SDK not available. Run inside IDA or configure idalib.")

        self._export_set = None
        self._string_ea_set = set()
        self._elf_tag_to_lib: Optional[Dict[str, str]] = None
        self._elf_sym_to_lib: Optional[Dict[str, str]] = None
        self._hexrays_harvest: Optional[HexraysHarvestResult] = None

    def extract(self) -> RawBinaryData:
        """Run full extraction workflow."""
        total_start = time.perf_counter()
        raw = RawBinaryData()
        stage_start = time.perf_counter()
        raw.binary_info = self.extract_binary_info()
        _log_perf("extract.binary_info", stage_start, self.binary_name)
        stage_start = time.perf_counter()
        raw.functions = self.extract_functions()
        _log_perf("extract.functions", stage_start, self.binary_name, count=len(raw.functions))
        stage_start = time.perf_counter()
        raw.strings = self.extract_strings()
        _log_perf("extract.strings", stage_start, self.binary_name, count=len(raw.strings))
        stage_start = time.perf_counter()
        raw.globals = self.extract_globals()
        _log_perf("extract.globals", stage_start, self.binary_name, count=len(raw.globals))
        stage_start = time.perf_counter()
        raw.struct_members = self.extract_struct_members()
        _log_perf("extract.struct_members", stage_start, self.binary_name, count=len(raw.struct_members))
        stage_start = time.perf_counter()
        raw.imports = self.extract_imports()
        _log_perf("extract.imports", stage_start, self.binary_name, count=len(raw.imports))
        stage_start = time.perf_counter()
        self._hexrays_harvest = harvest_hexrays_ctree(
            raw.functions,
            raw.binary_info.base_addr if raw.binary_info else ida_nalt.get_imagebase(),
            enable_dataflow=self.enable_dataflow,
        )
        raw.ghidra_fallbacks = list(self._hexrays_harvest.ghidra_fallbacks)
        _log_perf(
            "extract.hexrays_harvest",
            stage_start,
            self.binary_name,
            processed=len(self._hexrays_harvest.processed_functions),
            call_ctx=self._hexrays_harvest.total_call_ctx,
            data_accesses=len(self._hexrays_harvest.data_accesses),
            ghidra_fallbacks=len(raw.ghidra_fallbacks),
        )
        stage_start = time.perf_counter()
        raw.calls = self.extract_calls(
            raw.functions,
            {imp.ea for imp in raw.imports},
            self._hexrays_harvest,
        )
        _log_perf("extract.calls", stage_start, self.binary_name, count=len(raw.calls))
        stage_start = time.perf_counter()
        raw.string_refs = self.extract_string_refs(raw.functions)
        _log_perf("extract.string_refs", stage_start, self.binary_name, count=len(raw.string_refs))

        if self.enable_dataflow:
            stage_start = time.perf_counter()
            raw.data_accesses = self.extract_dataflow(
                raw.functions,
                raw.globals,
                self._hexrays_harvest,
            )
            _log_perf("extract.dataflow", stage_start, self.binary_name, count=len(raw.data_accesses))

        _log_perf("extract.total", total_start, self.binary_name)
        return raw

    def extract_binary_info(self) -> RawBinaryInfo:
        """Extract binary metadata."""
        base_addr = ida_nalt.get_imagebase()
        arch = self._get_arch()
        compile_ts = self._get_compile_ts(base_addr)
        # Use only IDA root filename for binary naming.
        root_name = ida_nalt.get_root_filename() or ""
        return RawBinaryInfo(
            name=root_name,
            orig_name=root_name,
            base_addr=base_addr,
            arch=arch,
            compile_ts=compile_ts,
        )

    def extract_functions(self) -> List[RawFunction]:
        """Extract functions."""
        functions: List[RawFunction] = []

        if self._export_set is None:
            self._export_set = self._build_export_set()

        for func_ea in idautils.Functions():
            func_obj = ida_funcs.get_func(func_ea)
            if not func_obj:
                continue

            name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
            size = func_obj.end_ea - func_obj.start_ea
            signature = self._get_function_signature(func_ea)
            flags = func_obj.flags
            is_lib = bool(flags & ida_funcs.FUNC_LIB)
            is_thunk = bool(flags & ida_funcs.FUNC_THUNK)
            is_export = func_ea in self._export_set
            is_import = self._is_import_function(func_ea, func_obj, name)

            functions.append(
                RawFunction(
                    ea=func_ea,
                    name=name,
                    orig_name=name,
                    size=size,
                    flags=flags,
                    is_lib=is_lib,
                    signature=signature,
                    is_thunk=is_thunk,
                    is_export=is_export,
                    is_import=is_import,
                )
            )

        return functions

    def extract_strings(self) -> List[RawString]:
        """Extract strings."""
        strings: List[RawString] = []
        seen = set()

        for s in idautils.Strings():
            try:
                raw_content = str(s)
                content = self._clean_string(raw_content)
                if len(content) < 2 or not content.strip():
                    continue
                if content in seen:
                    continue
                seen.add(content)

                encoding = "ASCII"
                if hasattr(s, "is_1_byte_encoding"):
                    encoding = "ASCII" if s.is_1_byte_encoding() else "UTF-16"
                elif hasattr(s, "strtype"):
                    encoding = "UTF-16" if s.strtype in [1, 2, 3] else "ASCII"

                strings.append(RawString(ea=s.ea, content=content, orig_content=raw_content, encoding=encoding))
                self._string_ea_set.add(s.ea)
            except Exception:
                continue

        return strings

    def extract_globals(self) -> List[RawGlobal]:
        """Extract globals from data segments."""
        globals_list: List[RawGlobal] = []

        for ea, name in idautils.Names():
            seg = ida_segment.getseg(ea)
            if not seg or seg.type != ida_segment.SEG_DATA:
                continue

            size = ida_bytes.get_item_size(ea)
            if size == 0:
                continue

            globals_list.append(RawGlobal(ea=ea, name=name, orig_name=name, size=size))

        return globals_list

    def extract_struct_members(self) -> List[RawStructMember]:
        """Extract struct members."""
        members: List[RawStructMember] = []

        for _idx, struct_id, struct_name in idautils.Structs():
            if not struct_name:
                continue

            for member_offset, member_name, member_size in idautils.StructMembers(struct_id):
                orig_member_name = member_name or ""
                display_name = member_name or f"field_{member_offset:X}"

                members.append(
                    RawStructMember(
                        struct_name=struct_name,
                        struct_orig_name=struct_name,
                        offset=member_offset,
                        name=display_name,
                        orig_name=orig_member_name,
                        size=member_size,
                    )
                )

        return members

    def extract_calls(
        self,
        functions: List[RawFunction],
        import_eas: Optional[set] = None,
        hexrays_harvest: Optional[HexraysHarvestResult] = None,
    ) -> List[RawCall]:
        """Extract call relationships."""
        calls: List[RawCall] = []
        seen = set()
        func_starts = {f.ea for f in functions}
        import_eas = import_eas or set()
        if not hexrays_harvest or not hexrays_harvest.processed_functions:
            raise RuntimeError("Hex-Rays ctree harvest is required for call context extraction")
        (
            call_contexts_by_addr,
            call_contexts_by_pair,
            call_contexts_by_order,
            call_contexts_by_callee,
        ) = hexrays_harvest.context_indexes()
        call_seq_map = {}
        ctx_hits = 0
        ctx_pair_hits = 0
        ctx_order_hits = 0
        ctx_callee_hits = 0
        ctx_misses = 0
        callee_ctx_index = {}

        def _get_call_ctx(call_addr: int, callee_start: int, caller_ea: int, seq_order: int) -> dict:
            nonlocal ctx_hits, ctx_pair_hits, ctx_order_hits, ctx_callee_hits, ctx_misses
            call_ctx = call_contexts_by_addr.get(call_addr)
            if call_ctx:
                ctx_hits += 1
                return call_ctx
            call_ctx = call_contexts_by_pair.get((caller_ea, callee_start))
            if call_ctx:
                ctx_pair_hits += 1
                return call_ctx
            call_ctx = call_contexts_by_order.get((caller_ea, seq_order))
            if call_ctx:
                ctx_order_hits += 1
                return call_ctx
            callee_key = (caller_ea, callee_start)
            callee_list = call_contexts_by_callee.get(callee_key)
            if callee_list:
                idx = callee_ctx_index.get(callee_key, 0)
                if idx < len(callee_list):
                    callee_ctx_index[callee_key] = idx + 1
                    ctx_callee_hits += 1
                    return callee_list[idx]
            ctx_misses += 1
            return {}

        for func in functions:
            func_obj = ida_funcs.get_func(func.ea)
            if not func_obj:
                continue

            for head in idautils.FuncItems(func.ea):
                mnem = idc.print_insn_mnem(head).lower()
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type not in [ida_xref.fl_CF, ida_xref.fl_CN]:
                        continue

                    callee = ida_funcs.get_func(xref.to)
                    if callee:
                        callee_start = callee.start_ea
                        if callee_start not in func_starts and callee_start not in import_eas:
                            continue
                    else:
                        if xref.to not in import_eas:
                            continue
                        callee_start = xref.to

                    key = (func.ea, callee_start, head)
                    if key in seen:
                        continue
                    seen.add(key)

                    seq_order = call_seq_map.get(func.ea, 0)
                    call_seq_map[func.ea] = seq_order + 1
                    call_ctx = _get_call_ctx(head, callee_start, func.ea, seq_order)

                    calls.append(
                        RawCall(
                            caller_ea=func.ea,
                            callee_ea=callee_start,
                            call_addr=head,
                            call_type=self._detect_call_type(head),
                            seq_order=seq_order,
                            in_condition=call_ctx.get("in_condition", False),
                            in_loop=call_ctx.get("in_loop", False),
                            loop_depth=call_ctx.get("loop_depth", 0),
                            const_args=call_ctx.get("const_args", {}),
                            return_used=call_ctx.get("return_used", False),
                            return_in_condition=call_ctx.get("return_in_condition", False),
                        )
                    )

                if import_eas and mnem in ("call", "jmp"):
                    op_type = idc.get_operand_type(head, 0)
                    if op_type == idc.o_mem:
                        target_ea = idc.get_operand_value(head, 0)
                        if target_ea in import_eas:
                            key = (func.ea, target_ea, head)
                            if key not in seen:
                                seen.add(key)
                                seq_order = call_seq_map.get(func.ea, 0)
                                call_seq_map[func.ea] = seq_order + 1
                                call_ctx = _get_call_ctx(head, target_ea, func.ea, seq_order)
                                calls.append(
                                    RawCall(
                                        caller_ea=func.ea,
                                        callee_ea=target_ea,
                                        call_addr=head,
                                        call_type=self._detect_call_type(head),
                                        seq_order=seq_order,
                                        in_condition=call_ctx.get("in_condition", False),
                                        in_loop=call_ctx.get("in_loop", False),
                                        loop_depth=call_ctx.get("loop_depth", 0),
                                        const_args=call_ctx.get("const_args", {}),
                                        return_used=call_ctx.get("return_used", False),
                                        return_in_condition=call_ctx.get("return_in_condition", False),
                                    )
                                )

        total_ctx = ctx_hits + ctx_pair_hits + ctx_order_hits + ctx_callee_hits + ctx_misses
        if total_ctx:
            logger.info(
                "Call context match: addr_hits=%d, pair_hits=%d, order_hits=%d, callee_hits=%d, miss=%d, total=%d",
                ctx_hits,
                ctx_pair_hits,
                ctx_order_hits,
                ctx_callee_hits,
                ctx_misses,
                total_ctx,
            )
        return calls

    def extract_string_refs(self, functions: List[RawFunction]) -> List[RawStringRef]:
        """Extract function-to-string references."""
        refs: List[RawStringRef] = []

        if not self._string_ea_set:
            return refs

        for func in functions:
            func_obj = ida_funcs.get_func(func.ea)
            if not func_obj:
                continue

            for head in idautils.FuncItems(func.ea):
                for i in range(2):
                    op_type = idc.get_operand_type(head, i)
                    if op_type in [idc.o_mem, idc.o_imm]:
                        op_value = idc.get_operand_value(head, i)
                        if op_value in self._string_ea_set:
                            refs.append(RawStringRef(func_ea=func.ea, string_ea=op_value))

        return refs

    def extract_imports(self) -> List[RawImport]:
        """Extract import table entries.

        For ELF binaries, ``ida_nalt.get_import_module_name()`` returns a
        segment name like ``.dynsym`` instead of the actual shared library
        because ELF uses a flat dynamic symbol table.

        We resolve each import to its real library by:
        1. Parsing ``.gnu.version_r`` from the raw ELF file on disk to build
           a ``version_tag → library_name`` map.
        2. Extracting the ``@@VERSION_TAG`` already present in each import
           ``name`` from IDA's callback (e.g. ``memcpy@@GLIBC_2.14``).
        """
        imports: List[RawImport] = []

        is_elf = self._is_elf()
        ver_tag_to_lib: Dict[str, str] = {}
        sym_to_lib: Dict[str, str] = {}
        if is_elf:
            ver_tag_to_lib, sym_to_lib = self._build_elf_import_maps()

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                continue

            # For ELF, module_name is typically ".dynsym" (a section name)
            needs_resolution = is_elf and module_name.startswith(".")

            def callback(ea, name, _ordinal):
                if ea and ea != idaapi.BADADDR:
                    ida_name = idc.get_name(ea) or idc.get_func_name(ea) or ""

                    resolved_module = module_name
                    if needs_resolution:
                        resolved_module = self._resolve_elf_import_module(
                            name or "", ida_name, ver_tag_to_lib, sym_to_lib, module_name,
                        )

                    imports.append(RawImport(module=resolved_module, name=name or "", ea=ea, ida_name=ida_name))
                return True

            ida_nalt.enum_import_names(i, callback)

        return imports

    def extract_dataflow(
        self,
        functions: List[RawFunction],
        globals_list: List[RawGlobal],
        hexrays_harvest: Optional[HexraysHarvestResult] = None,
    ) -> List[RawDataAccess]:
        """Extract dataflow (READS/WRITES) for global variables and struct members.

        Strategy:
        Use the mandatory Hex-Rays harvest results produced earlier in
        ``extract()``. The main extraction flow does not fall back to
        assembly-level dataflow because that would lose struct semantics.
        """
        if not hexrays_harvest or not hexrays_harvest.processed_functions:
            raise RuntimeError("Hex-Rays ctree harvest is required for dataflow extraction")

        hexrays_accesses = hexrays_harvest.data_accesses
        if hexrays_accesses:
            logger.info(
                "Using Hex-Rays dataflow: %d accesses (struct=%d, global=%d)",
                len(hexrays_accesses),
                sum(1 for a in hexrays_accesses if a.struct_name is not None),
                sum(1 for a in hexrays_accesses if a.struct_name is None),
            )
        else:
            logger.info("Using Hex-Rays dataflow: 0 accesses")
        return hexrays_accesses

    def _extract_dataflow_asm(
        self,
        functions: List[RawFunction],
        globals_list: List[RawGlobal],
        base_addr: int,
    ) -> List[RawDataAccess]:
        """Assembly-level dataflow scan (globals only, no struct members)."""
        accesses: List[RawDataAccess] = []

        global_eas = {g.ea for g in globals_list}
        if not global_eas:
            return accesses

        for func in functions:
            func_obj = ida_funcs.get_func(func.ea)
            if not func_obj:
                continue

            for head in idautils.FuncItems(func.ea):
                mnem = idc.print_insn_mnem(head).lower()

                if mnem in ["mov", "movzx", "movsx", "lea", "xor", "or", "and", "add", "sub", "inc", "dec"]:
                    op0_type = idc.get_operand_type(head, 0)
                    if op0_type == idc.o_mem:
                        target_ea = idc.get_operand_value(head, 0)
                        if target_ea in global_eas:
                            op_type = "ASSIGN"
                            if mnem == "or":
                                op_type = "OR"
                            elif mnem == "and":
                                op_type = "AND"
                            elif mnem in ["add", "inc"]:
                                op_type = "ADD"

                            const_val = None
                            op1_type = idc.get_operand_type(head, 1)
                            if op1_type == idc.o_imm:
                                const_val = hex(idc.get_operand_value(head, 1))

                            accesses.append(
                                RawDataAccess(
                                    func_ea=func.ea,
                                    target_ea=target_ea,
                                    is_write=True,
                                    op_type=op_type,
                                    const_val=const_val,
                                    is_condition=False,
                                    loc=head - base_addr,
                                )
                            )

                for op_idx in [0, 1, 2]:
                    op_type = idc.get_operand_type(head, op_idx)
                    if op_type == idc.o_mem:
                        source_ea = idc.get_operand_value(head, op_idx)
                        if source_ea in global_eas:
                            is_condition = mnem in [
                                "cmp",
                                "test",
                                "jz",
                                "jnz",
                                "je",
                                "jne",
                                "jg",
                                "jl",
                                "jge",
                                "jle",
                            ]
                            const_val = None
                            if mnem in ["cmp", "test"]:
                                other_op_idx = 1 if op_idx == 0 else 0
                                other_op_type = idc.get_operand_type(head, other_op_idx)
                                if other_op_type == idc.o_imm:
                                    const_val = hex(idc.get_operand_value(head, other_op_idx))

                            accesses.append(
                                RawDataAccess(
                                    func_ea=func.ea,
                                    target_ea=source_ea,
                                    is_write=False,
                                    op_type=mnem.upper(),
                                    const_val=const_val,
                                    is_condition=is_condition,
                                    loc=head - base_addr,
                                )
                            )

        return accesses

    # ------------------------------------------------------------------
    # ELF import library resolution helpers
    # ------------------------------------------------------------------

    def _is_elf(self) -> bool:
        """Check if the current binary is ELF format."""
        try:
            return idaapi.inf_get_filetype() == idaapi.f_ELF
        except Exception:
            return False

    def _build_elf_import_maps(self):
        """Parse ELF file to build import resolution maps.

        Uses ``_parse_elf_import_maps()`` which reads the raw binary to
        extract both version-tag-based and symbol-name-based mappings.

        Returns ``(tag_to_lib, sym_to_lib)``.
        """
        if self._elf_tag_to_lib is not None:
            return self._elf_tag_to_lib, self._elf_sym_to_lib

        self._elf_tag_to_lib = {}
        self._elf_sym_to_lib = {}

        try:
            self._elf_tag_to_lib, self._elf_sym_to_lib = _parse_elf_import_maps(self.binary_path)
            total = len(self._elf_tag_to_lib) + len(self._elf_sym_to_lib)
            if total:
                logger.info(
                    "ELF import maps: %d version tags, %d symbol→lib from %s",
                    len(self._elf_tag_to_lib),
                    len(self._elf_sym_to_lib),
                    self.binary_name,
                )
            else:
                logger.info("ELF: no version info found in %s", self.binary_name)
        except Exception as exc:
            logger.warning("ELF import map parsing failed for %s: %s", self.binary_name, exc)

        return self._elf_tag_to_lib, self._elf_sym_to_lib

    @staticmethod
    def _resolve_elf_import_module(
        import_name: str,
        ida_name: str,
        ver_tag_to_lib: Dict[str, str],
        sym_to_lib: Dict[str, str],
        fallback: str,
    ) -> str:
        """Resolve an ELF import's library.

        Resolution strategy (ordered by reliability):
        1. Extract ``@@VERSION_TAG`` from *import_name* and look up in
           *ver_tag_to_lib*.  (Most reliable — IDA already annotates these.)
        2. Look up the clean symbol name in *sym_to_lib* which was built
           from ``.gnu.version`` + ``.dynsym`` cross-referencing.
           (Catches symbols whose version tag was NOT in the name.)
        3. Fall back to the original module string (usually ``.dynsym``).
        """
        if not import_name and not ida_name:
            return fallback

        # Strategy 1: extract @@VERSION_TAG from import name
        tag = None
        if import_name:
            if "@@" in import_name:
                tag = import_name.split("@@", 1)[1]
            elif "@" in import_name:
                tag = import_name.split("@", 1)[1]
        if tag and tag in ver_tag_to_lib:
            return ver_tag_to_lib[tag]

        # Strategy 2: look up clean symbol name in sym_to_lib
        # Try import_name (strip version tag), then ida_name
        clean_name = import_name.split("@@")[0].split("@")[0] if import_name else ""
        if clean_name and clean_name in sym_to_lib:
            return sym_to_lib[clean_name]
        if ida_name and ida_name in sym_to_lib:
            return sym_to_lib[ida_name]

        return fallback

    # ------------------------------------------------------------------
    # end ELF helpers
    # ------------------------------------------------------------------

    def _build_export_set(self) -> set:
        export_set = set()
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            if ea != idc.BADADDR:
                export_set.add(ea)
        return export_set

    def _ensure_ida_imports(self) -> None:
        """Attempt to import IDA APIs after idalib is loaded."""
        global IDA_AVAILABLE
        if IDA_AVAILABLE:
            return

        try:
            global ida_funcs
            global ida_nalt
            global ida_segment
            global ida_bytes
            global ida_entry
            global idautils
            global idc
            global ida_xref
            global idaapi

            import ida_funcs as _ida_funcs
            import ida_nalt as _ida_nalt
            import ida_segment as _ida_segment
            import ida_bytes as _ida_bytes
            import ida_entry as _ida_entry
            import idautils as _idautils
            import idc as _idc
            import ida_xref as _ida_xref
            import idaapi as _idaapi

            ida_funcs = _ida_funcs
            ida_nalt = _ida_nalt
            ida_segment = _ida_segment
            ida_bytes = _ida_bytes
            ida_entry = _ida_entry
            idautils = _idautils
            idc = _idc
            ida_xref = _ida_xref
            idaapi = _idaapi

            IDA_AVAILABLE = True
        except ImportError:
            IDA_AVAILABLE = False

    def _get_arch(self) -> str:
        try:
            proc_name = idaapi.inf_get_procname()
            is_64 = idaapi.inf_is_64bit()
            is_32 = idaapi.inf_is_32bit_exactly()

            if is_64:
                return "x86_64" if "metapc" in proc_name.lower() or "pc" in proc_name.lower() else "ARM64"
            if is_32:
                return "x86" if "metapc" in proc_name.lower() or "pc" in proc_name.lower() or "80" in proc_name else "ARM"
            return proc_name
        except Exception:
            return "x86_64" if idc.get_inf_attr(idc.INF_64BIT) else "x86"

    def _get_compile_ts(self, base_addr: int) -> int:
        try:
            pe_header = base_addr + 0x3C
            if idc.get_wide_dword(pe_header):
                pe_offset = idc.get_wide_dword(pe_header)
                return idc.get_wide_dword(base_addr + pe_offset + 8)
        except Exception:
            pass
        return 0

    def _get_function_signature(self, func_ea: int) -> str:
        try:
            func_type = idc.get_type(func_ea)
            if func_type:
                return func_type
        except Exception:
            pass
        return ""

    def _clean_string(self, s: str) -> str:
        return "".join(c if c.isprintable() else " " for c in s).strip()

    def _detect_call_type(self, insn_ea: int) -> str:
        mnem = idc.print_insn_mnem(insn_ea)
        if mnem in ["call", "jmp"]:
            op_type = idc.get_operand_type(insn_ea, 0)
            if op_type in [idc.o_reg, idc.o_phrase, idc.o_displ]:
                return "INDIRECT"
        if mnem == "jmp":
            return "TAIL"
        return "DIRECT"

    def _is_import_function(self, func_ea: int, func_obj, func_name: str) -> bool:
        seg = ida_segment.getseg(func_ea)
        if not seg:
            return False

        try:
            if seg.type == ida_segment.SEG_XTRN:
                return True
        except Exception:
            pass

        try:
            seg_name = ida_segment.get_segm_name(seg).lower()
        except Exception:
            return False

        return seg_name in {
            "extern",
            "external",
            ".extern",
            ".external",
            ".idata",
            "__imp__",
        }

    def _is_in_import_section(self, ea: int) -> bool:
        seg = ida_segment.getseg(ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
            return seg_name in [".idata", ".rdata", "__imp__"]
        return False
