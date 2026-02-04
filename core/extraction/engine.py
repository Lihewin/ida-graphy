"""IDA data extraction engine.

Collects raw DTOs from IDA without generating graph IDs.
"""

import logging
import os
from typing import List, Optional

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

logger = logging.getLogger(__name__)


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

    def extract(self) -> RawBinaryData:
        """Run full extraction workflow."""
        raw = RawBinaryData()
        raw.binary_info = self.extract_binary_info()
        raw.functions = self.extract_functions()
        raw.strings = self.extract_strings()
        raw.globals = self.extract_globals()
        raw.struct_members = self.extract_struct_members()
        raw.imports = self.extract_imports()
        raw.calls = self.extract_calls(raw.functions, {imp.ea for imp in raw.imports})
        raw.string_refs = self.extract_string_refs(raw.functions)

        if self.enable_dataflow:
            raw.data_accesses = self.extract_dataflow(raw.functions, raw.globals)

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

    def extract_calls(self, functions: List[RawFunction], import_eas: Optional[set] = None) -> List[RawCall]:
        """Extract call relationships."""
        calls: List[RawCall] = []
        seen = set()
        func_starts = {f.ea for f in functions}
        import_eas = import_eas or set()

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

                    calls.append(
                        RawCall(
                            caller_ea=func.ea,
                            callee_ea=callee_start,
                            call_addr=head,
                            call_type=self._detect_call_type(head),
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
                                calls.append(
                                    RawCall(
                                        caller_ea=func.ea,
                                        callee_ea=target_ea,
                                        call_addr=head,
                                        call_type=self._detect_call_type(head),
                                    )
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
        """Extract import table entries."""
        imports: List[RawImport] = []

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                continue

            def callback(ea, name, _ordinal):
                if ea and ea != idaapi.BADADDR:
                    ida_name = idc.get_name(ea) or idc.get_func_name(ea) or ""
                    imports.append(RawImport(module=module_name, name=name or "", ea=ea, ida_name=ida_name))
                return True

            ida_nalt.enum_import_names(i, callback)

        return imports

    def extract_dataflow(
        self,
        functions: List[RawFunction],
        globals_list: List[RawGlobal],
    ) -> List[RawDataAccess]:
        """Extract simplified dataflow (reads/writes)."""
        accesses: List[RawDataAccess] = []

        global_eas = {g.ea for g in globals_list}
        if not global_eas:
            return accesses

        base_addr = ida_nalt.get_imagebase()

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
        return bool(func_obj.flags & ida_funcs.FUNC_LIB)

    def _is_in_import_section(self, ea: int) -> bool:
        seg = ida_segment.getseg(ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
            return seg_name in [".idata", ".rdata", "__imp__"]
        return False
