"""Hex-Rays ctree based dataflow analysis.

Uses the Hex-Rays decompiler to identify READS and WRITES operations on
global variables and structure members.  The visitor produces
:class:`RawDataAccess` DTOs containing **raw** IDA type names and byte
offsets – no UIDs or normalization is done here (that belongs to the
mapping layer).

When Hex-Rays is unavailable the public entry point
:func:`extract_dataflow_with_hexrays` gracefully returns an empty list so
that the caller can fall back to a simpler assembly-level scan.
"""

import logging
from typing import List, Optional

try:
    import ida_hexrays
    import ida_segment
    import ida_nalt
    import ida_bytes
    import idaapi

    HEXRAYS_AVAILABLE = True
except ImportError:
    HEXRAYS_AVAILABLE = False

from .raw_data import RawDataAccess, RawFunction

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hex-Rays ctree visitor
# ---------------------------------------------------------------------------

if HEXRAYS_AVAILABLE:

    def _init_hexrays() -> bool:
        """Try to initialise the Hex-Rays plugin.  Returns *True* on success."""
        try:
            if hasattr(ida_hexrays, "init_hexrays_plugin"):
                return bool(ida_hexrays.init_hexrays_plugin())
            return True
        except Exception as exc:
            logger.warning("Hex-Rays init exception: %s", exc)
            return False

    def _is_global_var(ea: int) -> bool:
        """Return *True* if *ea* resides in a data / BSS segment."""
        seg = ida_segment.getseg(ea)
        if not seg:
            return False
        if seg.type in (ida_segment.SEG_DATA, ida_segment.SEG_BSS):
            return True
        seg_name = ida_segment.get_segm_name(seg).lower()
        return any(n in seg_name for n in (".data", ".bss", ".rdata", "data", "bss"))

    def _extract_const_value(expr: "ida_hexrays.cexpr_t") -> Optional[str]:
        """Best-effort extraction of a constant value from *expr*."""
        if expr.op == ida_hexrays.cot_num:
            val = expr.numval()
            return hex(val) if val > 9 else str(val)
        if expr.op == ida_hexrays.cot_str:
            return f'"{expr.string}"'
        return None

    # ---- assignment op → semantic label mapping ----
    _WRITE_OPS = {
        ida_hexrays.cot_asg: "ASSIGN",
        ida_hexrays.cot_asgbor: "OR",
        ida_hexrays.cot_asgband: "AND",
        ida_hexrays.cot_asgadd: "ADD",
        ida_hexrays.cot_asgsub: "SUB",
        ida_hexrays.cot_asgmul: "MUL",
    }

    # ---- read expression ops ----
    _READ_OPS = frozenset(
        {
            ida_hexrays.cot_memref,  # obj.member
            ida_hexrays.cot_memptr,  # ptr->member
            ida_hexrays.cot_obj,  # object access
            ida_hexrays.cot_idx,  # array[idx]
        }
    )

    class _DataFlowVisitor(ida_hexrays.ctree_visitor_t):
        """Collect :class:`RawDataAccess` DTOs from a function's ctree.

        The visitor intentionally does **not** compute node UIDs or apply
        struct-name normalisation – that is the mapping layer's job.
        """

        def __init__(self, func_ea: int, base_addr: int):
            super().__init__(ida_hexrays.CV_FAST)
            self.func_ea: int = func_ea
            self.base_addr: int = base_addr

            self.accesses: List[RawDataAccess] = []
            # depth counter – >0 while we are inside a condition expression
            self._cond_depth: int = 0
            # track LHS expressions of current assignment to skip double-counting
            self._write_lhs_set: set = set()

        # -- public results -------------------------------------------------

        def get_accesses(self) -> List[RawDataAccess]:
            return self.accesses

        # -- visitor callbacks ----------------------------------------------

        def visit_insn(self, insn: "ida_hexrays.cinsn_t") -> int:  # noqa: C901
            """Track condition depth across if / switch / loop constructs."""
            op = insn.op

            if op == ida_hexrays.cit_if:
                self._cond_depth += 1
                if insn.cif and insn.cif.expr:
                    insn.cif.expr.accept(self)
                self._cond_depth -= 1
                if insn.cif.ithen:
                    insn.cif.ithen.accept(self)
                if insn.cif.ielse:
                    insn.cif.ielse.accept(self)
                return 1  # prevent automatic child traversal

            if op == ida_hexrays.cit_switch:
                self._cond_depth += 1
                if insn.cswitch and insn.cswitch.expr:
                    insn.cswitch.expr.accept(self)
                self._cond_depth -= 1
                if insn.cswitch and insn.cswitch.cases:
                    for case in insn.cswitch.cases:
                        case.accept(self)
                return 1

            if op in (ida_hexrays.cit_while, ida_hexrays.cit_do):
                loop = getattr(insn, "cwhile", None) or getattr(insn, "cdo", None)
                if loop is None:
                    # IDA 9+ exposes ".details" generically
                    loop = getattr(insn, "details", None)
                if loop:
                    self._cond_depth += 1
                    expr = getattr(loop, "expr", None)
                    if expr:
                        expr.accept(self)
                    self._cond_depth -= 1
                    body = getattr(loop, "body", None)
                    if body:
                        body.accept(self)
                return 1

            if op == ida_hexrays.cit_for:
                cfor = getattr(insn, "cfor", None) or getattr(insn, "details", None)
                if cfor:
                    init = getattr(cfor, "init", None)
                    if init:
                        init.accept(self)
                    self._cond_depth += 1
                    expr = getattr(cfor, "expr", None)
                    if expr:
                        expr.accept(self)
                    self._cond_depth -= 1
                    step = getattr(cfor, "step", None)
                    if step:
                        step.accept(self)
                    body = getattr(cfor, "body", None)
                    if body:
                        body.accept(self)
                return 1

            return 0  # default traversal

        def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
            # ---- WRITES ----
            if expr.op in _WRITE_OPS:
                self._handle_write(expr, _WRITE_OPS[expr.op])

            # ---- READS ----
            elif expr.op in _READ_OPS:
                # avoid counting the LHS of an assignment as a READ
                if id(expr) not in self._write_lhs_set:
                    self._handle_read(expr)

            return 0

        # -- write handling -------------------------------------------------

        def _handle_write(self, expr: "ida_hexrays.cexpr_t", op_type: str) -> None:
            lhs = expr.x
            rhs = expr.y
            if lhs is None:
                return

            # Mark LHS so that visit_expr won't double-count it as a READ
            self._write_lhs_set.add(id(lhs))

            result = self._resolve_slot(lhs)
            if result is None:
                return

            const_val = _extract_const_value(rhs) if rhs else None
            loc = self._ea_to_rva(expr.ea)

            struct_name, member_offset, target_ea = result
            self.accesses.append(
                RawDataAccess(
                    func_ea=self.func_ea,
                    target_ea=target_ea,
                    is_write=True,
                    op_type=op_type,
                    const_val=const_val,
                    is_condition=False,
                    loc=loc,
                    struct_name=struct_name,
                    member_offset=member_offset,
                )
            )

        # -- read handling --------------------------------------------------

        def _handle_read(self, expr: "ida_hexrays.cexpr_t") -> None:
            result = self._resolve_slot(expr)
            if result is None:
                return

            struct_name, member_offset, target_ea = result
            op_type = self._read_op_label(expr)
            loc = self._ea_to_rva(expr.ea)

            self.accesses.append(
                RawDataAccess(
                    func_ea=self.func_ea,
                    target_ea=target_ea,
                    is_write=False,
                    op_type=op_type,
                    const_val=None,
                    is_condition=self._cond_depth > 0,
                    loc=loc,
                    struct_name=struct_name,
                    member_offset=member_offset,
                )
            )

        # -- slot resolution ------------------------------------------------

        def _resolve_slot(
            self, expr: "ida_hexrays.cexpr_t"
        ) -> Optional[tuple]:
            """Return ``(struct_name, member_offset, target_ea)`` or *None*.

            For struct member accesses *target_ea* is 0 and *struct_name* /
            *member_offset* are populated.  For global variable accesses
            *struct_name* / *member_offset* are ``None`` and *target_ea* is
            the absolute EA.
            """
            if expr.op in (ida_hexrays.cot_memref, ida_hexrays.cot_memptr):
                return self._resolve_struct_member(expr)

            if expr.op == ida_hexrays.cot_obj:
                ea = expr.obj_ea
                if ea and ea != idaapi.BADADDR and _is_global_var(ea):
                    return (None, None, ea)

            if expr.op == ida_hexrays.cot_idx:
                base = expr.x
                if base:
                    return self._resolve_slot(base)

            if expr.op == ida_hexrays.cot_ptr:
                inner = expr.x
                if inner:
                    return self._resolve_slot(inner)

            return None

        def _resolve_struct_member(
            self, expr: "ida_hexrays.cexpr_t"
        ) -> Optional[tuple]:
            """Resolve a ``cot_memref`` / ``cot_memptr`` to struct info."""
            try:
                struct_expr = expr.x
                if struct_expr is None:
                    return None
                member_offset: int = expr.m  # byte offset from struct start

                # Obtain the type of the base expression
                tif = struct_expr.type
                if tif is None:
                    return None
                if tif.is_ptr():
                    tif = tif.get_pointed_object()
                if not tif.is_struct():
                    return None

                # Raw struct name straight from IDA (e.g. "struct _RECT")
                struct_name = tif.dstr()
                if not struct_name:
                    return None

                # Skip compiler-generated anonymous types
                if struct_name.startswith("$"):
                    return None

                return (struct_name, member_offset, 0)
            except Exception:
                return None

        # -- helpers --------------------------------------------------------

        @staticmethod
        def _read_op_label(expr: "ida_hexrays.cexpr_t") -> str:
            _map = {
                ida_hexrays.cot_memref: "MEMREF",
                ida_hexrays.cot_memptr: "MEMPTR",
                ida_hexrays.cot_obj: "OBJ",
                ida_hexrays.cot_idx: "IDX",
                ida_hexrays.cot_ptr: "PTR",
            }
            return _map.get(expr.op, "UNKNOWN")

        def _ea_to_rva(self, ea: Optional[int]) -> int:
            if ea is None or ea == idaapi.BADADDR:
                return 0
            return ea - self.base_addr


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extract_dataflow_with_hexrays(
    functions: List[RawFunction],
    base_addr: int,
) -> List[RawDataAccess]:
    """Analyse every *function* with Hex-Rays and return data-access DTOs.

    If Hex-Rays is not available or fails to initialise an empty list is
    returned so that the caller can fall back to assembly-level analysis.

    Args:
        functions: Functions extracted by :class:`ExtractionEngine`.
        base_addr: Image base address (used to compute RVAs for *loc*).

    Returns:
        A list of :class:`RawDataAccess` covering both global variable
        accesses **and** structure member accesses.
    """
    if not HEXRAYS_AVAILABLE:
        logger.debug("Hex-Rays not available; skipping dataflow analysis")
        return []

    if not _init_hexrays():
        logger.warning("Hex-Rays init failed; skipping dataflow analysis")
        return []

    accesses: List[RawDataAccess] = []
    decompiled = 0
    failures = 0

    for func in functions:
        # Skip library / thunk functions – they are irrelevant to the
        # project's own business logic and decompiling them is wasteful.
        if func.is_lib or func.is_thunk:
            continue

        try:
            cfunc = ida_hexrays.decompile(func.ea)
            if not cfunc:
                failures += 1
                continue

            visitor = _DataFlowVisitor(func.ea, base_addr)
            visitor.apply_to(cfunc.body, None)
            accesses.extend(visitor.get_accesses())
            decompiled += 1

        except ida_hexrays.DecompilationFailure:
            failures += 1
        except Exception as exc:
            failures += 1
            logger.debug(
                "Dataflow analysis failed at 0x%X: %s", func.ea, exc
            )

    logger.info(
        "Hex-Rays dataflow: decompiled=%d, failed=%d, accesses=%d "
        "(struct=%d, global=%d)",
        decompiled,
        failures,
        len(accesses),
        sum(1 for a in accesses if a.struct_name is not None),
        sum(1 for a in accesses if a.struct_name is None),
    )
    return accesses
