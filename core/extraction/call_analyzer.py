"""Call context analyzer using Hex-Rays ctree.

Extracts per-call-site context such as condition/loop presence and constant arguments.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from .raw_data import RawFunction

try:
    import ida_hexrays
    import ida_bytes
    import idaapi
    IDA_AVAILABLE = True
except ImportError:
    ida_hexrays = None
    ida_bytes = None
    idaapi = None
    IDA_AVAILABLE = False

logger = logging.getLogger("ida-graphy")


if IDA_AVAILABLE:
    class CallContextVisitor(ida_hexrays.ctree_parentee_t):
        """Collect call-site context from a function ctree."""

        def __init__(self):
            super().__init__(True)
            self.call_contexts: List[Dict[str, Any]] = []
            self.expr_count = 0
            self.call_count = 0
            self.call_index = 0
            self.insn_count = 0
            self.if_count = 0
            self.switch_count = 0
            self.loop_count = 0
            self.insn_op_counts: Dict[int, int] = {}

        def visit_expr(self, expr: "ida_hexrays.cexpr_t") -> int:
            self.expr_count += 1
            if expr.op == ida_hexrays.cot_call:
                self.call_count += 1
                self._handle_call(expr)
            return 0

        def visit_insn(self, insn: "ida_hexrays.cinsn_t") -> int:
            self.insn_count += 1
            self.insn_op_counts[insn.op] = self.insn_op_counts.get(insn.op, 0) + 1
            if insn.op == ida_hexrays.cit_if:
                self.if_count += 1
                return 0

            if insn.op == ida_hexrays.cit_switch:
                self.switch_count += 1
                return 0

            if insn.op in [ida_hexrays.cit_while, ida_hexrays.cit_do]:
                self.loop_count += 1
                return 0

            if insn.op == ida_hexrays.cit_for:
                self.loop_count += 1
                return 0

            return 0

        def _handle_call(self, expr: "ida_hexrays.cexpr_t") -> None:
            const_args: Dict[int, str] = {}
            for idx, arg in enumerate(expr.a):
                const_val = extract_const_value(arg)
                if const_val is not None:
                    const_args[idx] = const_val

            call_addr = self._normalize_call_ea(expr.ea)
            callee_ea = self._resolve_callee_ea(expr)

            return_used = False
            try:
                if expr.type and not expr.type.is_void():
                    return_used = True
            except Exception:
                return_used = False

            parent_ops = self._get_parent_ops()
            condition_ops = {
                ida_hexrays.cit_if,
                ida_hexrays.cit_switch,
                ida_hexrays.cit_while,
                ida_hexrays.cit_do,
                ida_hexrays.cit_for,
            }
            loop_ops = {ida_hexrays.cit_while, ida_hexrays.cit_do, ida_hexrays.cit_for}
            condition_expr_ops = {
                ida_hexrays.cot_tern,
                ida_hexrays.cot_lor,
                ida_hexrays.cot_land,
            }
            in_condition = any(op in condition_ops or op in condition_expr_ops for op in parent_ops)
            in_loop = any(op in loop_ops for op in parent_ops)
            loop_depth = 0
            seen_parents = set()
            parents = getattr(self, "parents", None) or []
            for item in parents:
                if not item:
                    continue
                item_id = id(item)
                if item_id in seen_parents:
                    continue
                seen_parents.add(item_id)
                op = getattr(item, "op", None)
                if op in loop_ops:
                    loop_depth += 1
            try:
                parent_insn = self.parent_insn()
                if parent_insn and id(parent_insn) not in seen_parents:
                    op = getattr(parent_insn, "op", None)
                    if op in loop_ops:
                        loop_depth += 1
            except Exception:
                pass

            seq_order = self.call_index
            self.call_index += 1
            self.call_contexts.append(
                {
                    "call_addr": call_addr,
                    "callee_ea": callee_ea,
                    "seq_order": seq_order,
                    "in_condition": in_condition,
                    "in_loop": in_loop,
                    "loop_depth": loop_depth,
                    "const_args": const_args,
                    "return_used": return_used,
                    "return_in_condition": in_condition,
                }
            )

        def _get_parent_ops(self) -> List[int]:
            ops: List[int] = []
            try:
                parents = getattr(self, "parents", None)
                if parents:
                    for item in parents:
                        op = getattr(item, "op", None)
                        if op is not None:
                            ops.append(op)
            except Exception:
                pass

            try:
                parent_insn = self.parent_insn()
                if parent_insn:
                    op = getattr(parent_insn, "op", None)
                    if op is not None:
                        ops.append(op)
            except Exception:
                pass

            return ops

        def _normalize_call_ea(self, ea: Optional[int]) -> Optional[int]:
            if ea is None:
                return None
            try:
                if idaapi and ea == idaapi.BADADDR:
                    return None
                if ida_bytes:
                    head = ida_bytes.get_item_head(ea)
                    if idaapi and head == idaapi.BADADDR:
                        return ea
                    return head
            except Exception:
                pass
            return ea

        def _resolve_callee_ea(self, expr: "ida_hexrays.cexpr_t") -> Optional[int]:
            try:
                callee = getattr(expr, "x", None)
                if not callee:
                    return None
                if callee.op == ida_hexrays.cot_obj:
                    ea = getattr(callee, "obj_ea", None)
                    if ea is not None and idaapi and ea != idaapi.BADADDR:
                        return ea
            except Exception:
                return None
            return None
else:
    class CallContextVisitor:
        """No-op visitor when Hex-Rays is unavailable."""

        def __init__(self):
            self.call_contexts = []
            self.expr_count = 0
            self.call_count = 0
            self.insn_count = 0
            self.if_count = 0
            self.switch_count = 0
            self.loop_count = 0
            self.insn_op_counts = {}


def analyze_call_context_cfunc(cfunc: Any) -> CallContextVisitor:
    """Run call-context analysis on an already decompiled function."""
    visitor = CallContextVisitor()
    visitor.apply_to(cfunc.body, None)
    return visitor


def merge_call_contexts(
    func_ea: int,
    call_contexts: List[Dict[str, Any]],
    contexts_by_addr: Dict[int, Dict[str, Any]],
    contexts_by_pair: Dict[Tuple[int, int], Dict[str, Any]],
    contexts_by_order: Dict[Tuple[int, int], Dict[str, Any]],
    contexts_by_callee: Dict[Tuple[int, int], List[Dict[str, Any]]],
) -> Tuple[int, int]:
    """Merge one function's call contexts into the shared lookup indexes."""
    call_addr_present = 0
    call_addr_missing = 0

    for call_ctx in call_contexts:
        call_addr = call_ctx.get("call_addr")
        if call_addr is not None:
            contexts_by_addr[call_addr] = call_ctx
            call_addr_present += 1
        else:
            call_addr_missing += 1

        callee_ea = call_ctx.get("callee_ea")
        if callee_ea is not None:
            contexts_by_pair[(func_ea, callee_ea)] = call_ctx
            contexts_by_callee.setdefault((func_ea, callee_ea), []).append(call_ctx)

        seq_order = call_ctx.get("seq_order")
        if seq_order is not None:
            contexts_by_order[(func_ea, seq_order)] = call_ctx

    return call_addr_present, call_addr_missing


def extract_call_contexts(
    functions: List[RawFunction],
) -> Tuple[
    Dict[int, Dict[str, Any]],
    Dict[Tuple[int, int], Dict[str, Any]],
    Dict[Tuple[int, int], Dict[str, Any]],
    Dict[Tuple[int, int], List[Dict[str, Any]]],
]:
    """Extract call-site context for each function.

    Returns dicts keyed by call address and (caller_ea, callee_ea).
    """
    if not IDA_AVAILABLE:
        logger.info("Hex-Rays not available; skipping call context analysis")
        return {}, {}, {}, {}

    try:
        if hasattr(ida_hexrays, "init_hexrays_plugin"):
            if not ida_hexrays.init_hexrays_plugin():
                logger.warning("Hex-Rays init failed; skipping call context analysis")
                return {}, {}, {}, {}
    except Exception as exc:
        logger.warning("Hex-Rays init exception: %s", exc)
        return {}, {}, {}, {}

    contexts_by_addr: Dict[int, Dict[str, Any]] = {}
    contexts_by_pair: Dict[Tuple[int, int], Dict[str, Any]] = {}
    contexts_by_order: Dict[Tuple[int, int], Dict[str, Any]] = {}
    contexts_by_callee: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}
    decompiled = 0
    decompile_failures = 0
    total_exprs = 0
    total_calls = 0
    total_insns = 0
    total_ifs = 0
    total_switches = 0
    total_loops = 0
    total_call_ctx = 0
    insn_op_counts: Dict[int, int] = {}
    call_addr_present = 0
    call_addr_missing = 0
    if IDA_AVAILABLE:
        op_names = [
            "cit_if",
            "cit_switch",
            "cit_while",
            "cit_do",
            "cit_for",
            "cit_block",
            "cit_expr",
            "cit_return",
        ]
        op_values = {name: getattr(ida_hexrays, name, None) for name in op_names}
        logger.debug("Call context op values: %s", op_values)
    for func in functions:
        try:
            cfunc = ida_hexrays.decompile(func.ea)
            if not cfunc:
                decompile_failures += 1
                continue
            decompiled += 1
            visitor = analyze_call_context_cfunc(cfunc)
            total_exprs += visitor.expr_count
            total_calls += visitor.call_count
            total_insns += visitor.insn_count
            total_ifs += visitor.if_count
            total_switches += visitor.switch_count
            total_loops += visitor.loop_count
            total_call_ctx += len(visitor.call_contexts)
            for op, count in visitor.insn_op_counts.items():
                insn_op_counts[op] = insn_op_counts.get(op, 0) + count
            present, missing = merge_call_contexts(
                func.ea,
                visitor.call_contexts,
                contexts_by_addr,
                contexts_by_pair,
                contexts_by_order,
                contexts_by_callee,
            )
            call_addr_present += present
            call_addr_missing += missing
        except Exception as exc:
            decompile_failures += 1
            logger.debug("Call context analysis failed at 0x%X: %s", func.ea, exc)
            continue

    logger.info(
        "Call context analysis: decompiled=%d, failed=%d, insns=%d, exprs=%d, calls=%d, ifs=%d, switches=%d, loops=%d, call_sites=%d",
        decompiled,
        decompile_failures,
        total_insns,
        total_exprs,
        total_calls,
        total_ifs,
        total_switches,
        total_loops,
        len(contexts_by_addr),
    )
    logger.debug("Call context entries: %d", total_call_ctx)
    logger.debug(
        "Call context addr availability: present=%d, missing=%d",
        call_addr_present,
        call_addr_missing,
    )
    if insn_op_counts:
        top_ops = sorted(insn_op_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        ops_summary = ", ".join(f"{op}:{count}" for op, count in top_ops)
        logger.debug("Call context insn ops: %s", ops_summary)
    return contexts_by_addr, contexts_by_pair, contexts_by_order, contexts_by_callee


def extract_const_value(expr: "ida_hexrays.cexpr_t") -> Any:
    """Extract constant values from a ctree expression."""
    if expr.op == ida_hexrays.cot_num:
        val = expr.numval()
        return hex(val) if val > 9 else str(val)

    if expr.op == ida_hexrays.cot_str:
        return f"\"{expr.string}\""

    if expr.op == ida_hexrays.cot_helper and hasattr(expr, "x") and expr.x:
        return extract_const_value(expr.x)

    return None
