"""Single-function Hex-Rays ctree harvesting.

This module decompiles each function once and immediately runs all ctree
visitors against the same ``cfunc``.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .call_analyzer import analyze_call_context_cfunc, merge_call_contexts
from .dataflow import analyze_dataflow_cfunc, init_hexrays
from .raw_data import RawDataAccess, RawFunction, RawGhidraFallback

try:
    import ida_hexrays
    import ida_bytes
    import ida_funcs
    import ida_segment
    import idaapi

    HEXRAYS_AVAILABLE = True
except ImportError:
    ida_hexrays = None
    ida_bytes = None
    ida_funcs = None
    ida_segment = None
    idaapi = None
    HEXRAYS_AVAILABLE = False

logger = logging.getLogger("ida-graphy")

STACK_FRAME_TOO_BIG = "stack frame is too big"
GHIDRA_FALLBACK_STACK_FRAME = "stack_frame_too_big"


@dataclass
class HexraysHarvestResult:
    """Derived ctree facts collected during one cfunc harvest pass."""

    contexts_by_addr: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    contexts_by_pair: Dict[Tuple[int, int], Dict[str, Any]] = field(default_factory=dict)
    contexts_by_order: Dict[Tuple[int, int], Dict[str, Any]] = field(default_factory=dict)
    contexts_by_callee: Dict[Tuple[int, int], List[Dict[str, Any]]] = field(default_factory=dict)
    data_accesses: List[RawDataAccess] = field(default_factory=list)
    processed_functions: Set[int] = field(default_factory=set)
    call_failures: int = 0
    dataflow_failures: int = 0
    total_exprs: int = 0
    total_calls: int = 0
    total_insns: int = 0
    total_ifs: int = 0
    total_switches: int = 0
    total_loops: int = 0
    total_call_ctx: int = 0
    call_addr_present: int = 0
    call_addr_missing: int = 0
    insn_op_counts: Dict[int, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    decompile_seconds: float = 0.0
    call_context_seconds: float = 0.0
    dataflow_seconds: float = 0.0
    attempted_decompiles: int = 0
    skipped_imports: int = 0
    skipped_external: int = 0
    skipped_no_body: int = 0
    skipped_thunks: int = 0
    skipped_samples: Dict[str, List[str]] = field(default_factory=dict)
    decompile_failures: int = 0
    decompile_failure_samples: List[str] = field(default_factory=list)
    ghidra_fallbacks: List[RawGhidraFallback] = field(default_factory=list)
    decompile_ok: bool = False

    def context_indexes(self):
        """Return context indexes in the shape expected by ``extract_calls``."""
        return (
            self.contexts_by_addr,
            self.contexts_by_pair,
            self.contexts_by_order,
            self.contexts_by_callee,
        )


def harvest_hexrays_ctree(
    functions: List[RawFunction],
    base_addr: int,
    enable_dataflow: bool = True,
) -> HexraysHarvestResult:
    """Decompile each function once and collect semantic facts from its ctree."""
    result = HexraysHarvestResult()

    if not HEXRAYS_AVAILABLE:
        raise RuntimeError("Hex-Rays is not available; ctree harvest cannot continue")

    if not init_hexrays():
        raise RuntimeError("Hex-Rays init failed; ctree harvest cannot continue")

    started = time.perf_counter()

    for index, func in enumerate(functions, 1):
        skip_reason = _skip_decompile_reason(func)
        if skip_reason:
            _record_skip(result, func, skip_reason)
            continue

        result.attempted_decompiles += 1
        hf = ida_hexrays.hexrays_failure_t()
        try:
            decompile_started = time.perf_counter()
            cfunc = ida_hexrays.decompile(func.ea, hf)
            result.decompile_seconds += time.perf_counter() - decompile_started
        except Exception as exc:
            result.decompile_seconds += time.perf_counter() - decompile_started
            _record_decompile_failure(result, func, f"{type(exc).__name__}: {exc}")
            logger.debug("Hex-Rays decompile failed at 0x%X: %s", func.ea, exc)
            continue

        if not cfunc:
            failure_desc = _hexrays_failure_desc(hf) or "decompile returned None"
            if _requires_ghidra_fallback(failure_desc):
                _record_ghidra_fallback(result, func, hf, failure_desc)
            else:
                _record_decompile_failure(result, func, failure_desc)
            continue

        _harvest_cfunc(func, cfunc, base_addr, enable_dataflow, result)
        processed_count = len(result.processed_functions)
        if processed_count == 1 or processed_count % 1000 == 0:
            logger.info(
                "Hex-Rays single-cfunc harvest progress: processed=%d/%d",
                processed_count,
                index,
            )

    result.elapsed_seconds = time.perf_counter() - started
    result.decompile_ok = bool(result.processed_functions)

    if not result.decompile_ok:
        raise RuntimeError(
            "Hex-Rays decompile did not produce ctree harvest results; "
            "refusing to continue without full ctree semantics"
        )

    _log_harvest_summary(result, len(functions))
    if result.decompile_failures:
        samples = "; ".join(result.decompile_failure_samples)
        raise RuntimeError(
            "Hex-Rays failed to decompile meaningful code functions; "
            f"failures={result.decompile_failures}; samples={samples}"
        )
    return result


def _skip_decompile_reason(func: RawFunction) -> Optional[str]:
    """Return a conservative reason to skip decompile, or None to attempt it."""
    func_obj = ida_funcs.get_func(func.ea) if ida_funcs else None
    seg = ida_segment.getseg(func.ea) if ida_segment else None

    if _is_external_or_import_segment(seg):
        if func.is_thunk:
            return "thunk"
        if func.is_import:
            return "import"
        return "external"

    if not _has_code_body(func, func_obj):
        if func.is_thunk:
            return "thunk"
        return "no_body"

    return None


def _is_external_or_import_segment(seg: Any) -> bool:
    if not seg or not ida_segment:
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


def _has_code_body(func: RawFunction, func_obj: Any) -> bool:
    if not func_obj:
        return False

    start_ea = int(getattr(func_obj, "start_ea", func.ea))
    end_ea = int(getattr(func_obj, "end_ea", func.ea))
    if end_ea <= start_ea:
        return False

    seg = ida_segment.getseg(start_ea) if ida_segment else None
    if not seg:
        return False

    try:
        if seg.type == ida_segment.SEG_XTRN:
            return False
    except Exception:
        pass

    if not ida_bytes:
        return bool(func.size > 0)

    ea = start_ea
    while ea < end_ea:
        try:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_code(flags):
                return True
            next_ea = ida_bytes.next_head(ea, end_ea)
        except Exception:
            return bool(func.size > 0)

        if idaapi and next_ea == idaapi.BADADDR:
            break
        if next_ea <= ea:
            break
        ea = next_ea

    return False


def _record_skip(result: HexraysHarvestResult, func: RawFunction, reason: str) -> None:
    if reason == "import":
        result.skipped_imports += 1
    elif reason == "external":
        result.skipped_external += 1
    elif reason == "no_body":
        result.skipped_no_body += 1
    elif reason == "thunk":
        result.skipped_thunks += 1

    samples = result.skipped_samples.setdefault(reason, [])
    if len(samples) < 8:
        samples.append(_format_skip_sample(func))


def _record_decompile_failure(result: HexraysHarvestResult, func: RawFunction, error: str) -> None:
    result.decompile_failures += 1
    if len(result.decompile_failure_samples) < 16:
        result.decompile_failure_samples.append(_format_failure_sample(func, error))


def _record_ghidra_fallback(
    result: HexraysHarvestResult,
    func: RawFunction,
    hf: Any,
    error: str,
) -> None:
    result.ghidra_fallbacks.append(
        RawGhidraFallback(
            ea=func.ea,
            name=func.name,
            size=func.size,
            reason=GHIDRA_FALLBACK_STACK_FRAME,
            error=error,
            failure_code=int(getattr(hf, "code", 0) or 0),
            failure_ea=int(getattr(hf, "errea", 0) or 0),
        )
    )


def _hexrays_failure_desc(hf: Any) -> str:
    try:
        return hf.desc() if hf else ""
    except Exception:
        return ""


def _requires_ghidra_fallback(failure_desc: str) -> bool:
    """Return True for Hex-Rays hard limits that Ghidra may supplement."""
    return failure_desc == STACK_FRAME_TOO_BIG


def _format_failure_sample(func: RawFunction, error: str) -> str:
    seg_name = "?"
    if ida_segment:
        try:
            seg = ida_segment.getseg(func.ea)
            if seg:
                seg_name = ida_segment.get_segm_name(seg)
        except Exception:
            pass

    return (
        f"0x{func.ea:X}:{func.name}:seg={seg_name}:"
        f"size={func.size}:export={int(func.is_export)}:"
        f"lib={int(func.is_lib)}:thunk={int(func.is_thunk)}:"
        f"import={int(func.is_import)}:error={error}"
    )


def _format_skip_sample(func: RawFunction) -> str:
    seg_name = "?"
    if ida_segment:
        try:
            seg = ida_segment.getseg(func.ea)
            if seg:
                seg_name = ida_segment.get_segm_name(seg)
        except Exception:
            pass

    return (
        f"0x{func.ea:X}:{func.name}:seg={seg_name}:"
        f"flags=0x{func.flags:X}:size={func.size}:"
        f"lib={int(func.is_lib)}:thunk={int(func.is_thunk)}:import={int(func.is_import)}"
    )


def _harvest_cfunc(
    func: RawFunction,
    cfunc: Any,
    base_addr: int,
    enable_dataflow: bool,
    result: HexraysHarvestResult,
) -> None:
    """Run all ctree visitors against one decompiled function."""
    func_ea = int(func.ea)
    if func_ea in result.processed_functions:
        return

    result.processed_functions.add(func_ea)

    try:
        call_started = time.perf_counter()
        visitor = analyze_call_context_cfunc(cfunc)
        result.total_exprs += visitor.expr_count
        result.total_calls += visitor.call_count
        result.total_insns += visitor.insn_count
        result.total_ifs += visitor.if_count
        result.total_switches += visitor.switch_count
        result.total_loops += visitor.loop_count
        result.total_call_ctx += len(visitor.call_contexts)
        for op, count in visitor.insn_op_counts.items():
            result.insn_op_counts[op] = result.insn_op_counts.get(op, 0) + count

        present, missing = merge_call_contexts(
            func_ea,
            visitor.call_contexts,
            result.contexts_by_addr,
            result.contexts_by_pair,
            result.contexts_by_order,
            result.contexts_by_callee,
        )
        result.call_addr_present += present
        result.call_addr_missing += missing
    except Exception as exc:
        result.call_failures += 1
        logger.debug("Hex-Rays harvest call context failed at 0x%X: %s", func_ea, exc)
    finally:
        result.call_context_seconds += time.perf_counter() - call_started

    if enable_dataflow and not (func.is_lib or func.is_thunk):
        try:
            dataflow_started = time.perf_counter()
            result.data_accesses.extend(
                analyze_dataflow_cfunc(func_ea, cfunc, base_addr)
            )
        except Exception as exc:
            result.dataflow_failures += 1
            logger.debug("Hex-Rays harvest dataflow failed at 0x%X: %s", func_ea, exc)
        finally:
            result.dataflow_seconds += time.perf_counter() - dataflow_started


def _log_harvest_summary(result: HexraysHarvestResult, function_count: int) -> None:
    skipped_total = (
        result.skipped_imports
        + result.skipped_external
        + result.skipped_no_body
        + result.skipped_thunks
    )
    logger.info(
        "Hex-Rays single-cfunc harvest: ok=%s processed=%d/%d elapsed=%.1fs "
        "attempted=%d skipped=%d decompile_failures=%d ghidra_fallbacks=%d "
        "call_ctx=%d accesses=%d call_failures=%d "
        "dataflow_failures=%d",
        result.decompile_ok,
        len(result.processed_functions),
        function_count,
        result.elapsed_seconds,
        result.attempted_decompiles,
        skipped_total,
        result.decompile_failures,
        len(result.ghidra_fallbacks),
        result.total_call_ctx,
        len(result.data_accesses),
        result.call_failures,
        result.dataflow_failures,
    )
    logger.info(
        "Hex-Rays single-cfunc timing: decompile=%.3fs call_context=%.3fs dataflow=%.3fs other=%.3fs",
        result.decompile_seconds,
        result.call_context_seconds,
        result.dataflow_seconds,
        max(
            result.elapsed_seconds
            - result.decompile_seconds
            - result.call_context_seconds
            - result.dataflow_seconds,
            0.0,
        ),
    )
    logger.info(
        "Hex-Rays decompile skips: imports=%d external=%d no_body=%d thunks=%d",
        result.skipped_imports,
        result.skipped_external,
        result.skipped_no_body,
        result.skipped_thunks,
    )
    for reason, samples in sorted(result.skipped_samples.items()):
        logger.debug("Hex-Rays skipped %s samples: %s", reason, "; ".join(samples))
    if result.ghidra_fallbacks:
        samples = "; ".join(
            f"0x{item.ea:X}:{item.name}:{item.reason}:{item.error}"
            for item in result.ghidra_fallbacks[:8]
        )
        logger.info("Hex-Rays Ghidra fallback queue samples: %s", samples)
    logger.info(
        "Call context analysis: decompiled=%d, not_decompiled=%d, insns=%d, exprs=%d, "
        "calls=%d, ifs=%d, switches=%d, loops=%d, call_sites=%d",
        len(result.processed_functions),
        max(function_count - len(result.processed_functions), 0),
        result.total_insns,
        result.total_exprs,
        result.total_calls,
        result.total_ifs,
        result.total_switches,
        result.total_loops,
        len(result.contexts_by_addr),
    )
    logger.debug("Call context entries: %d", result.total_call_ctx)
    logger.debug(
        "Call context addr availability: present=%d, missing=%d",
        result.call_addr_present,
        result.call_addr_missing,
    )
    if result.insn_op_counts:
        top_ops = sorted(result.insn_op_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        ops_summary = ", ".join(f"{op}:{count}" for op, count in top_ops)
        logger.debug("Call context insn ops: %s", ops_summary)
    logger.info(
        "Hex-Rays dataflow: decompiled=%d, failed=%d, accesses=%d "
        "(struct=%d, global=%d)",
        len(result.processed_functions),
        result.dataflow_failures,
        len(result.data_accesses),
        sum(1 for a in result.data_accesses if a.struct_name is not None),
        sum(1 for a in result.data_accesses if a.struct_name is None),
    )
