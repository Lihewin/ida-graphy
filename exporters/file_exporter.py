"""
File Exporter - Export decompiled code, structures, and metadata to files.

This module exports IDA analysis results to human-readable files that can be
referenced from the graph database through file path attributes.
"""

import os
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from .artifact_utils import artifact_record, relative_artifact_path, sanitize_filename

try:
    import ida_hexrays
    import ida_funcs
    import ida_nalt
    import ida_typeinf
    import ida_entry
    import idautils
    import idc
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ExportResult:
    """Result of file export operation."""
    success_count: int
    failed_count: int
    file_mapping: Dict[str, Dict[str, str]]  # {uid: {'path': ..., 'hash': ...}}
    failed_items: List[Tuple[str, str]]  # [(uid, error_message)]
    artifacts: List[Dict[str, str]] = field(default_factory=list)


class FileExporter:
    """
    Export IDA analysis results to files with graph database integration.

    Exports include:
    - Decompiled C pseudocode (one file per function)
    - Structure definitions (.h files)
    - Strings table (strings.txt)
    - Import/Export tables (imports.txt, exports.txt)

    Each exported file is linked to graph nodes via relative file paths.
    """

    def __init__(self, output_dir: str, graph_data: Any, binary_name: str = None):
        """
        Initialize FileExporter.

        Args:
            output_dir: Base output directory (contains nodes/, edges/, exports/)
            graph_data: GraphData object with extracted nodes and edges
            binary_name: Binary filename (without path) for subdirectory organization
        """
        self.output_dir = output_dir
        self.graph_data = graph_data
        self.binary_name = binary_name or "default"
        self._callers_map: Optional[Dict[str, List[str]]] = None
        self._callees_map: Optional[Dict[str, List[str]]] = None

        # Create export directories with binary-specific subdirectory
        self.exports_dir = os.path.join(output_dir, 'exports', self.binary_name)
        self.decompile_dir = os.path.join(self.exports_dir, 'decompile')
        self.struct_dir = os.path.join(self.exports_dir, 'structures')

        os.makedirs(self.decompile_dir, exist_ok=True)
        os.makedirs(self.struct_dir, exist_ok=True)

        # Initialize Hex-Rays if available
        self.hexrays_available = False
        self._ensure_ida_imports()
        if IDA_AVAILABLE:
            try:
                if ida_hexrays.init_hexrays_plugin():
                    self.hexrays_available = True
                    logger.info("Hex-Rays decompiler initialized")
                else:
                    logger.warning("Hex-Rays plugin failed to initialize")
            except Exception as e:
                logger.warning(f"Hex-Rays not available: {e}")

    def _ensure_ida_imports(self) -> None:
        """Attempt to import IDA APIs after idalib is loaded."""
        global IDA_AVAILABLE
        if IDA_AVAILABLE:
            return

        try:
            global ida_hexrays
            global ida_funcs
            global ida_nalt
            global ida_typeinf
            global ida_entry
            global idautils
            global idc

            import ida_hexrays as _ida_hexrays
            import ida_funcs as _ida_funcs
            import ida_nalt as _ida_nalt
            import ida_typeinf as _ida_typeinf
            import ida_entry as _ida_entry
            import idautils as _idautils
            import idc as _idc

            ida_hexrays = _ida_hexrays
            ida_funcs = _ida_funcs
            ida_nalt = _ida_nalt
            ida_typeinf = _ida_typeinf
            ida_entry = _ida_entry
            idautils = _idautils
            idc = _idc

            IDA_AVAILABLE = True
        except ImportError:
            IDA_AVAILABLE = False

    def export_all(self) -> Dict[str, Any]:
        """
        Export all supported artifacts.

        Returns:
            Dictionary with export results for each category
        """
        results = {}

        # Export decompiled functions (P0)
        logger.info("Exporting decompiled functions...")
        results['functions'] = self.export_decompiled_functions()

        # Export structures (P1)
        logger.info("Exporting structure definitions...")
        results['structures'] = self.export_structures()

        # Export strings table (P1)
        logger.info("Exporting strings table...")
        results['strings'] = self.export_strings_table()

        # Export import/export tables (P1)
        logger.info("Exporting import/export tables...")
        results['imports'] = self.export_imports_table()
        results['exports'] = self.export_exports_table()

        return results

    def export_decompiled_functions(self) -> ExportResult:
        """
        Export decompiled C pseudocode for all functions.

        Returns:
            ExportResult with success/failure statistics and file mappings
        """
        if not self.hexrays_available:
            logger.warning("Hex-Rays not available, skipping decompilation export")
            return ExportResult(0, 0, {}, [])

        file_mapping = {}
        failed_items = []
        artifacts = []
        success_count = 0

        imagebase = ida_nalt.get_imagebase()

        self._prepare_call_indexes()
        ghidra_fallback_uids = {
            item.function_uid for item in getattr(self.graph_data, "ghidra_fallbacks", [])
        }

        for func_node in self.graph_data.functions:
            if func_node.func_type == "IMPORT":
                continue
            if func_node.uid in ghidra_fallback_uids:
                continue

            func_ea = imagebase + func_node.rva

            try:
                # Attempt decompilation
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    failed_items.append((func_node.uid, "Decompilation returned None"))
                    continue

                # Get pseudocode
                pseudocode = str(cfunc)

                # Compute hash for caching/change detection
                pseudocode_hash = hashlib.sha256(pseudocode.encode('utf-8')).hexdigest()

                # Get callers and callees from indexed graph data
                callers = self._get_callers_from_graph(func_node.uid)
                callees = self._get_callees_from_graph(func_node.uid)

                # Format file content with metadata header
                content = self._format_function_file(
                    func_node.name,
                    func_node.rva,
                    callers,
                    callees,
                    pseudocode
                )

                # Generate filename: <uid>_<sanitized_name>.c
                safe_name = sanitize_filename(func_node.name)
                filename = f"{func_node.uid}_{safe_name}.c"
                filepath = os.path.join(self.decompile_dir, filename)

                # Skip writing if content has not changed
                content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                if self._file_hash_matches(filepath, content_hash):
                    relative_path = relative_artifact_path(self.output_dir, filepath)
                    file_mapping[func_node.uid] = {
                        'path': relative_path,
                        'hash': pseudocode_hash
                    }
                    artifacts.append(
                        artifact_record(
                            self.output_dir,
                            owner_id=func_node.uid,
                            owner_type="Function",
                            artifact_type="decompile",
                            filepath=filepath,
                            content_hash=content_hash,
                        )
                    )
                    success_count += 1
                    continue

                # Write to file
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)

                # Track relative path from output_dir
                relative_path = relative_artifact_path(self.output_dir, filepath)
                file_mapping[func_node.uid] = {
                    'path': relative_path,
                    'hash': pseudocode_hash
                }
                artifacts.append(
                    artifact_record(
                        self.output_dir,
                        owner_id=func_node.uid,
                        owner_type="Function",
                        artifact_type="decompile",
                        filepath=filepath,
                        content_hash=content_hash,
                    )
                )

                success_count += 1

            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)}"
                failed_items.append((func_node.uid, error_msg))
                logger.debug(f"Failed to decompile {func_node.name} at 0x{func_node.rva:x}: {error_msg}")

        # Write failed log
        if failed_items:
            failed_log_path = self._write_failed_log(failed_items)
            for uid, error in failed_items:
                artifacts.append(
                    artifact_record(
                        self.output_dir,
                        owner_id=uid,
                        owner_type="Function",
                        artifact_type="decompile_failures",
                        filepath=failed_log_path,
                        status="failed",
                        error=error,
                    )
                )

        logger.info(f"Decompiled functions: {success_count} succeeded, {len(failed_items)} failed")
        if failed_items:
            samples = "; ".join(
                f"{uid}: {error}" for uid, error in failed_items[:16]
            )
            raise RuntimeError(
                "Hex-Rays failed to export decompiled pseudocode for meaningful functions; "
                f"failures={len(failed_items)}; samples={samples}"
            )

        return ExportResult(success_count, len(failed_items), file_mapping, failed_items, artifacts)

    def export_structures(self) -> ExportResult:
        """
        Export structure definitions to .h files.

        Returns:
            ExportResult with structure export statistics
        """
        if not IDA_AVAILABLE:
            return ExportResult(0, 0, {}, [])

        file_mapping = {}
        failed_items = []
        artifacts = []
        success_count = 0

        summary_path = os.path.join(self.struct_dir, '_all_structures.txt')
        summary_file = None

        try:
            # Get type information library
            til = ida_typeinf.get_idati()

            try:
                # Iterate through all named types (IDA 9.x API)
                for tif in til.named_types():
                    # Check if it's a structure or union
                    if not (tif.is_struct() or tif.is_union()):
                        continue

                    # Get type name
                    type_name = str(tif)
                    if not type_name:
                        continue

                    try:
                        # Get structure definition
                        struct_def = self._format_structure_definition(tif, type_name)

                        if struct_def:
                            # Write individual .h file
                            safe_name = sanitize_filename(type_name)
                            filename = f"{safe_name}.h"
                            filepath = os.path.join(self.struct_dir, filename)

                            with open(filepath, 'w', encoding='utf-8') as f:
                                f.write(struct_def)

                            if summary_file is None:
                                summary_file = open(summary_path, 'w', encoding='utf-8')
                                summary_file.write("=" * 80 + "\n")
                                summary_file.write("All Structure Definitions\n")
                                summary_file.write("=" * 80 + "\n\n")

                            summary_file.write(struct_def)
                            summary_file.write("\n\n")

                            relative_path = relative_artifact_path(self.output_dir, filepath)
                            struct_hash = hashlib.sha256(struct_def.encode('utf-8')).hexdigest()
                            file_mapping[type_name] = {
                                'path': relative_path,
                                'hash': struct_hash
                            }
                            artifacts.append(
                                artifact_record(
                                    self.output_dir,
                                    owner_id=type_name,
                                    owner_type="DataSlot",
                                    artifact_type="structure",
                                    filepath=filepath,
                                    content_hash=struct_hash,
                                )
                            )

                            success_count += 1

                    except Exception as e:
                        failed_items.append((type_name, str(e)))
            finally:
                if summary_file is not None:
                    summary_file.close()
                    artifacts.append(
                        artifact_record(
                            self.output_dir,
                            owner_id=self.binary_name,
                            owner_type="Binary",
                            artifact_type="structure_summary",
                            filepath=summary_path,
                        )
                    )

        except Exception as e:
            logger.error(f"Failed to export structures: {e}")

        logger.info(f"Exported structures: {success_count} succeeded, {len(failed_items)} failed")

        return ExportResult(success_count, len(failed_items), file_mapping, failed_items, artifacts)

    def export_strings_table(self) -> Optional[Dict[str, str]]:
        """
        Export strings table with addresses and metadata.

        Returns:
            Path to strings.txt file (relative to output_dir)
        """
        if not IDA_AVAILABLE:
            return None

        try:
            strings_path = os.path.join(self.exports_dir, 'strings.txt')

            with open(strings_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("String Table\n")
                f.write("=" * 80 + "\n")
                f.write("Format: address | length | encoding | content\n")
                f.write("-" * 80 + "\n\n")

                for string in idautils.Strings():
                    # Determine encoding
                    encoding = "ASCII"
                    if string.strtype == ida_nalt.STRTYPE_C_16:
                        encoding = "UTF-16"
                    elif string.strtype == ida_nalt.STRTYPE_C_32:
                        encoding = "UTF-32"

                    # Escape special characters
                    content = str(string).replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

                    # Write entry
                    f.write(f"0x{string.ea:x} | {string.length} | {encoding} | {content}\n")

            relative_path = relative_artifact_path(self.output_dir, strings_path)
            logger.info(f"Exported strings table: {relative_path}")
            return artifact_record(
                self.output_dir,
                owner_id=self.binary_name,
                owner_type="Binary",
                artifact_type="strings",
                filepath=strings_path,
            )

        except Exception as e:
            logger.error(f"Failed to export strings table: {e}")
            return None

    def export_imports_table(self) -> Optional[Dict[str, str]]:
        """
        Export import address table (IAT).

        Returns:
            Path to imports.txt file (relative to output_dir)
        """
        if not IDA_AVAILABLE:
            return None

        try:
            imports_path = os.path.join(self.exports_dir, 'imports.txt')

            with open(imports_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("Import Address Table (IAT)\n")
                f.write("=" * 80 + "\n")
                f.write("Format: module | function | address | ordinal\n")
                f.write("-" * 80 + "\n\n")

                nimps = ida_nalt.get_import_module_qty()

                for i in range(nimps):
                    module_name = ida_nalt.get_import_module_name(i)
                    f.write(f"\n[{module_name}]\n")

                    def callback(ea, name, ordinal):
                        f.write(f"  {name or '(no name)'} | 0x{ea:x} | {ordinal}\n")
                        return True

                    ida_nalt.enum_import_names(i, callback)

            relative_path = relative_artifact_path(self.output_dir, imports_path)
            logger.info(f"Exported imports table: {relative_path}")
            return artifact_record(
                self.output_dir,
                owner_id=self.binary_name,
                owner_type="Binary",
                artifact_type="imports",
                filepath=imports_path,
            )

        except Exception as e:
            logger.error(f"Failed to export imports table: {e}")
            return None

    def export_exports_table(self) -> Optional[Dict[str, str]]:
        """
        Export export address table (EAT).

        Returns:
            Path to exports.txt file (relative to output_dir)
        """
        if not IDA_AVAILABLE:
            return None

        try:
            exports_path = os.path.join(self.exports_dir, 'exports.txt')

            with open(exports_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("Export Address Table (EAT)\n")
                f.write("=" * 80 + "\n")
                f.write("Format: ordinal | address | name\n")
                f.write("-" * 80 + "\n\n")

                for i in range(ida_entry.get_entry_qty()):
                    ordinal = ida_entry.get_entry_ordinal(i)
                    ea = ida_entry.get_entry(ordinal)
                    name = ida_entry.get_entry_name(ordinal)

                    f.write(f"{ordinal} | 0x{ea:x} | {name}\n")

            relative_path = relative_artifact_path(self.output_dir, exports_path)
            logger.info(f"Exported exports table: {relative_path}")
            return artifact_record(
                self.output_dir,
                owner_id=self.binary_name,
                owner_type="Binary",
                artifact_type="exports",
                filepath=exports_path,
            )

        except Exception as e:
            logger.error(f"Failed to export exports table: {e}")
            return None

    def _get_callers_from_graph(self, func_uid: str) -> List[str]:
        """Get caller function names from CALLS edges."""
        if self._callers_map is not None:
            return self._callers_map.get(func_uid, [])
        callers = []
        for edge in self.graph_data.calls:
            if edge.to_id == func_uid:
                # Find caller function name
                for func in self.graph_data.functions:
                    if func.uid == edge.from_id:
                        callers.append(f"0x{func.rva:x} ({func.name})")
                        break
        return callers

    def _get_callees_from_graph(self, func_uid: str) -> List[str]:
        """Get callee function names from CALLS edges."""
        if self._callees_map is not None:
            return self._callees_map.get(func_uid, [])
        callees = []
        for edge in self.graph_data.calls:
            if edge.from_id == func_uid:
                # Find callee function name
                for func in self.graph_data.functions:
                    if func.uid == edge.to_id:
                        callees.append(f"0x{func.rva:x} ({func.name})")
                        break
        return callees

    def _format_function_file(self, name: str, rva: int, callers: List[str],
                              callees: List[str], pseudocode: str) -> str:
        """Format function file with metadata header."""
        lines = []
        lines.append("/*")
        lines.append(f" * Function: {name}")
        lines.append(f" * Address: 0x{rva:x}")
        lines.append(f" * Callers: {', '.join(callers) if callers else 'none'}")
        lines.append(f" * Callees: {', '.join(callees) if callees else 'none'}")
        lines.append(" */")
        lines.append("")
        lines.append(pseudocode)

        return '\n'.join(lines)

    def _prepare_call_indexes(self) -> None:
        """Build caller/callee indexes to avoid repeated scans."""
        func_index: Dict[str, Tuple[int, str]] = {
            func.uid: (func.rva, func.name) for func in self.graph_data.functions
        }
        callers_map: Dict[str, List[str]] = {}
        callees_map: Dict[str, List[str]] = {}

        for edge in self.graph_data.calls:
            caller = func_index.get(edge.from_id)
            callee = func_index.get(edge.to_id)
            if not caller or not callee:
                continue

            caller_text = f"0x{caller[0]:x} ({caller[1]})"
            callee_text = f"0x{callee[0]:x} ({callee[1]})"

            callers_map.setdefault(edge.to_id, []).append(caller_text)
            callees_map.setdefault(edge.from_id, []).append(callee_text)

        self._callers_map = callers_map
        self._callees_map = callees_map

    def _file_hash_matches(self, filepath: str, expected_hash: str) -> bool:
        """Check whether a file exists and its content hash matches expected."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            return hashlib.sha256(data).hexdigest() == expected_hash
        except FileNotFoundError:
            return False
        except Exception as e:
            logger.debug(f"Failed to read {filepath} for hash check: {e}")
            return False

    def _format_structure_definition(self, tif: Any, type_name: str) -> Optional[str]:
        """Format structure definition as C header using IDA 9.x generator API."""
        try:
            lines = []
            lines.append(f"// Structure: {type_name}")
            lines.append(f"// Size: {tif.get_size()} bytes")
            lines.append("")

            struct_keyword = "union" if tif.is_union() else "struct"
            lines.append(f"{struct_keyword} {type_name}")
            lines.append("{")

            # Use iterator API (IDA 9.x)
            for member in tif.iter_udt():
                member_type = str(member.type)
                member_name = member.name
                member_offset = member.offset // 8  # Convert bits to bytes
                member_size = member.size // 8

                lines.append(f"    {member_type} {member_name};  // offset: 0x{member_offset:x}, size: 0x{member_size:x}")

            lines.append("};")
            lines.append("")

            return '\n'.join(lines)

        except Exception as e:
            logger.debug(f"Failed to format structure {type_name}: {e}")
            return None

    def _write_failed_log(self, failed_items: List[Tuple[str, str]]) -> str:
        """Write failed decompilations to log file."""
        failed_log_path = os.path.join(self.decompile_dir, '_failed.txt')

        with open(failed_log_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("Failed Decompilations\n")
            f.write("=" * 80 + "\n\n")

            for uid, error in failed_items:
                f.write(f"UID: {uid}\n")
                f.write(f"Error: {error}\n")
                f.write("-" * 80 + "\n")

        return failed_log_path
