"""
File Exporter - Export decompiled code, structures, and metadata to files.

This module exports IDA analysis results to human-readable files that can be
referenced from the Neo4j graph database through file path attributes.
"""

import os
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

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
        
        # Create export directories with binary-specific subdirectory
        self.exports_dir = os.path.join(output_dir, 'exports', self.binary_name)
        self.decompile_dir = os.path.join(self.exports_dir, 'decompile')
        self.struct_dir = os.path.join(self.exports_dir, 'structures')
        
        os.makedirs(self.decompile_dir, exist_ok=True)
        os.makedirs(self.struct_dir, exist_ok=True)
        
        # Initialize Hex-Rays if available
        self.hexrays_available = False
        if IDA_AVAILABLE:
            try:
                if ida_hexrays.init_hexrays_plugin():
                    self.hexrays_available = True
                    logger.info("Hex-Rays decompiler initialized")
                else:
                    logger.warning("Hex-Rays plugin failed to initialize")
            except Exception as e:
                logger.warning(f"Hex-Rays not available: {e}")
    
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
        success_count = 0
        
        imagebase = ida_nalt.get_imagebase()
        
        for func_node in self.graph_data.functions:
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
                
                # Get callers and callees from graph data
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
                safe_name = self._sanitize_filename(func_node.name)
                filename = f"{func_node.uid}_{safe_name}.c"
                filepath = os.path.join(self.decompile_dir, filename)
                
                # Write to file
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Track relative path from output_dir
                relative_path = os.path.relpath(filepath, self.output_dir).replace('\\', '/')
                file_mapping[func_node.uid] = {
                    'path': relative_path,
                    'hash': pseudocode_hash
                }
                
                success_count += 1
                
            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)}"
                failed_items.append((func_node.uid, error_msg))
                logger.debug(f"Failed to decompile {func_node.name} at 0x{func_node.rva:x}: {error_msg}")
        
        # Write failed log
        if failed_items:
            self._write_failed_log(failed_items)
        
        logger.info(f"Decompiled functions: {success_count} succeeded, {len(failed_items)} failed")
        
        return ExportResult(success_count, len(failed_items), file_mapping, failed_items)
    
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
        success_count = 0
        
        all_structs_content = []
        
        try:
            # Get type information library
            til = ida_typeinf.get_idati()
            
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
                        safe_name = self._sanitize_filename(type_name)
                        filename = f"{safe_name}.h"
                        filepath = os.path.join(self.struct_dir, filename)
                        
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(struct_def)
                        
                        # Add to summary
                        all_structs_content.append(struct_def)
                        
                        relative_path = os.path.relpath(filepath, self.output_dir).replace('\\', '/')
                        file_mapping[type_name] = {
                            'path': relative_path,
                            'hash': hashlib.sha256(struct_def.encode('utf-8')).hexdigest()
                        }
                        
                        success_count += 1
                
                except Exception as e:
                    failed_items.append((type_name, str(e)))
            
            # Write summary file
            if all_structs_content:
                summary_path = os.path.join(self.struct_dir, '_all_structures.txt')
                with open(summary_path, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write("All Structure Definitions\n")
                    f.write("=" * 80 + "\n\n")
                    f.write("\n\n".join(all_structs_content))
        
        except Exception as e:
            logger.error(f"Failed to export structures: {e}")
        
        logger.info(f"Exported structures: {success_count} succeeded, {len(failed_items)} failed")
        
        return ExportResult(success_count, len(failed_items), file_mapping, failed_items)
    
    def export_strings_table(self) -> Optional[str]:
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
            
            relative_path = os.path.relpath(strings_path, self.output_dir).replace('\\', '/')
            logger.info(f"Exported strings table: {relative_path}")
            return relative_path
        
        except Exception as e:
            logger.error(f"Failed to export strings table: {e}")
            return None
    
    def export_imports_table(self) -> Optional[str]:
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
            
            relative_path = os.path.relpath(imports_path, self.output_dir).replace('\\', '/')
            logger.info(f"Exported imports table: {relative_path}")
            return relative_path
        
        except Exception as e:
            logger.error(f"Failed to export imports table: {e}")
            return None
    
    def export_exports_table(self) -> Optional[str]:
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
            
            relative_path = os.path.relpath(exports_path, self.output_dir).replace('\\', '/')
            logger.info(f"Exported exports table: {relative_path}")
            return relative_path
        
        except Exception as e:
            logger.error(f"Failed to export exports table: {e}")
            return None
    
    def _get_callers_from_graph(self, func_uid: str) -> List[str]:
        """Get caller function names from CALLS edges."""
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
    
    def _sanitize_filename(self, name: str) -> str:
        """Sanitize function/type name for use as filename."""
        # Replace problematic characters
        replacements = {
            ':': '_',
            '/': '_',
            '\\': '_',
            '?': '_',
            '*': '_',
            '"': '_',
            '<': '_',
            '>': '_',
            '|': '_',
            ' ': '_'
        }
        
        sanitized = name
        for old, new in replacements.items():
            sanitized = sanitized.replace(old, new)
        
        # Truncate if too long
        if len(sanitized) > 100:
            sanitized = sanitized[:100]
        
        return sanitized
    
    def _write_failed_log(self, failed_items: List[Tuple[str, str]]):
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
