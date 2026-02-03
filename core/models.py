"""
Data Models Module

This module defines the data classes for nodes and edges in the graph database.
All models use dataclasses for clean, type-safe representations of graph entities.

Node Types:
- BinaryNode: Represents an executable or dynamic library
- FunctionNode: Represents a code execution unit
- DataSlotNode: Represents struct members or global variables
- StringNode: Represents constant strings

Edge Types:
- ContainsEdge: Physical containment (Binary -> Function/DataSlot/String)
- CallsEdge: Control flow (Function -> Function)
- LinksToEdge: Dynamic linking (IMPORT -> EXPORT)
- ReferencesEdge: Semantic reference (Function -> String)
- WritesEdge: Data write operation (Function -> DataSlot)
- ReadsEdge: Data read operation (Function -> DataSlot)
"""

from dataclasses import dataclass, field
from typing import Optional, List, Literal, Dict
from datetime import datetime
import json
import os


# ============================================================================
# Node Definitions
# ============================================================================

@dataclass
class BinaryNode:
    """
    Binary node representing a physical file (executable or dynamic library).
    
    Label: :Binary
    ID Generation: SHA256(file_content)
    
    Attributes:
        hash: Primary key, globally unique identifier (SHA256)
        name: Filename (e.g., 'fw_engine.exe')
        base_addr: Load base address (e.g., 0x140000000) for RVA<->VA conversion
        arch: Architecture (e.g., 'x86_64', 'MIPS', 'ARM')
        compile_ts: Compilation timestamp for version tracking
    """
    hash: str
    name: str
    base_addr: int
    arch: str
    compile_ts: Optional[int] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'hash': self.hash,
            'name': self.name,
            'base_addr': self.base_addr,
            'arch': self.arch,
            'compile_ts': self.compile_ts or 0
        }


@dataclass
class FunctionNode:
    """
    Function node representing a code execution unit.
    
    Label: :Function
    ID Generation: MD5(binary_hash + "_" + rva_hex)
    
    Attributes:
        uid: Primary key, cross-binary unique identifier
        rva: Relative Virtual Address (function start RVA)
        name: Symbol name (e.g., 'Process_Packet') or 'sub_XXXX'
        size: Function length in bytes
        is_lib: AI filter flag - True if standard library function (to be ignored)
        func_type: Function classification - 'NORMAL', 'IMPORT', 'EXPORT', 'THUNK'
        signature: Function prototype (e.g., 'int func(void* ctx)')
        complexity: Cyclomatic complexity
        binary_id: [Redundant optimization] Hash of parent Binary for fast filtering
    """
    uid: str
    rva: int
    name: str
    binary_id: str
    size: int = 0
    is_lib: bool = False
    func_type: Literal['NORMAL', 'IMPORT', 'EXPORT', 'THUNK'] = 'NORMAL'
    signature: str = ''
    complexity: int = 0
    
    # File export references (added for file_exporter integration)
    decompiled_file: Optional[str] = None  # Relative path to .c file (e.g., 'exports/decompile/uid_name.c')
    pseudocode_hash: Optional[str] = None  # SHA256 hash for change detection
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'uid': self.uid,
            'rva': self.rva,
            'name': self.name,
            'size': self.size,
            'is_lib': self.is_lib,
            'func_type': self.func_type,
            'signature': self.signature,
            'complexity': self.complexity,
            'binary_id': self.binary_id,
            'decompiled_file': self.decompiled_file or '',
            'pseudocode_hash': self.pseudocode_hash or ''
        }


@dataclass
class DataSlotNode:
    """
    DataSlot node representing struct members or global variables.
    
    Label: :DataSlot
    ID Generation:
        - Struct: MD5(struct_name + "_" + offset_decimal) - cross-binary shared
        - Global: MD5(binary_hash + "_GLOBAL_" + rva_hex) - binary-private
    
    Attributes:
        uid: Primary key
        base_type: Structure name (e.g., 'SessionEntry') or 'GLOBAL'
        offset: Flattened absolute offset (decimal) for structs, or RVA for globals
        size: Data width (1, 2, 4, 8 bytes)
        name: Readable name (e.g., 'status', 'flags', 'g_Config')
        is_global: True for global variables, False for struct members
    """
    uid: str
    base_type: str
    offset: int
    size: int
    name: str
    is_global: bool
    
    # File export reference (for struct members only)
    struct_file: Optional[str] = None  # Relative path to .h file (e.g., 'exports/structures/StructName.h')
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'uid': self.uid,
            'base_type': self.base_type,
            'offset': self.offset,
            'size': self.size,
            'name': self.name,
            'is_global': self.is_global,
            'struct_file': self.struct_file or ''
        }


@dataclass
class StringNode:
    """
    String node representing constant strings (semantic anchors).
    
    Label: :String
    ID Generation: MD5(content)
    
    Attributes:
        hash: Primary key (MD5 of content)
        content: Actual string content (needs cleaning, remove garbage)
        encoding: Character encoding ('ASCII', 'UTF-16', etc.)
    """
    hash: str
    content: str
    encoding: str = 'ASCII'
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'hash': self.hash,
            'content': self.content,
            'encoding': self.encoding
        }


# ============================================================================
# Edge Definitions
# ============================================================================

@dataclass
class ContainsEdge:
    """
    CONTAINS edge - Physical containment relationship.
    
    Paths:
        - (:Binary) -[:CONTAINS]-> (:Function)
        - (:Binary) -[:CONTAINS]-> (:DataSlot {is_global:True})
        - (:Binary) -[:CONTAINS]-> (:String)
    
    Purpose: Maintains physical topology for module-level analysis.
    
    Attributes:
        from_id: Binary node hash
        to_id: Contained node ID (Function/DataSlot/String)
    """
    from_id: str
    to_id: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'from_id': self.from_id,
            'to_id': self.to_id
        }


@dataclass
class CallsEdge:
    """
    CALLS edge - Control flow relationship.
    
    Path: (:Function) -[:CALLS]-> (:Function)
    
    Attributes:
        from_id: Caller function UID
        to_id: Callee function UID
        call_type: 'DIRECT' (direct call), 'INDIRECT' (vtable/pointer), 'TAIL' (tail call)
        count: Number of times called (high frequency may indicate loops)
    """
    from_id: str
    to_id: str
    call_type: Literal['DIRECT', 'INDIRECT', 'TAIL'] = 'DIRECT'
    count: int = 1
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'from_id': self.from_id,
            'to_id': self.to_id,
            'type': self.call_type,
            'count': self.count
        }


@dataclass
class LinksToEdge:
    """
    LINKS_TO edge - Dynamic linking relationship.
    
    Path: (:Function {type:'IMPORT'}) -[:LINKS_TO]-> (:Function {type:'EXPORT'})
    
    Purpose: Stitches together logic across different binaries (IAT -> EAT).
    
    Attributes:
        from_id: IMPORT function UID
        to_id: EXPORT function UID (or virtual external ID before symbol resolution)
        dll_name: DLL name (e.g., "kernel32.dll") - for symbol resolution
        func_name: Function name (e.g., "CreateFileW") - for symbol resolution
    """
    from_id: str
    to_id: str
    dll_name: Optional[str] = None
    func_name: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'from_id': self.from_id,
            'to_id': self.to_id,
            'dll_name': self.dll_name,
            'func_name': self.func_name
        }


@dataclass
class ReferencesEdge:
    """
    REFERENCES edge - Semantic reference relationship.
    
    Path: (:Function) -[:REFERENCES]-> (:String)
    
    Purpose: Function uses this string (parameter reference or local reference).
    
    Attributes:
        from_id: Function UID
        to_id: String node hash
    """
    from_id: str
    to_id: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'from_id': self.from_id,
            'to_id': self.to_id
        }


@dataclass
class WritesEdge:
    """
    WRITES edge - Data write operation (CORE business flow).
    
    Path: (:Function) -[:WRITES]-> (:DataSlot)
    
    Definition: Function MODIFIES a state.
    
    Attributes:
        from_id: Function UID
        to_id: DataSlot UID
        op_type: Operation type - 'ASSIGN' (assignment), 'OR' (set bits),
                 'AND' (clear bits), 'ADD' (accumulation)
        const_val: **KEY**: Specific value written (e.g., '0x80', '1')
        loc: Instruction RVA where the operation occurs
    """
    from_id: str
    to_id: str
    op_type: Literal['ASSIGN', 'OR', 'AND', 'ADD']
    loc: int
    const_val: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'from_id': self.from_id,
            'to_id': self.to_id,
            'op_type': self.op_type,
            'const_val': self.const_val or '',
            'loc': self.loc
        }


@dataclass
class ReadsEdge:
    """
    READS edge - Data read operation (CORE business flow).
    
    Path: (:Function) -[:READS]-> (:DataSlot)
    
    Definition: Function USES a state.
    
    Attributes:
        from_id: Function UID
        to_id: DataSlot UID
        condition: **KEY**: True if read occurs in if/switch/loop (control flow dependency);
                   False if only used for data calculation or passing
        op_type: Operation type - 'CMP', 'TEST', 'MOV', etc.
        const_val: Constant value in comparison (e.g., '3' in 'if (state == 3)')
        loc: Instruction RVA where the operation occurs
    """
    from_id: str
    to_id: str
    condition: bool
    loc: int
    op_type: Optional[str] = None
    const_val: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for CSV export."""
        return {
            'from_id': self.from_id,
            'to_id': self.to_id,
            'condition': self.condition,
            'op_type': self.op_type or '',
            'const_val': self.const_val or '',
            'loc': self.loc
        }


# ============================================================================
# Helper Functions
# ============================================================================

def validate_node_id(node_id: str, expected_length: int = 32) -> bool:
    """
    Validate that a node ID is a valid hash string.
    
    Args:
        node_id: The ID to validate
        expected_length: Expected length (32 for MD5, 64 for SHA256)
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(node_id, str):
        return False
    if len(node_id) != expected_length:
        return False
    try:
        int(node_id, 16)  # Check if valid hex
        return True
    except ValueError:
        return False


# ============= 图数据容�?=============

@dataclass
class GraphData:
    """完整的图数据容器"""
    # 节点集合
    binaries: List[BinaryNode] = field(default_factory=list)
    functions: List[FunctionNode] = field(default_factory=list)
    dataslots: List[DataSlotNode] = field(default_factory=list)
    strings: List[StringNode] = field(default_factory=list)
    
    # 边集�?
    contains: List[ContainsEdge] = field(default_factory=list)
    calls: List[CallsEdge] = field(default_factory=list)
    links_to: List[LinksToEdge] = field(default_factory=list)
    references: List[ReferencesEdge] = field(default_factory=list)
    writes: List[WritesEdge] = field(default_factory=list)
    reads: List[ReadsEdge] = field(default_factory=list)    
    # 元数据（用于符号解析）
    binary_name: Optional[str] = None    
    def node_count(self):
        """返回总节点数"""
        return (len(self.binaries) + len(self.functions) + 
                len(self.dataslots) + len(self.strings))
    
    def edge_count(self):
        """返回总边数"""
        return (len(self.contains) + len(self.calls) + len(self.links_to) + 
                len(self.references) + len(self.writes) + len(self.reads))
    
    def merge(self, other: 'GraphData') -> None:
        """合并另一个GraphData对象到当前对象中
        
        Args:
            other: 要合并的GraphData对象
        """
        # 合并节点（避免重复）
        existing_binary_hashes = {b.hash for b in self.binaries}
        existing_function_uids = {f.uid for f in self.functions}
        existing_dataslot_uids = {d.uid for d in self.dataslots}
        existing_string_hashes = {s.hash for s in self.strings}
        
        # 添加新的节点
        for binary in other.binaries:
            if binary.hash not in existing_binary_hashes:
                self.binaries.append(binary)
                
        for function in other.functions:
            if function.uid not in existing_function_uids:
                self.functions.append(function)
                
        for dataslot in other.dataslots:
            if dataslot.uid not in existing_dataslot_uids:
                self.dataslots.append(dataslot)
                
        for string in other.strings:
            if string.hash not in existing_string_hashes:
                self.strings.append(string)
        
        # 合并边（避免重复）
        existing_contains = {(c.from_id, c.to_id) for c in self.contains}
        existing_calls = {(c.from_id, c.to_id, c.call_type) for c in self.calls}
        existing_links_to = {(l.from_id, l.to_id, l.dll_name, l.func_name) for l in self.links_to}
        existing_references = {(r.from_id, r.to_id) for r in self.references}
        existing_writes = {(w.from_id, w.to_id) for w in self.writes}
        existing_reads = {(r.from_id, r.to_id) for r in self.reads}
        
        for edge in other.contains:
            if (edge.from_id, edge.to_id) not in existing_contains:
                self.contains.append(edge)
                
        for edge in other.calls:
            key = (edge.from_id, edge.to_id, edge.call_type)
            if key not in existing_calls:
                self.calls.append(edge)
            else:
                # 如果已存在相同的调用，则累加计数
                for existing_call in self.calls:
                    if (existing_call.from_id == edge.from_id and 
                        existing_call.to_id == edge.to_id and 
                        existing_call.call_type == edge.call_type):
                        existing_call.count += edge.count
                        break
                
        for edge in other.links_to:
            key = (edge.from_id, edge.to_id, edge.dll_name, edge.func_name)
            if key not in existing_links_to:
                self.links_to.append(edge)
                
        for edge in other.references:
            if (edge.from_id, edge.to_id) not in existing_references:
                self.references.append(edge)
                
        for edge in other.writes:
            if (edge.from_id, edge.to_id) not in existing_writes:
                self.writes.append(edge)
                
        for edge in other.reads:
            if (edge.from_id, edge.to_id) not in existing_reads:
                self.reads.append(edge)


# ============================================================================
# Project Management Models (re-export for compatibility)
# ============================================================================

from core.project.metadata import BinaryFile, ProjectMetadata  # noqa: E402,F401
