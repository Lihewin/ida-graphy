"""Raw data DTO definitions for extraction output.

These DTOs contain only raw addresses and names. IDs are computed later
by the mapping layer.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RawBinaryInfo:
    """Binary metadata."""

    name: str
    base_addr: int
    arch: str
    orig_name: str = ""
    compile_ts: int = 0


@dataclass
class RawFunction:
    """Function raw data."""

    ea: int
    name: str
    size: int
    flags: int
    is_lib: bool = False
    orig_name: str = ""
    signature: str = ""
    is_thunk: bool = False
    is_export: bool = False
    is_import: bool = False


@dataclass
class RawString:
    """String raw data."""

    ea: int
    content: str
    orig_content: str = ""
    encoding: str = "ASCII"


@dataclass
class RawGlobal:
    """Global variable raw data."""

    ea: int
    name: str
    size: int
    orig_name: str = ""


@dataclass
class RawStructMember:
    """Structure member raw data."""

    struct_name: str
    offset: int
    name: str
    size: int
    struct_orig_name: str = ""
    orig_name: str = ""


@dataclass
class RawCall:
    """Call relationship raw data."""

    caller_ea: int
    callee_ea: int
    call_addr: int
    call_type: str = "DIRECT"


@dataclass
class RawStringRef:
    """String reference raw data."""

    func_ea: int
    string_ea: int


@dataclass
class RawImport:
    """Import table entry raw data."""

    module: str
    name: str
    ea: int
    ida_name: str = ""


@dataclass
class RawDataAccess:
    """Data access (READS/WRITES) raw data."""

    func_ea: int
    target_ea: int
    is_write: bool
    op_type: str
    const_val: Optional[str] = None
    is_condition: bool = False
    loc: int = 0


@dataclass
class RawBinaryData:
    """Aggregated raw binary data container."""

    binary_info: Optional[RawBinaryInfo] = None
    functions: List[RawFunction] = field(default_factory=list)
    strings: List[RawString] = field(default_factory=list)
    globals: List[RawGlobal] = field(default_factory=list)
    struct_members: List[RawStructMember] = field(default_factory=list)
    calls: List[RawCall] = field(default_factory=list)
    string_refs: List[RawStringRef] = field(default_factory=list)
    imports: List[RawImport] = field(default_factory=list)
    data_accesses: List[RawDataAccess] = field(default_factory=list)
