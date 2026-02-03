"""Node ID generator for graph mapping."""

import hashlib
from typing import Optional


class NodeIDGenerator:
    """Generator for creating consistent node IDs across binaries."""

    def __init__(self, binary_content: Optional[bytes] = None, binary_hash: Optional[str] = None):
        if binary_hash:
            self.binary_hash = binary_hash
        elif binary_content:
            self.binary_hash = hashlib.sha256(binary_content).hexdigest()
        else:
            raise ValueError("Must provide binary_content or binary_hash")

    def _md5(self, s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()

    def get_binary_id(self) -> str:
        return self.binary_hash

    def get_function_id(self, rva: int) -> str:
        rva_str = hex(rva)[2:].lower()
        return self._md5(f"{self.binary_hash}_{rva_str}")

    def get_struct_slot_id(self, struct_name: str, offset: int) -> str:
        return self._md5(f"{struct_name}_{int(offset)}")

    def get_global_slot_id(self, rva: int) -> str:
        rva_str = hex(rva)[2:].lower()
        return self._md5(f"{self.binary_hash}_GLOBAL_{rva_str}")

    def get_string_id(self, content: str) -> str:
        return self._md5(content)
