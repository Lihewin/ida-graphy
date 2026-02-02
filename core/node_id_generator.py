"""
Node ID Generator Module

This module provides the NodeIDGenerator class for generating consistent and unique
IDs for nodes in the graph database according to the strict hashing rules defined
in the project specification.

ID Generation Rules:
- Binary Node: SHA256(file_content)
- Function Node: MD5(binary_hash + "_" + rva_hex)
- DataSlot Node (Struct): MD5(struct_name + "_" + offset_decimal)
- DataSlot Node (Global): MD5(binary_hash + "_GLOBAL_" + rva_hex)
- String Node: MD5(content)
"""

import hashlib
from typing import Optional, Union


class NodeIDGenerator:
    """
    Generator for creating consistent node IDs across binary analysis runs.
    
    This class implements the strict hashing rules to ensure data consistency
    and cross-binary logical associations. All IDs are generated as hexadecimal
    strings in lowercase.
    
    Attributes:
        binary_hash (str): The SHA256 hash of the binary file content
    """
    
    def __init__(
        self,
        binary_content: Optional[bytes] = None,
        binary_hash: Optional[str] = None
    ):
        """
        Initialize the ID generator.
        
        Must provide either binary_content or binary_hash. If both are provided,
        binary_hash takes precedence.
        
        Args:
            binary_content: Raw binary file content as bytes
            binary_hash: Pre-computed SHA256 hash of the binary
            
        Raises:
            ValueError: If neither binary_content nor binary_hash is provided
        """
        if binary_hash:
            self.binary_hash = binary_hash
        elif binary_content:
            self.binary_hash = hashlib.sha256(binary_content).hexdigest()
        else:
            raise ValueError("Must provide binary_content or binary_hash")
    
    def _md5(self, s: str) -> str:
        """
        Helper function to compute MD5 hash of a string.
        
        Args:
            s: Input string to hash
            
        Returns:
            MD5 hash as a lowercase hexadecimal string
        """
        return hashlib.md5(s.encode('utf-8')).hexdigest()
    
    def get_binary_id(self) -> str:
        """
        Get the Binary node ID.
        
        Algorithm: SHA-256 of the complete binary file content.
        Scope: Global unique identifier for the binary file.
        
        Returns:
            SHA256 hash as a lowercase hexadecimal string
            
        Example:
            >>> gen = NodeIDGenerator(binary_hash="a1b2c3...")
            >>> gen.get_binary_id()
            'a1b2c3...'
        """
        return self.binary_hash
    
    def get_function_id(self, rva: int) -> str:
        """
        Get the Function node ID.
        
        Algorithm: MD5(binary_hash + "_" + rva_hex)
        Scope: Binary-private (different binaries with same RVA get different IDs)
        
        Args:
            rva: Relative Virtual Address of the function start
            
        Returns:
            MD5 hash as a lowercase hexadecimal string
            
        Example:
            >>> gen = NodeIDGenerator(binary_hash="a1b2c3...")
            >>> gen.get_function_id(0x1000)
            'fa3c...'  # MD5("a1b2c3..._1000")
        """
        # Convert RVA to lowercase hex without '0x' prefix
        rva_str = hex(rva)[2:].lower()
        return self._md5(f"{self.binary_hash}_{rva_str}")
    
    def get_struct_slot_id(self, struct_name: str, offset: int) -> str:
        """
        Get the DataSlot node ID for a structure member.
        
        Algorithm: MD5(struct_name + "_" + offset_decimal)
        Scope: Global (cross-binary shared for same struct member)
        
        This design allows different binaries accessing the same structure
        member to converge to the same node, enabling cross-component
        data flow tracking.
        
        Args:
            struct_name: Name of the structure (should be standardized)
            offset: Flattened absolute offset in bytes (decimal)
            
        Returns:
            MD5 hash as a lowercase hexadecimal string
            
        Example:
            >>> gen = NodeIDGenerator(binary_hash="a1b2c3...")
            >>> gen.get_struct_slot_id("SessionEntry", 8)
            '7d4e...'  # MD5("SessionEntry_8")
            
        Note:
            The ID does not include binary_hash, ensuring cross-binary consistency.
        """
        # Note: DataSlot ID for structures does NOT bind to binary_hash
        return self._md5(f"{struct_name}_{int(offset)}")
    
    def get_global_slot_id(self, rva: int) -> str:
        """
        Get the DataSlot node ID for a global variable.
        
        Algorithm: MD5(binary_hash + "_GLOBAL_" + rva_hex)
        Scope: Binary-private (global variables are physically bound to a binary)
        
        Args:
            rva: Relative Virtual Address of the global variable
            
        Returns:
            MD5 hash as a lowercase hexadecimal string
            
        Example:
            >>> gen = NodeIDGenerator(binary_hash="a1b2c3...")
            >>> gen.get_global_slot_id(0x5000)
            'b8f1...'  # MD5("a1b2c3..._GLOBAL_5000")
        """
        rva_str = hex(rva)[2:].lower()
        return self._md5(f"{self.binary_hash}_GLOBAL_{rva_str}")
    
    def get_string_id(self, content: str) -> str:
        """
        Get the String node ID.
        
        Algorithm: MD5(string_content)
        Scope: Global (same string in different binaries gets same ID)
        
        This enables deduplication of string constants across binaries.
        
        Args:
            content: The actual string content
            
        Returns:
            MD5 hash as a lowercase hexadecimal string
            
        Example:
            >>> gen = NodeIDGenerator(binary_hash="a1b2c3...")
            >>> gen.get_string_id("Hello World")
            '2ef7...'  # MD5("Hello World")
        """
        return self._md5(content)


# --- 使用示例 ---
if __name__ == "__main__":
    # 假设我们正在分析 kernel32.dll
    gen = NodeIDGenerator(binary_hash="a1b2c3d4e5f6...")
    
    # 1. 生成函数 ID (0x1000)
    func_id = gen.get_function_id(0x1000)
    print(f"Function Node ID: {func_id}")
    
    # 2. 生成结构体成员 ID (SessionEntry.status, offset 8)
    # 注意：即便在 user32.dll 中调用，生成的 ID 也是一样的，从而实现关联
    slot_id = gen.get_struct_slot_id("SessionEntry", 8)
    print(f"Struct Slot ID:   {slot_id}")
    
    # 3. 生成全局变量 ID
    global_id = gen.get_global_slot_id(0x5000)
    print(f"Global Slot ID:   {global_id}")
    
    # 4. 生成字符串 ID
    string_id = gen.get_string_id("Hello World")
    print(f"String Node ID:   {string_id}")
