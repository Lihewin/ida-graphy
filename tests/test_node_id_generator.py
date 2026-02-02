"""
Unit Tests for NodeIDGenerator

This module tests the ID generation logic to ensure:
1. IDs are generated correctly according to the specification
2. Cross-binary consistency for struct members
3. Binary-private scoping for functions and global variables
4. Hash format validation
"""

import unittest
import hashlib
from core.node_id_generator import NodeIDGenerator


class TestNodeIDGenerator(unittest.TestCase):
    """Test suite for NodeIDGenerator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create two generators with different binary hashes
        self.binary_content_1 = b"fake binary content 1"
        self.binary_content_2 = b"fake binary content 2"
        
        self.gen1 = NodeIDGenerator(binary_content=self.binary_content_1)
        self.gen2 = NodeIDGenerator(binary_content=self.binary_content_2)
        
        # Pre-computed hash for validation
        self.expected_hash_1 = hashlib.sha256(self.binary_content_1).hexdigest()
        self.expected_hash_2 = hashlib.sha256(self.binary_content_2).hexdigest()
    
    def test_initialization_with_content(self):
        """Test generator initialization with binary content."""
        gen = NodeIDGenerator(binary_content=b"test content")
        self.assertIsNotNone(gen.binary_hash)
        self.assertEqual(len(gen.binary_hash), 64)  # SHA256 = 64 hex chars
    
    def test_initialization_with_hash(self):
        """Test generator initialization with pre-computed hash."""
        test_hash = "a" * 64
        gen = NodeIDGenerator(binary_hash=test_hash)
        self.assertEqual(gen.binary_hash, test_hash)
    
    def test_initialization_requires_parameter(self):
        """Test that initialization fails without required parameters."""
        with self.assertRaises(ValueError):
            NodeIDGenerator()
    
    def test_binary_id_generation(self):
        """Test Binary node ID generation (SHA256)."""
        binary_id = self.gen1.get_binary_id()
        
        # Verify it's a valid SHA256 hash
        self.assertEqual(len(binary_id), 64)
        self.assertEqual(binary_id, self.expected_hash_1)
        self.assertTrue(all(c in '0123456789abcdef' for c in binary_id))
    
    def test_function_id_generation(self):
        """Test Function node ID generation."""
        rva = 0x1000
        func_id = self.gen1.get_function_id(rva)
        
        # Verify it's a valid MD5 hash
        self.assertEqual(len(func_id), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in func_id))
        
        # Verify it follows the correct format
        expected_input = f"{self.expected_hash_1}_1000"
        expected_id = hashlib.md5(expected_input.encode('utf-8')).hexdigest()
        self.assertEqual(func_id, expected_id)
    
    def test_function_id_binary_private(self):
        """Test that function IDs are binary-private (different for different binaries)."""
        rva = 0x1000
        func_id_1 = self.gen1.get_function_id(rva)
        func_id_2 = self.gen2.get_function_id(rva)
        
        # Same RVA in different binaries should produce different IDs
        self.assertNotEqual(func_id_1, func_id_2)
    
    def test_function_id_hex_format(self):
        """Test that RVA is converted to lowercase hex without 0x prefix."""
        rva = 0xABCD
        func_id = self.gen1.get_function_id(rva)
        
        # Verify the input string format
        expected_input = f"{self.expected_hash_1}_abcd"
        expected_id = hashlib.md5(expected_input.encode('utf-8')).hexdigest()
        self.assertEqual(func_id, expected_id)
    
    def test_struct_slot_id_generation(self):
        """Test DataSlot node ID generation for struct members."""
        struct_name = "SessionEntry"
        offset = 8
        
        slot_id = self.gen1.get_struct_slot_id(struct_name, offset)
        
        # Verify it's a valid MD5 hash
        self.assertEqual(len(slot_id), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in slot_id))
        
        # Verify it follows the correct format
        expected_input = f"{struct_name}_{offset}"
        expected_id = hashlib.md5(expected_input.encode('utf-8')).hexdigest()
        self.assertEqual(slot_id, expected_id)
    
    def test_struct_slot_id_cross_binary_consistency(self):
        """
        Test that struct member IDs are consistent across binaries.
        This is the CRITICAL feature for cross-component analysis.
        """
        struct_name = "RECT"
        offset = 0
        
        slot_id_1 = self.gen1.get_struct_slot_id(struct_name, offset)
        slot_id_2 = self.gen2.get_struct_slot_id(struct_name, offset)
        
        # Same struct member in different binaries should produce SAME ID
        self.assertEqual(slot_id_1, slot_id_2)
    
    def test_struct_slot_id_different_offsets(self):
        """Test that different offsets produce different IDs."""
        struct_name = "MyStruct"
        
        slot_id_1 = self.gen1.get_struct_slot_id(struct_name, 0)
        slot_id_2 = self.gen1.get_struct_slot_id(struct_name, 4)
        
        self.assertNotEqual(slot_id_1, slot_id_2)
    
    def test_global_slot_id_generation(self):
        """Test DataSlot node ID generation for global variables."""
        rva = 0x5000
        global_id = self.gen1.get_global_slot_id(rva)
        
        # Verify it's a valid MD5 hash
        self.assertEqual(len(global_id), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in global_id))
        
        # Verify it follows the correct format
        expected_input = f"{self.expected_hash_1}_GLOBAL_5000"
        expected_id = hashlib.md5(expected_input.encode('utf-8')).hexdigest()
        self.assertEqual(global_id, expected_id)
    
    def test_global_slot_id_binary_private(self):
        """Test that global variable IDs are binary-private."""
        rva = 0x5000
        global_id_1 = self.gen1.get_global_slot_id(rva)
        global_id_2 = self.gen2.get_global_slot_id(rva)
        
        # Same RVA in different binaries should produce different IDs
        self.assertNotEqual(global_id_1, global_id_2)
    
    def test_string_id_generation(self):
        """Test String node ID generation."""
        content = "Hello World"
        string_id = self.gen1.get_string_id(content)
        
        # Verify it's a valid MD5 hash
        self.assertEqual(len(string_id), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in string_id))
        
        # Verify it follows the correct format
        expected_id = hashlib.md5(content.encode('utf-8')).hexdigest()
        self.assertEqual(string_id, expected_id)
    
    def test_string_id_deduplication(self):
        """Test that identical strings produce the same ID across binaries."""
        content = "Error: Invalid parameter"
        
        string_id_1 = self.gen1.get_string_id(content)
        string_id_2 = self.gen2.get_string_id(content)
        
        # Same string in different binaries should produce SAME ID
        self.assertEqual(string_id_1, string_id_2)
    
    def test_string_id_different_content(self):
        """Test that different strings produce different IDs."""
        string_id_1 = self.gen1.get_string_id("String A")
        string_id_2 = self.gen1.get_string_id("String B")
        
        self.assertNotEqual(string_id_1, string_id_2)
    
    def test_id_uniqueness_within_same_binary(self):
        """Test that different node types with same numeric value produce different IDs."""
        rva = 0x1000
        
        func_id = self.gen1.get_function_id(rva)
        global_id = self.gen1.get_global_slot_id(rva)
        
        # Function and global variable at same RVA should have different IDs
        self.assertNotEqual(func_id, global_id)
    
    def test_real_world_scenario_kernel32(self):
        """
        Test a real-world scenario: Multiple binaries accessing RECT structure.
        
        Scenario:
            - user32.dll has a function that writes to RECT.left (offset 0)
            - app.exe has a function that reads from RECT.left (offset 0)
            - Both should converge to the same DataSlot node
        """
        # Simulate user32.dll
        gen_user32 = NodeIDGenerator(binary_hash="user32_hash" + "0" * 53)
        func_setwindowpos = gen_user32.get_function_id(0x2000)
        rect_left_id = gen_user32.get_struct_slot_id("RECT", 0)
        
        # Simulate app.exe
        gen_app = NodeIDGenerator(binary_hash="app_hash" + "0" * 56)
        func_mymain = gen_app.get_function_id(0x1000)
        rect_left_id_app = gen_app.get_struct_slot_id("RECT", 0)
        
        # Verify cross-binary consistency
        self.assertEqual(rect_left_id, rect_left_id_app)
        
        # Verify functions are different
        self.assertNotEqual(func_setwindowpos, func_mymain)
    
    def test_unicode_string_handling(self):
        """Test that Unicode strings are handled correctly."""
        unicode_content = "こんにちは世界"  # "Hello World" in Japanese
        
        string_id = self.gen1.get_string_id(unicode_content)
        
        # Verify it's a valid MD5 hash
        self.assertEqual(len(string_id), 32)
        
        # Verify consistency
        expected_id = hashlib.md5(unicode_content.encode('utf-8')).hexdigest()
        self.assertEqual(string_id, expected_id)
    
    def test_edge_case_zero_offset(self):
        """Test struct member at offset 0."""
        slot_id = self.gen1.get_struct_slot_id("MyStruct", 0)
        
        expected_input = "MyStruct_0"
        expected_id = hashlib.md5(expected_input.encode('utf-8')).hexdigest()
        self.assertEqual(slot_id, expected_id)
    
    def test_edge_case_large_rva(self):
        """Test function with large RVA."""
        large_rva = 0xFFFFFFFF
        func_id = self.gen1.get_function_id(large_rva)
        
        # Verify it's properly formatted
        expected_input = f"{self.expected_hash_1}_ffffffff"
        expected_id = hashlib.md5(expected_input.encode('utf-8')).hexdigest()
        self.assertEqual(func_id, expected_id)
    
    def test_md5_helper_function(self):
        """Test the internal _md5 helper function."""
        test_string = "test_input"
        result = self.gen1._md5(test_string)
        
        expected = hashlib.md5(test_string.encode('utf-8')).hexdigest()
        self.assertEqual(result, expected)


class TestIDGenerationPerformance(unittest.TestCase):
    """Performance tests for ID generation."""
    
    def test_generation_speed(self):
        """Test that ID generation is fast enough for large-scale processing."""
        import time
        
        gen = NodeIDGenerator(binary_hash="a" * 64)
        
        # Generate 10000 function IDs
        start = time.time()
        for i in range(10000):
            _ = gen.get_function_id(i * 0x100)
        elapsed = time.time() - start
        
        # Should complete in less than 1 second
        self.assertLess(elapsed, 1.0)
        print(f"\nGenerated 10000 function IDs in {elapsed:.4f} seconds")


if __name__ == '__main__':
    unittest.main(verbosity=2)
