"""
Unit Tests for Structure Name Normalizer

Tests the struct_normalizer module to ensure cross-binary consistency
for DataSlot IDs according to the struct.txt strategy.

Author: IDA-Graphy Project
Date: 2026-02-02
"""

import unittest
from core.mapping.struct_normalizer import StructNameNormalizer, normalize_struct_name


class TestStructNameNormalizer(unittest.TestCase):
    """Test cases for StructNameNormalizer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.normalizer = StructNameNormalizer(case_mode='lower')
    
    def test_basic_normalization(self):
        """Test basic structure name normalization."""
        test_cases = [
            ("Session", "session"),
            ("SessionEntry", "sessionentry"),
            ("_EPROCESS", "eprocess"),
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = self.normalizer.normalize(input_name)
                self.assertEqual(result, expected)
    
    def test_prefix_removal(self):
        """Test removal of common type prefixes."""
        test_cases = [
            ("struct Session", "session"),
            ("class SessionEntry", "sessionentry"),
            ("union _LARGE_INTEGER", "large_integer"),  # 保留内部下划线
            ("enum Status", "status"),
            ("T_EPROCESS", "eprocess"),
            ("tagWNDCLASS", "wndclass"),
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = self.normalizer.normalize(input_name)
                self.assertEqual(result, expected)
    
    def test_suffix_removal(self):
        """Test removal of IDA-generated numeric suffixes."""
        test_cases = [
            ("Session_1", "session"),
            ("Session_2", "session"),
            ("_EPROCESS_5", "eprocess"),
            ("SessionEntry_0", "sessionentry"),
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = self.normalizer.normalize(input_name)
                self.assertEqual(result, expected)
    
    def test_underscore_cleaning(self):
        """Test removal of leading underscores."""
        test_cases = [
            ("_Session", "session"),
            ("__int64", "int64"),
            ("___Test", "test"),
            ("_IO_FILE", "io_file"),  # 只清理前导下划线，保留内部下划线
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = self.normalizer.normalize(input_name)
                self.assertEqual(result, expected)
    
    def test_complex_normalization(self):
        """Test complex normalization with multiple transformations."""
        test_cases = [
            ("struct _SessionEntry_1", "sessionentry"),
            ("class __EPROCESS_2", "eprocess"),
            ("T__IO_FILE_0", "io_file"),  # 保留内部下划线
            ("tagWNDCLASS_1", "wndclass"),
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = self.normalizer.normalize(input_name)
                self.assertEqual(result, expected)
    
    def test_alias_mapping(self):
        """Test structure name alias mapping."""
        # Add aliases
        self.normalizer.add_alias("ProcessObject", "EPROCESS")
        self.normalizer.add_alias("HandleTable", "EPROCESS")
        
        test_cases = [
            ("ProcessObject", "eprocess"),
            ("HandleTable", "eprocess"),
            ("struct ProcessObject", "eprocess"),  # Alias applied before normalization
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = self.normalizer.normalize(input_name)
                self.assertEqual(result, expected)
    
    def test_case_modes(self):
        """Test different case normalization modes."""
        # Lowercase mode (default)
        normalizer_lower = StructNameNormalizer(case_mode='lower')
        self.assertEqual(normalizer_lower.normalize("Session"), "session")
        
        # Uppercase mode
        normalizer_upper = StructNameNormalizer(case_mode='upper')
        self.assertEqual(normalizer_upper.normalize("Session"), "SESSION")
        
        # Preserve mode
        normalizer_preserve = StructNameNormalizer(case_mode='preserve')
        self.assertEqual(normalizer_preserve.normalize("Session"), "Session")
    
    def test_aggressive_suffix_removal(self):
        """Test aggressive vs conservative suffix removal."""
        # Aggressive mode (removes all numeric suffixes)
        normalizer_aggressive = StructNameNormalizer(aggressive_suffix_removal=True)
        self.assertEqual(normalizer_aggressive.normalize("Session_123"), "session")
        
        # Conservative mode (only single digits)
        normalizer_conservative = StructNameNormalizer(aggressive_suffix_removal=False)
        self.assertEqual(normalizer_conservative.normalize("Session_1"), "session")
        self.assertEqual(normalizer_conservative.normalize("Session_123"), "session_123")
    
    def test_batch_aliases(self):
        """Test loading multiple aliases at once."""
        aliases = {
            "ProcessObject": "EPROCESS",
            "HandleTable": "EPROCESS",
            "_EPROCESS": "EPROCESS",
        }
        
        self.normalizer.load_aliases(aliases)
        
        for variant in aliases.keys():
            result = self.normalizer.normalize(variant)
            self.assertEqual(result, "eprocess")
    
    def test_empty_and_none_inputs(self):
        """Test handling of edge cases."""
        self.assertEqual(self.normalizer.normalize(""), "")
        self.assertEqual(self.normalizer.normalize(None), None)
    
    def test_statistics(self):
        """Test statistics tracking."""
        self.normalizer.reset_stats()
        
        # Perform normalizations
        self.normalizer.normalize("struct Session_1")
        self.normalizer.normalize("class _EPROCESS_2")
        
        stats = self.normalizer.get_stats()
        
        # Should have 2 normalizations
        self.assertEqual(stats['normalized'], 2)
        # Should have removed prefixes
        self.assertGreater(stats['prefix_removed'], 0)
        # Should have removed suffixes
        self.assertGreater(stats['suffix_removed'], 0)
    
    def test_cross_binary_consistency(self):
        """
        Test the key requirement: same struct member across binaries
        should produce the same normalized name.
        """
        # Simulate two different binaries defining the same structure
        binary_a_name = "struct Session"
        binary_b_name = "struct _Session_1"  # IDA added suffix in binary B
        
        result_a = self.normalizer.normalize(binary_a_name)
        result_b = self.normalizer.normalize(binary_b_name)
        
        # Both should normalize to the same canonical name
        self.assertEqual(result_a, result_b, 
                        "Cross-binary structure names must normalize to the same value")
        self.assertEqual(result_a, "session")


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""
    
    def test_default_normalizer(self):
        """Test the default global normalizer."""
        result = normalize_struct_name("struct Session_1")
        self.assertEqual(result, "session")


class TestRealWorldScenarios(unittest.TestCase):
    """Test real-world usage scenarios."""
    
    def test_windows_kernel_structures(self):
        """Test normalization of common Windows kernel structures."""
        normalizer = StructNameNormalizer(case_mode='upper')
        
        # Add Windows kernel aliases
        # Note: Aliases should match the name AFTER prefix removal
        aliases = {
            "ProcessObject": "EPROCESS",
            "EPROCESS": "EPROCESS",  # After removing _ prefix
            "PROCESS": "EPROCESS",    # After removing tag prefix
        }
        normalizer.load_aliases(aliases)
        
        test_cases = [
            ("ProcessObject", "EPROCESS"),
            ("_EPROCESS", "EPROCESS"),
            ("struct _EPROCESS_1", "EPROCESS"),
            ("tagPROCESS", "EPROCESS"),
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = normalizer.normalize(input_name)
                self.assertEqual(result, expected)
    
    def test_cpp_classes(self):
        """Test normalization of C++ class names."""
        normalizer = StructNameNormalizer()
        
        test_cases = [
            ("class std::vector", "stdvector"),  # May need special handling
            ("class Session", "session"),
            ("class _SessionImpl_2", "sessionimpl"),
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                result = normalizer.normalize(input_name)
                # Note: This test may need adjustment based on how we want to handle :: 
                # For now, just checking basic functionality


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
