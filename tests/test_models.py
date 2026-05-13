"""
Unit Tests for Data Models

This module tests the data model classes to ensure:
1. Nodes and edges are properly instantiated
2. Data validation works correctly
3. Conversion to dictionary format is correct
4. Type safety is enforced
"""

import unittest
from core.models import (
    BinaryNode,
    FunctionNode,
    DataSlotNode,
    StringNode,
    ContainsEdge,
    EmbedsEdge,
    CallsEdge,
    LinksToEdge,
    ReferencesEdge,
    WritesEdge,
    ReadsEdge,
    validate_node_id
)
from core.mapping.id_generator import NodeIDGenerator


class TestNodeModels(unittest.TestCase):
    """Test suite for node data models."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.gen = NodeIDGenerator(binary_hash="a" * 64)
    
    def test_binary_node_creation(self):
        """Test BinaryNode instantiation."""
        binary = BinaryNode(
            hash=self.gen.get_binary_id(),
            name="test.exe",
            orig_name="test.exe",
            base_addr=0x140000000,
            arch="x86_64",
            compile_ts=1234567890,
        )
        
        self.assertEqual(binary.name, "test.exe")
        self.assertEqual(binary.base_addr, 0x140000000)
        self.assertEqual(binary.arch, "x86_64")
        self.assertEqual(binary.compile_ts, 1234567890)
    
    def test_binary_node_optional_compile_ts(self):
        """Test BinaryNode with optional compile_ts."""
        binary = BinaryNode(
            hash=self.gen.get_binary_id(),
            name="test.exe",
            base_addr=0x140000000,
            arch="x86_64"
        )
        
        self.assertIsNone(binary.compile_ts)
        
        # Check to_dict handles None correctly
        data = binary.to_dict()
        self.assertEqual(data['compile_ts'], 0)
    
    def test_binary_node_to_dict(self):
        """Test BinaryNode conversion to dictionary."""
        binary = BinaryNode(
            hash="test_hash",
            name="test.exe",
            orig_name="test.exe",
            base_addr=0x140000000,
            arch="x86_64",
            compile_ts=1234567890,
            export_manifest_file="exports/test.exe/_export_manifest.json",
            export_manifest_hash="manifest_hash",
        )
        
        data = binary.to_dict()
        
        self.assertEqual(data['hash'], "test_hash")
        self.assertEqual(data['name'], "test.exe")
        self.assertEqual(data['orig_name'], "test.exe")
        self.assertEqual(data['base_addr'], 0x140000000)
        self.assertEqual(data['arch'], "x86_64")
        self.assertEqual(data['compile_ts'], 1234567890)
        self.assertEqual(data['export_manifest_file'], "exports/test.exe/_export_manifest.json")
        self.assertEqual(data['export_manifest_hash'], "manifest_hash")
    
    def test_function_node_creation(self):
        """Test FunctionNode instantiation."""
        function = FunctionNode(
            uid=self.gen.get_function_id(0x1000),
            rva=0x1000,
            name="TestFunc",
            binary_id=self.gen.get_binary_id(),
            size=256,
            is_lib=False,
            func_type='NORMAL',
            signature='void TestFunc(int)',
            complexity=5
        )
        
        self.assertEqual(function.rva, 0x1000)
        self.assertEqual(function.name, "TestFunc")
        self.assertEqual(function.size, 256)
        self.assertEqual(function.func_type, 'NORMAL')
    
    def test_function_node_default_values(self):
        """Test FunctionNode with default values."""
        function = FunctionNode(
            uid=self.gen.get_function_id(0x1000),
            rva=0x1000,
            name="TestFunc",
            binary_id=self.gen.get_binary_id()
        )
        
        self.assertEqual(function.size, 0)
        self.assertFalse(function.is_lib)
        self.assertEqual(function.func_type, 'NORMAL')
        self.assertEqual(function.signature, '')
        self.assertEqual(function.complexity, 0)
    
    def test_function_node_func_types(self):
        """Test FunctionNode with different func_types."""
        func_types = ['NORMAL', 'IMPORT', 'EXPORT', 'THUNK']
        
        for ftype in func_types:
            function = FunctionNode(
                uid=self.gen.get_function_id(0x1000),
                rva=0x1000,
                name=f"Func_{ftype}",
                binary_id=self.gen.get_binary_id(),
                func_type=ftype
            )
            self.assertEqual(function.func_type, ftype)
    
    def test_function_node_to_dict(self):
        """Test FunctionNode conversion to dictionary."""
        function = FunctionNode(
            uid="test_uid",
            rva=0x1000,
            name="TestFunc",
            orig_name="TestFunc",
            binary_id="test_binary",
            size=256,
            is_lib=True,
            func_type='EXPORT',
            signature='int TestFunc(void)',
            complexity=3
        )
        
        data = function.to_dict()
        
        self.assertEqual(data['uid'], "test_uid")
        self.assertEqual(data['rva'], 0x1000)
        self.assertEqual(data['name'], "TestFunc")
        self.assertEqual(data['orig_name'], "TestFunc")
        self.assertEqual(data['binary_id'], "test_binary")
        self.assertEqual(data['size'], 256)
        self.assertTrue(data['is_lib'])
        self.assertEqual(data['func_type'], 'EXPORT')
    
    def test_dataslot_node_struct_member(self):
        """Test DataSlotNode for struct member."""
        dataslot = DataSlotNode(
            uid=self.gen.get_struct_slot_id("RECT", 0),
            base_type="RECT",
            base_type_orig="RECT",
            offset=0,
            size=4,
            name="left",
            orig_name="left",
            is_global=False
        )
        
        self.assertEqual(dataslot.base_type, "RECT")
        self.assertEqual(dataslot.offset, 0)
        self.assertFalse(dataslot.is_global)
    
    def test_dataslot_node_global_variable(self):
        """Test DataSlotNode for global variable."""
        dataslot = DataSlotNode(
            uid=self.gen.get_global_slot_id(0x5000),
            base_type="GLOBAL",
            base_type_orig="GLOBAL",
            offset=0x5000,
            size=8,
            name="g_Config",
            orig_name="g_Config",
            is_global=True
        )
        
        self.assertEqual(dataslot.base_type, "GLOBAL")
        self.assertTrue(dataslot.is_global)
    
    def test_dataslot_node_to_dict(self):
        """Test DataSlotNode conversion to dictionary."""
        dataslot = DataSlotNode(
            uid="test_uid",
            base_type="MyStruct",
            base_type_orig="MyStruct",
            offset=8,
            size=4,
            name="field",
            orig_name="field",
            is_global=False
        )
        
        data = dataslot.to_dict()
        
        self.assertEqual(data['uid'], "test_uid")
        self.assertEqual(data['base_type'], "MyStruct")
        self.assertEqual(data['base_type_orig'], "MyStruct")
        self.assertEqual(data['offset'], 8)
        self.assertEqual(data['size'], 4)
        self.assertEqual(data['name'], "field")
        self.assertEqual(data['orig_name'], "field")
        self.assertFalse(data['is_global'])
    
    def test_string_node_creation(self):
        """Test StringNode instantiation."""
        string = StringNode(
            hash=self.gen.get_string_id("Hello"),
            content="Hello",
            encoding="ASCII"
        )
        
        self.assertEqual(string.content, "Hello")
        self.assertEqual(string.encoding, "ASCII")
    
    def test_string_node_unicode(self):
        """Test StringNode with Unicode content."""
        unicode_str = "こんにちは"
        string = StringNode(
            hash=self.gen.get_string_id(unicode_str),
            content=unicode_str,
            encoding="UTF-8"
        )
        
        self.assertEqual(string.content, unicode_str)
        self.assertEqual(string.encoding, "UTF-8")
    
    def test_string_node_to_dict(self):
        """Test StringNode conversion to dictionary."""
        string = StringNode(
            hash="test_hash",
            content="Test String",
            orig_name="Test String",
            encoding="ASCII"
        )
        
        data = string.to_dict()
        
        self.assertEqual(data['hash'], "test_hash")
        self.assertEqual(data['content'], "Test String")
        self.assertEqual(data['orig_name'], "Test String")
        self.assertEqual(data['encoding'], "ASCII")


class TestEdgeModels(unittest.TestCase):
    """Test suite for edge data models."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.gen = NodeIDGenerator(binary_hash="a" * 64)
        self.binary_id = self.gen.get_binary_id()
        self.func_id = self.gen.get_function_id(0x1000)
        self.slot_id = self.gen.get_struct_slot_id("RECT", 0)
    
    def test_contains_edge_creation(self):
        """Test ContainsEdge instantiation."""
        edge = ContainsEdge(
            from_id=self.binary_id,
            to_id=self.func_id
        )
        
        self.assertEqual(edge.from_id, self.binary_id)
        self.assertEqual(edge.to_id, self.func_id)
    
    def test_contains_edge_to_dict(self):
        """Test ContainsEdge conversion to dictionary."""
        edge = ContainsEdge(
            from_id="from_test",
            to_id="to_test"
        )
        
        data = edge.to_dict()
        
        self.assertEqual(data['from_id'], "from_test")
        self.assertEqual(data['to_id'], "to_test")

    def test_embeds_edge_creation(self):
        """Test EmbedsEdge instantiation."""
        root_id = self.gen.get_struct_slot_id("RECT", -1)
        member_id = self.gen.get_struct_slot_id("RECT", 0)

        edge = EmbedsEdge(
            from_id=root_id,
            to_id=member_id
        )

        self.assertEqual(edge.from_id, root_id)
        self.assertEqual(edge.to_id, member_id)
    
    def test_calls_edge_creation(self):
        """Test CallsEdge instantiation."""
        caller_id = self.gen.get_function_id(0x1000)
        callee_id = self.gen.get_function_id(0x2000)
        
        edge = CallsEdge(
            from_id=caller_id,
            to_id=callee_id,
            call_type='DIRECT',
            count=5,
            loc=0x1200,
            seq_order=3,
            in_condition=True,
            in_loop=False,
            const_args='{"0":"0x1"}',
            return_used=True,
            return_in_condition=True,
        )
        
        self.assertEqual(edge.call_type, 'DIRECT')
        self.assertEqual(edge.count, 5)
        self.assertEqual(edge.loc, 0x1200)
        self.assertEqual(edge.seq_order, 3)
        self.assertTrue(edge.in_condition)
        self.assertTrue(edge.return_used)
    
    def test_calls_edge_call_types(self):
        """Test CallsEdge with different call types."""
        caller_id = self.gen.get_function_id(0x1000)
        callee_id = self.gen.get_function_id(0x2000)
        
        call_types = ['DIRECT', 'INDIRECT', 'TAIL']
        
        for ctype in call_types:
            edge = CallsEdge(
                from_id=caller_id,
                to_id=callee_id,
                call_type=ctype
            )
            self.assertEqual(edge.call_type, ctype)
    
    def test_calls_edge_to_dict(self):
        """Test CallsEdge conversion to dictionary."""
        edge = CallsEdge(
            from_id="func1",
            to_id="func2",
            call_type='INDIRECT',
            count=3,
            loc=0x2000,
            seq_order=4,
            in_condition=False,
            in_loop=True,
            const_args='{"1":"\"path\""}',
            return_used=False,
            return_in_condition=False,
        )
        
        data = edge.to_dict()
        
        self.assertEqual(data['from_id'], "func1")
        self.assertEqual(data['to_id'], "func2")
        self.assertEqual(data['type'], 'INDIRECT')
        self.assertEqual(data['count'], 3)
        self.assertEqual(data['loc'], 0x2000)
        self.assertEqual(data['seq_order'], 4)
        self.assertFalse(data['in_condition'])
        self.assertTrue(data['in_loop'])
    
    def test_links_to_edge_creation(self):
        """Test LinksToEdge instantiation."""
        import_id = self.gen.get_function_id(0x1000)
        export_id = self.gen.get_function_id(0x2000)
        
        edge = LinksToEdge(
            from_id=import_id,
            to_id=export_id
        )
        
        self.assertEqual(edge.from_id, import_id)
        self.assertEqual(edge.to_id, export_id)
    
    def test_references_edge_creation(self):
        """Test ReferencesEdge instantiation."""
        func_id = self.gen.get_function_id(0x1000)
        string_id = self.gen.get_string_id("Error message")
        
        edge = ReferencesEdge(
            from_id=func_id,
            to_id=string_id
        )
        
        self.assertEqual(edge.from_id, func_id)
        self.assertEqual(edge.to_id, string_id)
    
    def test_writes_edge_creation(self):
        """Test WritesEdge instantiation."""
        func_id = self.gen.get_function_id(0x1000)
        slot_id = self.gen.get_struct_slot_id("Session", 8)
        
        edge = WritesEdge(
            from_id=func_id,
            to_id=slot_id,
            op_type='ASSIGN',
            const_val='0x80',
            loc=0x1010
        )
        
        self.assertEqual(edge.op_type, 'ASSIGN')
        self.assertEqual(edge.const_val, '0x80')
        self.assertEqual(edge.loc, 0x1010)
    
    def test_writes_edge_op_types(self):
        """Test WritesEdge with different operation types."""
        func_id = self.gen.get_function_id(0x1000)
        slot_id = self.gen.get_struct_slot_id("Session", 8)
        
        op_types = ['ASSIGN', 'OR', 'AND', 'ADD']
        
        for op in op_types:
            edge = WritesEdge(
                from_id=func_id,
                to_id=slot_id,
                op_type=op,
                loc=0x1000
            )
            self.assertEqual(edge.op_type, op)
    
    def test_writes_edge_to_dict(self):
        """Test WritesEdge conversion to dictionary."""
        edge = WritesEdge(
            from_id="func1",
            to_id="slot1",
            op_type='OR',
            const_val='0xFF',
            loc=0x2000
        )
        
        data = edge.to_dict()
        
        self.assertEqual(data['from_id'], "func1")
        self.assertEqual(data['to_id'], "slot1")
        self.assertEqual(data['op_type'], 'OR')
        self.assertEqual(data['const_val'], '0xFF')
        self.assertEqual(data['loc'], 0x2000)
    
    def test_writes_edge_optional_const_val(self):
        """Test WritesEdge with optional const_val."""
        edge = WritesEdge(
            from_id="func1",
            to_id="slot1",
            op_type='ASSIGN',
            loc=0x1000
        )
        
        data = edge.to_dict()
        self.assertEqual(data['const_val'], '')
    
    def test_reads_edge_creation(self):
        """Test ReadsEdge instantiation."""
        func_id = self.gen.get_function_id(0x1000)
        slot_id = self.gen.get_struct_slot_id("Session", 8)
        
        edge = ReadsEdge(
            from_id=func_id,
            to_id=slot_id,
            condition=True,
            op_type='CMP',
            const_val='3',
            loc=0x1010
        )
        
        self.assertTrue(edge.condition)
        self.assertEqual(edge.op_type, 'CMP')
        self.assertEqual(edge.const_val, '3')
    
    def test_reads_edge_condition_flag(self):
        """Test ReadsEdge with condition flag."""
        func_id = self.gen.get_function_id(0x1000)
        slot_id = self.gen.get_struct_slot_id("Session", 8)
        
        # Read in conditional statement
        edge_conditional = ReadsEdge(
            from_id=func_id,
            to_id=slot_id,
            condition=True,
            loc=0x1010
        )
        self.assertTrue(edge_conditional.condition)
        
        # Read in non-conditional statement
        edge_non_conditional = ReadsEdge(
            from_id=func_id,
            to_id=slot_id,
            condition=False,
            loc=0x1010
        )
        self.assertFalse(edge_non_conditional.condition)
    
    def test_reads_edge_to_dict(self):
        """Test ReadsEdge conversion to dictionary."""
        edge = ReadsEdge(
            from_id="func1",
            to_id="slot1",
            condition=True,
            op_type='TEST',
            const_val='0',
            loc=0x1000
        )
        
        data = edge.to_dict()
        
        self.assertEqual(data['from_id'], "func1")
        self.assertEqual(data['to_id'], "slot1")
        self.assertTrue(data['condition'])
        self.assertEqual(data['op_type'], 'TEST')
        self.assertEqual(data['const_val'], '0')


class TestValidationHelpers(unittest.TestCase):
    """Test suite for validation helper functions."""
    
    def test_validate_node_id_md5(self):
        """Test validation of MD5 hashes."""
        valid_md5 = "5d41402abc4b2a76b9719d911017c592"
        self.assertTrue(validate_node_id(valid_md5, 32))
    
    def test_validate_node_id_sha256(self):
        """Test validation of SHA256 hashes."""
        valid_sha256 = "a" * 64
        self.assertTrue(validate_node_id(valid_sha256, 64))
    
    def test_validate_node_id_invalid_length(self):
        """Test validation fails for incorrect length."""
        invalid = "abc123"
        self.assertFalse(validate_node_id(invalid, 32))
    
    def test_validate_node_id_invalid_characters(self):
        """Test validation fails for non-hex characters."""
        invalid = "g" * 32  # 'g' is not a hex digit
        self.assertFalse(validate_node_id(invalid, 32))
    
    def test_validate_node_id_invalid_type(self):
        """Test validation fails for non-string input."""
        self.assertFalse(validate_node_id(123, 32))
        self.assertFalse(validate_node_id(None, 32))


class TestModelIntegration(unittest.TestCase):
    """Integration tests combining models with ID generator."""
    
    def test_complete_graph_creation(self):
        """Test creating a complete graph with nodes and edges."""
        # Create ID generator
        gen = NodeIDGenerator(binary_hash="a" * 64)
        
        # Create nodes
        binary = BinaryNode(
            hash=gen.get_binary_id(),
            name="test.exe",
            orig_name="test.exe",
            base_addr=0x140000000,
            arch="x86_64"
        )
        
        function = FunctionNode(
            uid=gen.get_function_id(0x1000),
            rva=0x1000,
            name="main",
            orig_name="main",
            binary_id=binary.hash,
            func_type='NORMAL'
        )
        
        dataslot = DataSlotNode(
            uid=gen.get_struct_slot_id("Config", 0),
            base_type="Config",
            base_type_orig="Config",
            offset=0,
            size=4,
            name="flags",
            orig_name="flags",
            is_global=False
        )
        
        string = StringNode(
            hash=gen.get_string_id("Hello"),
            content="Hello",
            orig_name="Hello",
            encoding="ASCII"
        )
        
        # Create edges
        contains_func = ContainsEdge(
            from_id=binary.hash,
            to_id=function.uid
        )
        
        writes = WritesEdge(
            from_id=function.uid,
            to_id=dataslot.uid,
            op_type='ASSIGN',
            const_val='1',
            loc=0x1010
        )
        
        references = ReferencesEdge(
            from_id=function.uid,
            to_id=string.hash
        )
        
        # Verify all components are properly connected
        self.assertEqual(contains_func.from_id, binary.hash)
        self.assertEqual(contains_func.to_id, function.uid)
        self.assertEqual(writes.from_id, function.uid)
        self.assertEqual(writes.to_id, dataslot.uid)
        self.assertEqual(references.to_id, string.hash)


if __name__ == '__main__':
    unittest.main(verbosity=2)
