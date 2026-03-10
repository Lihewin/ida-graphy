"""Tests for the Hex-Rays dataflow → GraphMapper integration.

Validates that:
1. ``RawDataAccess`` with ``struct_name`` / ``member_offset`` produces
   READS/WRITES edges pointing to struct ``DataSlotNode`` instances.
2. Dynamic ``DataSlotNode`` creation works for Hex-Rays-discovered
   members not present in IDA's struct definition list.
3. The global-variable fallback path still works identically.
"""

import unittest

from core.models import (
    GraphData,
    BinaryNode,
    FunctionNode,
    DataSlotNode,
    WritesEdge,
    ReadsEdge,
)
from core.extraction.raw_data import (
    RawBinaryData,
    RawBinaryInfo,
    RawFunction,
    RawGlobal,
    RawStructMember,
    RawDataAccess,
)
from core.mapping.graph_mapper import GraphMapper
from core.mapping.struct_normalizer import StructNameNormalizer


def _make_raw_data(
    *,
    functions=None,
    globals_list=None,
    struct_members=None,
    data_accesses=None,
) -> RawBinaryData:
    """Helper to build a minimal ``RawBinaryData`` for testing."""
    raw = RawBinaryData()
    raw.binary_info = RawBinaryInfo(
        name="test.exe",
        orig_name="test.exe",
        base_addr=0x140000000,
        arch="x86_64",
    )
    raw.functions = functions or [
        RawFunction(
            ea=0x140001000,
            name="TestFunc",
            size=64,
            flags=0,
        )
    ]
    raw.globals = globals_list or []
    raw.struct_members = struct_members or []
    raw.data_accesses = data_accesses or []
    return raw


class TestStructMemberDataAccess(unittest.TestCase):
    """Test READS/WRITES edge generation for struct member accesses."""

    def setUp(self):
        self.binary_content = b"test binary content for dataflow"
        self.normalizer = StructNameNormalizer()
        self.mapper = GraphMapper(self.binary_content, self.normalizer)

    def test_writes_edge_to_existing_struct_member(self):
        """A WRITES access with struct_name should resolve to the matching DataSlot."""
        raw = _make_raw_data(
            struct_members=[
                RawStructMember(
                    struct_name="SESSION",
                    offset=8,
                    name="status",
                    size=4,
                )
            ],
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0,
                    is_write=True,
                    op_type="ASSIGN",
                    const_val="0x1",
                    loc=0x1010,
                    struct_name="SESSION",
                    member_offset=8,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        self.assertGreater(len(graph.writes), 0, "Expected at least one WRITES edge")
        w = graph.writes[0]
        self.assertEqual(w.op_type, "ASSIGN")
        self.assertEqual(w.const_val, "0x1")

        # The target should be a struct DataSlot
        target_slots = [d for d in graph.dataslots if d.uid == w.to_id and not d.is_global]
        self.assertEqual(len(target_slots), 1)
        self.assertEqual(target_slots[0].offset, 8)

    def test_reads_edge_to_existing_struct_member(self):
        """A READS access with struct_name should resolve to the matching DataSlot."""
        raw = _make_raw_data(
            struct_members=[
                RawStructMember(
                    struct_name="SESSION",
                    offset=0,
                    name="flags",
                    size=4,
                )
            ],
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0,
                    is_write=False,
                    op_type="MEMPTR",
                    is_condition=True,
                    loc=0x1020,
                    struct_name="SESSION",
                    member_offset=0,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        self.assertGreater(len(graph.reads), 0, "Expected at least one READS edge")
        r = graph.reads[0]
        self.assertTrue(r.condition)
        self.assertEqual(r.op_type, "MEMPTR")

    def test_struct_name_normalization(self):
        """The struct_name from Hex-Rays (e.g. 'struct _SESSION') should be
        normalized before lookup."""
        raw = _make_raw_data(
            struct_members=[
                RawStructMember(
                    struct_name="SESSION",
                    offset=4,
                    name="refcount",
                    size=4,
                )
            ],
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0,
                    is_write=True,
                    op_type="ADD",
                    loc=0x1030,
                    # Hex-Rays returns "struct _SESSION" which normalizes to "session"
                    struct_name="struct _SESSION",
                    member_offset=4,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        # Should match because both normalize to "session"
        self.assertGreater(len(graph.writes), 0)

    def test_dynamic_dataslot_creation(self):
        """When Hex-Rays discovers a struct member not in the IDA struct list,
        a DataSlotNode should be created dynamically."""
        raw = _make_raw_data(
            struct_members=[],  # empty – no struct definitions
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0,
                    is_write=True,
                    op_type="ASSIGN",
                    const_val="0xFF",
                    loc=0x1040,
                    struct_name="UNKNOWN_STRUCT",
                    member_offset=16,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        # Should still produce a WRITES edge via dynamic creation
        self.assertGreater(len(graph.writes), 0)

        # The dynamically created DataSlot should exist
        w = graph.writes[0]
        dynamic_slots = [d for d in graph.dataslots if d.uid == w.to_id]
        self.assertEqual(len(dynamic_slots), 1)
        ds = dynamic_slots[0]
        self.assertFalse(ds.is_global)
        self.assertEqual(ds.offset, 16)
        # Normalized name
        self.assertEqual(ds.base_type, self.normalizer.normalize("UNKNOWN_STRUCT"))

    def test_duplicate_dynamic_creation(self):
        """Multiple accesses to the same unknown struct member should reuse
        the same dynamically created DataSlot."""
        raw = _make_raw_data(
            struct_members=[],
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0,
                    is_write=True,
                    op_type="ASSIGN",
                    loc=0x1050,
                    struct_name="FOO",
                    member_offset=0,
                ),
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0,
                    is_write=False,
                    op_type="MEMREF",
                    is_condition=True,
                    loc=0x1060,
                    struct_name="FOO",
                    member_offset=0,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        self.assertEqual(len(graph.writes), 1)
        self.assertEqual(len(graph.reads), 1)
        # Both edges should point to the same DataSlot
        self.assertEqual(graph.writes[0].to_id, graph.reads[0].to_id)


class TestGlobalVariableFallback(unittest.TestCase):
    """Ensure the original global-variable path still works."""

    def setUp(self):
        self.binary_content = b"test binary content for dataflow"
        self.normalizer = StructNameNormalizer()
        self.mapper = GraphMapper(self.binary_content, self.normalizer)

    def test_global_writes_edge(self):
        """RawDataAccess without struct_name should resolve via global_map."""
        raw = _make_raw_data(
            globals_list=[
                RawGlobal(ea=0x140005000, name="g_Config", size=8),
            ],
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0x140005000,
                    is_write=True,
                    op_type="ASSIGN",
                    const_val="0x42",
                    loc=0x1070,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        self.assertGreater(len(graph.writes), 0)
        w = graph.writes[0]
        target_slots = [d for d in graph.dataslots if d.uid == w.to_id and d.is_global]
        self.assertEqual(len(target_slots), 1)
        self.assertEqual(target_slots[0].name, "g_Config")

    def test_global_reads_edge(self):
        raw = _make_raw_data(
            globals_list=[
                RawGlobal(ea=0x140005000, name="g_State", size=4),
            ],
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0x140005000,
                    is_write=False,
                    op_type="CMP",
                    const_val="3",
                    is_condition=True,
                    loc=0x1080,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        self.assertGreater(len(graph.reads), 0)
        r = graph.reads[0]
        self.assertTrue(r.condition)
        self.assertEqual(r.const_val, "3")

    def test_unknown_global_ea_is_silently_skipped(self):
        """A data access targeting an unknown EA should not produce an edge."""
        raw = _make_raw_data(
            globals_list=[],
            data_accesses=[
                RawDataAccess(
                    func_ea=0x140001000,
                    target_ea=0xDEADBEEF,
                    is_write=True,
                    op_type="ASSIGN",
                    loc=0x1090,
                ),
            ],
        )

        graph = self.mapper.map(raw)

        self.assertEqual(len(graph.writes), 0)
        self.assertEqual(len(graph.reads), 0)


class TestRawDataAccessDTO(unittest.TestCase):
    """Basic tests for the extended RawDataAccess DTO."""

    def test_struct_fields_default_to_none(self):
        access = RawDataAccess(
            func_ea=0x1000,
            target_ea=0x5000,
            is_write=True,
            op_type="ASSIGN",
        )
        self.assertIsNone(access.struct_name)
        self.assertIsNone(access.member_offset)

    def test_struct_fields_set(self):
        access = RawDataAccess(
            func_ea=0x1000,
            target_ea=0,
            is_write=False,
            op_type="MEMPTR",
            struct_name="MyStruct",
            member_offset=24,
        )
        self.assertEqual(access.struct_name, "MyStruct")
        self.assertEqual(access.member_offset, 24)


if __name__ == "__main__":
    unittest.main(verbosity=2)
