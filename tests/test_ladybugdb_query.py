"""Tests for the LadybugDB query command."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from core.mapping.id_generator import NodeIDGenerator
from core.models import BinaryNode, DataSlotNode, FunctionNode, GraphData
from core.project.manager import ProjectManager
from database.ladybugdb_manager import HAS_LADYBUG, LadybugDBError, LadybugDBManager
from exporters.ladybugdb_exporter import LadybugDBExporter
from ida_graphy import cmd_ladybugdb_query, _parse_ladybugdb_query_params


class TestLadybugDBQueryCommand(unittest.TestCase):
    def test_parse_query_params(self):
        self.assertEqual(_parse_ladybugdb_query_params('{"name": "demo"}'), {"name": "demo"})

        with self.assertRaises(ValueError):
            _parse_ladybugdb_query_params('[]')

    def test_query_command_table_output(self):
        if not HAS_LADYBUG:
            self.skipTest("LadybugDB Python bindings are not installed")

        with tempfile.TemporaryDirectory() as tmp_dir:
            projects_root = Path(tmp_dir) / "projects"
            manager = ProjectManager(str(projects_root))
            manager.create_project("demo")

            binary_hash = NodeIDGenerator(binary_content=b"demo binary").get_binary_id()
            graph_data = GraphData(
                binaries=[
                    BinaryNode(
                        hash=binary_hash,
                        name="demo.exe",
                        orig_name="demo.exe",
                        base_addr=0x140000000,
                        arch="x86_64",
                        export_manifest_file="exports/demo.exe/_export_manifest.json",
                        export_manifest_hash="manifest-hash",
                    )
                ],
                functions=[
                    FunctionNode(
                        uid="func1",
                        rva=0x1000,
                        name="target",
                        binary_id=binary_hash,
                        binary_name="demo.exe",
                        decompiled_file="exports/demo.exe/decompile/func1_target.c",
                        pseudocode_hash="pseudo",
                    )
                ],
                dataslots=[
                    DataSlotNode(
                        uid="slot1",
                        base_type="S",
                        offset=-1,
                        size=4,
                        name="S",
                        is_global=False,
                        struct_file="exports/demo.exe/structures/S.h",
                    )
                ],
            )

            db_path = projects_root / "demo" / "graph.lbug"
            LadybugDBExporter().export_to_ladybugdb(str(db_path), graph_data)

            args = SimpleNamespace(
                name="demo",
                query="MATCH (n:Binary) RETURN n.name AS name, n.arch AS arch;",
                params=None,
                output_format="table",
            )
            config = {"projects": {"root_dir": str(projects_root)}}

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                return_code = cmd_ladybugdb_query(args, config)

            self.assertEqual(return_code, 0)
            output = buffer.getvalue()
            self.assertIn("demo.exe", output)
            self.assertIn("x86_64", output)
            self.assertIn("查询结果", output)

            with LadybugDBManager(str(db_path)) as db:
                path_result = db.query(
                    "MATCH (f:Function) RETURN f.decompiled_file AS decompiled_file, f.pseudocode_hash AS pseudocode_hash;"
                )
                self.assertEqual(
                    tuple(path_result["rows"][0]),
                    ("exports/demo.exe/decompile/func1_target.c", "pseudo"),
                )

                dataslot_result = db.query("MATCH (d:DataSlot) RETURN d.struct_file AS struct_file;")
                self.assertEqual(tuple(dataslot_result["rows"][0]), ("exports/demo.exe/structures/S.h",))

                manifest_result = db.query(
                    "MATCH (b:Binary) RETURN b.export_manifest_file AS export_manifest_file, "
                    "b.export_manifest_hash AS export_manifest_hash;"
                )
                self.assertEqual(
                    tuple(manifest_result["rows"][0]),
                    ("exports/demo.exe/_export_manifest.json", "manifest-hash"),
                )

                with self.assertRaises(LadybugDBError):
                    db.query("MATCH (a:ExportArtifact) RETURN count(a);")
