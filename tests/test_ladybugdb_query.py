"""Tests for the LadybugDB query command."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from core.mapping.id_generator import NodeIDGenerator
from core.models import BinaryNode, GraphData
from core.project.manager import ProjectManager
from exporters.ladybugdb_exporter import LadybugDBExporter
from ida_graphy import cmd_ladybugdb_query, _parse_ladybugdb_query_params


class TestLadybugDBQueryCommand(unittest.TestCase):
    def test_parse_query_params(self):
        self.assertEqual(_parse_ladybugdb_query_params('{"name": "demo"}'), {"name": "demo"})

        with self.assertRaises(ValueError):
            _parse_ladybugdb_query_params('[]')

    def test_query_command_table_output(self):
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
                    )
                ]
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
