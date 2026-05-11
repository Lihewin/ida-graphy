"""Tests for export artifact helpers and Ghidra fallback backfill."""

import unittest

from core.extraction.hexrays_harvest import (
    GHIDRA_FALLBACK_STACK_FRAME,
    STACK_FRAME_TOO_BIG,
    _requires_ghidra_fallback,
)
from core.models import BinaryNode, FunctionNode, GhidraFallbackItem, GraphData
from exporters.artifact_utils import artifact_record, relative_artifact_path, sanitize_filename
from exporters.export_manager import ExportManager
from exporters.ghidra_fallback import _ghidra_fallback_config


class TestExportArtifacts(unittest.TestCase):
    def test_artifact_helper_normalizes_paths_and_filenames(self):
        output_dir = "/tmp/ida-graphy-test"
        filepath = "/tmp/ida-graphy-test/exports/bin/decompile/a.c"

        row = artifact_record(
            output_dir,
            owner_id="f1",
            owner_type="Function",
            artifact_type="decompile",
            filepath=filepath,
            status="failed",
            error="x",
        )

        self.assertEqual(row["path"], "exports/bin/decompile/a.c")
        self.assertEqual(row["hash"], "")
        self.assertEqual(relative_artifact_path(output_dir, filepath), row["path"])
        self.assertEqual(sanitize_filename("a/b:c*? name"), "a_b_c___name")
        self.assertEqual(sanitize_filename("函数"), "__")

    def test_stack_frame_too_big_enters_fallback_class(self):
        self.assertTrue(_requires_ghidra_fallback(STACK_FRAME_TOO_BIG))
        self.assertFalse(_requires_ghidra_fallback("too big function"))

    def test_export_scoped_ghidra_config_precedes_legacy_config(self):
        config = {
            "ghidra": {"path": "/legacy/ghidra"},
            "export": {
                "ghidra_fallback": {
                    "path": "/opt/ghidra",
                    "analyze_headless": "/opt/ghidra/support/analyzeHeadless",
                }
            },
        }

        self.assertEqual(_ghidra_fallback_config(config)["path"], "/opt/ghidra")

    def test_ghidra_artifact_backfill_updates_function_and_edges(self):
        graph = GraphData()
        graph.binaries.append(
            BinaryNode(
                hash="binhash",
                name="bin.so",
                base_addr=0x400000,
                arch="x86_64",
            )
        )
        graph.functions.append(
            FunctionNode(
                uid="func1",
                rva=0x1234,
                name="f",
                binary_id="binhash",
                binary_name="bin.so",
            )
        )
        graph.ghidra_fallbacks.append(
            GhidraFallbackItem(
                function_uid="func1",
                binary_id="binhash",
                binary_name="bin.so",
                rva=0x1234,
                name="f",
                size=1,
                reason=GHIDRA_FALLBACK_STACK_FRAME,
                error=STACK_FRAME_TOO_BIG,
            )
        )

        manager = ExportManager(
            {"projects": {"root_dir": "/tmp/ida-graphy-flow-test"}},
            type("Meta", (), {"name": "p"})(),
        )
        manager._backfill_ghidra_artifacts(
            graph,
            "bin.so",
            [
                {
                    "owner_id": "func1",
                    "owner_type": "Function",
                    "artifact_type": "ghidra_decompile",
                    "path": "exports/bin.so/ghidra_decompile/func1_f.c",
                    "hash": "abc",
                    "status": "exported",
                    "error": STACK_FRAME_TOO_BIG,
                }
            ],
        )

        self.assertEqual(graph.functions[0].decompiled_file, "exports/bin.so/ghidra_decompile/func1_f.c")
        self.assertEqual(graph.functions[0].pseudocode_hash, "abc")
        self.assertEqual(graph.export_artifacts[0].artifact_type, "ghidra_decompile")
        self.assertEqual(graph.has_artifact[0].from_id, "func1")


if __name__ == "__main__":
    unittest.main()
