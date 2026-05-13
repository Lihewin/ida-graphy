"""Tests for export artifact helpers and Ghidra fallback backfill."""

import hashlib
import json
import os
import tempfile
import unittest

from core.extraction.hexrays_harvest import (
    GHIDRA_FALLBACK_STACK_FRAME,
    STACK_FRAME_TOO_BIG,
    _requires_ghidra_fallback,
)
from core.models import BinaryNode, FunctionNode, GhidraFallbackItem, GraphData
from exporters.artifact_utils import artifact_record, relative_artifact_path, sanitize_filename
from exporters.export_manifest import write_binary_manifest, verify_export_records
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

    def test_ghidra_artifact_backfill_updates_function_attributes_only(self):
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

    def test_manifest_verification_success_and_failures(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            exported_path = "exports/bin.so/decompile/func1_f.c"
            absolute_path = os.path.join(tmp_dir, exported_path)
            os.makedirs(os.path.dirname(absolute_path), exist_ok=True)
            with open(absolute_path, "w", encoding="utf-8") as f:
                f.write("int f(void) { return 1; }\n")

            file_hash = hashlib.sha256(b"int f(void) { return 1; }\n").hexdigest()
            manifest_path = os.path.join(tmp_dir, "exports", "bin.so", "_export_manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "version": 1,
                        "binary": {"id": "binhash", "name": "bin.so"},
                        "entries": [
                            {
                                "owner_type": "Function",
                                "owner_id": "func1",
                                "artifact_type": "decompile",
                                "path": exported_path,
                                "file_hash": file_hash,
                                "pseudocode_hash": "pseudo",
                                "status": "exported",
                                "error": "",
                            }
                        ],
                    },
                    f,
                )

            base_record = {
                "owner_type": "Function",
                "owner_id": "func1",
                "binary_name": "bin.so",
                "path": exported_path,
                "pseudocode_hash": "pseudo",
            }
            self.assertTrue(verify_export_records(tmp_dir, [base_record])["ok"])

            missing = dict(base_record, path="exports/bin.so/decompile/missing.c")
            missing_result = verify_export_records(tmp_dir, [missing])
            self.assertFalse(missing_result["ok"])
            self.assertEqual(missing_result["issues"][0]["message"], "exported file is missing")

            with open(absolute_path, "w", encoding="utf-8") as f:
                f.write("modified\n")
            hash_result = verify_export_records(tmp_dir, [base_record])
            self.assertFalse(hash_result["ok"])
            self.assertEqual(hash_result["issues"][0]["message"], "file hash differs from manifest")

            absent_path = "exports/bin.so/decompile/absent_from_manifest.c"
            with open(os.path.join(tmp_dir, absent_path), "w", encoding="utf-8") as f:
                f.write("exists\n")
            absent_result = verify_export_records(tmp_dir, [dict(base_record, path=absent_path)])
            self.assertFalse(absent_result["ok"])
            self.assertEqual(absent_result["issues"][0]["message"], "path is not present in manifest")

    def test_write_manifest_backfills_binary_manifest_hash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            graph = GraphData()
            binary = BinaryNode(hash="binhash", name="bin.so", base_addr=0, arch="x86_64")
            graph.binaries.append(binary)

            manifest_path = write_binary_manifest(tmp_dir, binary, graph, binary_name="bin.so.i64")
            absolute_manifest_path = os.path.join(tmp_dir, manifest_path)
            with open(absolute_manifest_path, "rb") as f:
                expected_hash = hashlib.sha256(f.read()).hexdigest()

            self.assertEqual(manifest_path, "exports/bin.so.i64/_export_manifest.json")
            self.assertEqual(binary.export_manifest_file, manifest_path)
            self.assertEqual(binary.export_manifest_hash, expected_hash)

            result = verify_export_records(
                tmp_dir,
                [
                    {
                        "owner_type": "Binary",
                        "owner_id": "binhash",
                        "binary_name": "bin.so",
                        "path": manifest_path,
                        "manifest_hash": expected_hash,
                    }
                ],
            )
            self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
