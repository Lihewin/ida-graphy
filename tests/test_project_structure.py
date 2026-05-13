"""Lightweight project structure and import checks."""

import importlib
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestProjectStructure(unittest.TestCase):
    def test_core_modules_import(self):
        modules = [
            "core.mapping.id_generator",
            "core.models",
            "core.extraction.engine",
            "core.mapping.graph_mapper",
            "exporters.export_manager",
            "exporters.file_exporter",
            "exporters.export_manifest",
            "database.ladybugdb_manager",
        ]

        for module in modules:
            with self.subTest(module=module):
                importlib.import_module(module)

    def test_required_project_files_exist(self):
        required_files = [
            "core/__init__.py",
            "core/mapping/id_generator.py",
            "core/mapping/struct_normalizer.py",
            "core/mapping/graph_mapper.py",
            "core/extraction/raw_data.py",
            "core/extraction/engine.py",
            "core/project/metadata.py",
            "core/project/manager.py",
            "core/project/file_tracker.py",
            "core/models.py",
            "exporters/__init__.py",
            "exporters/artifact_utils.py",
            "exporters/export_manifest.py",
            "ida_graphy.py",
            "config.yaml.example",
            "pyproject.toml",
        ]

        missing = [path for path in required_files if not (PROJECT_ROOT / path).exists()]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
