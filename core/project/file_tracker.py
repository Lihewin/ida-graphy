"""File change tracking helpers.

Compatibility wrapper around core.file_watcher.
"""

from core.file_watcher import (  # noqa: F401
    FileWatcher,
    ProjectFileMonitor,
    create_project_monitor,
)

__all__ = [
    "FileWatcher",
    "ProjectFileMonitor",
    "create_project_monitor",
]
