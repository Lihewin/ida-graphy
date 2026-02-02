"""
IDA-Graphy Core Module

This module provides the core functionality for ida-graphy including:
- Data models and graph structures  
- Project management
- File change monitoring
- Node ID generation
"""

from .node_id_generator import NodeIDGenerator
from .models import (
    BinaryNode,
    FunctionNode,
    DataSlotNode,
    StringNode,
    ContainsEdge,
    CallsEdge,
    LinksToEdge,
    ReferencesEdge,
    WritesEdge,
    ReadsEdge,
    GraphData,
    BinaryFile,
    ProjectMetadata
)
from .project_manager import ProjectManager, Project, ProjectError
from .file_watcher import FileWatcher, ProjectFileMonitor, create_project_monitor

__version__ = "2.0.0"

__all__ = [
    'NodeIDGenerator',
    'BinaryNode',
    'FunctionNode', 
    'DataSlotNode',
    'StringNode',
    'ContainsEdge',
    'CallsEdge',
    'LinksToEdge',
    'ReferencesEdge',
    'WritesEdge',
    'ReadsEdge',
    'GraphData',
    'BinaryFile',
    'ProjectMetadata',
    'ProjectManager',
    'Project',
    'ProjectError',
    'FileWatcher',
    'ProjectFileMonitor',
    'create_project_monitor'
]
