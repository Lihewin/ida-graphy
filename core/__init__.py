"""
IDA-Graphy Core Module

This module provides the core functionality for generating graph data from IDA analysis.
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
    ReadsEdge
)

__version__ = "1.0.0"

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
    'ReadsEdge'
]
