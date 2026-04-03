"""Project management module.

This package contains project metadata and lifecycle helpers.
"""

from .metadata import ProjectMetadata, BinaryFile  # noqa: F401

__all__ = [
	"ProjectMetadata",
	"BinaryFile",
]
