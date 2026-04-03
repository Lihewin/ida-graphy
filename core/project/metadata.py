"""Project metadata models.

Holds project and binary file metadata persisted to disk.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict
import json
import os


@dataclass
class BinaryFile:
    """Binary file record within a project."""

    path: str
    name: str
    hash: str
    added_time: str
    last_analyzed: Optional[str] = None
    last_modified: Optional[str] = None
    size: int = 0

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        return {
            "path": self.path,
            "name": self.name,
            "hash": self.hash,
            "added_time": self.added_time,
            "last_analyzed": self.last_analyzed,
            "last_modified": self.last_modified,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BinaryFile":
        """Create BinaryFile from dict."""
        return cls(
            path=data["path"],
            name=data["name"],
            hash=data["hash"],
            added_time=data["added_time"],
            last_analyzed=data.get("last_analyzed"),
            last_modified=data.get("last_modified"),
            size=data.get("size", 0),
        )


@dataclass
class ProjectMetadata:
    """Project metadata persisted to disk."""

    name: str
    description: str
    created_time: str
    modified_time: str
    database_name: str
    binaries: List[BinaryFile] = field(default_factory=list)
    config_overrides: Dict[str, any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "database_name": self.database_name,
            "binaries": [binary.to_dict() for binary in self.binaries],
            "config_overrides": self.config_overrides,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ProjectMetadata":
        """Create ProjectMetadata from dict."""
        binaries = [BinaryFile.from_dict(b) for b in data.get("binaries", [])]
        return cls(
            name=data["name"],
            description=data["description"],
            created_time=data["created_time"],
            modified_time=data["modified_time"],
            database_name=data["database_name"],
            binaries=binaries,
            config_overrides=data.get("config_overrides", {}),
        )

    def save_to_file(self, file_path: str) -> None:
        """Save metadata to JSON file."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=4, ensure_ascii=False)

    @classmethod
    def load_from_file(cls, file_path: str) -> "ProjectMetadata":
        """Load metadata from JSON file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
