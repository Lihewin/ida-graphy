"""LadybugDB database manager.

This module provides an embedded database backend using LadybugDB (real_ladybug).

Design:
- Each project maps to a single on-disk database file: `graph.lbug`
- The database file is stored inside the project's folder
- Sync uses a full rebuild strategy (delete + re-create) to avoid PK conflicts

Implementation notes:
- Uses CSV + COPY for bulk ingest (nodes first, then relationships)
- `CONTAINS` is modeled as a multi FROM-TO relationship table
- Unresolved `LINKS_TO` targets are materialized as placeholder `Function` nodes
  with `binary_id='EXTERNAL'`.
"""

from __future__ import annotations

import csv
import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from core.models import (
    BinaryNode,
    CallsEdge,
    DataSlotNode,
    EmbedsEdge,
    FunctionNode,
    GraphData,
    LinksToEdge,
    ReadsEdge,
    ReferencesEdge,
    StringNode,
    WritesEdge,
)

logger = logging.getLogger(__name__)

try:
    import lbug as _lb  # type: ignore

    HAS_LADYBUG = True
except ImportError:  # pragma: no cover
    try:
        import real_ladybug as _lb  # type: ignore

        HAS_LADYBUG = True
    except ImportError:  # pragma: no cover
        _lb = None
        HAS_LADYBUG = False


class LadybugDBError(Exception):
    """LadybugDB operation error."""


def _bool(v: bool) -> str:
    return "true" if bool(v) else "false"


def _cypher_str(value: str) -> str:
    """Return a Cypher single-quoted string literal with safe escaping."""
    return "'" + value.replace("'", "''") + "'"


def _write_csv(path: str, rows: Iterable[Sequence[object]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(list(row))


@dataclass(frozen=True)
class LadybugSchema:
    node_tables: Tuple[str, ...]
    rel_tables: Tuple[str, ...]


DEFAULT_SCHEMA = LadybugSchema(
    node_tables=("Binary", "Function", "DataSlot", "String"),
    rel_tables=("CONTAINS", "EMBEDS", "CALLS", "LINKS_TO", "REFERENCES", "WRITES", "READS"),
)


class LadybugDBManager:
    """Embedded LadybugDB manager for a single database file."""

    def __init__(self, db_path: str):
        if not HAS_LADYBUG:
            raise LadybugDBError(
                "LadybugDB Python bindings not installed. Install `real_ladybug` (recommended) "
                "or a compatible `lbug` build."
            )

        self.db_path = db_path
        self._db = None
        self._conn = None

    def __enter__(self) -> "LadybugDBManager":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def conn(self):
        if self._conn is None:
            raise LadybugDBError("LadybugDB connection is not initialized")
        return self._conn

    def connect(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
            self._db = _lb.Database(self.db_path)
            self._conn = _lb.Connection(self._db)
        except Exception as e:  # pragma: no cover
            raise LadybugDBError(f"Failed to open LadybugDB database: {e}") from e

    def close(self) -> None:
        # Some bindings may not expose explicit close methods; rely on GC.
        try:
            if self._conn is not None:
                close_fn = getattr(self._conn, "close", None)
                if callable(close_fn):
                    close_fn()
        finally:
            self._conn = None
            self._db = None

    def execute(self, query: str, parameters: Optional[Dict[str, object]] = None):
        try:
            if parameters is None:
                return self.conn.execute(query)
            return self.conn.execute(query, parameters=parameters)
        except Exception as e:
            raise LadybugDBError(f"Query failed: {e}\nQuery: {query}") from e

    def query(self, query: str, parameters: Optional[Dict[str, object]] = None) -> Dict[str, Any]:
        """Execute a Cypher query and materialize the result set."""
        result = self.execute(query, parameters)

        try:
            columns = list(result.get_column_names()) if hasattr(result, "get_column_names") else []
            rows = result.get_all() if hasattr(result, "get_all") else []
            schema = result.get_schema() if hasattr(result, "get_schema") else {}

            return {
                "columns": columns,
                "rows": rows,
                "schema": schema,
                "row_count": len(rows),
                "execution_time": result.get_execution_time() if hasattr(result, "get_execution_time") else None,
                "compiling_time": result.get_compiling_time() if hasattr(result, "get_compiling_time") else None,
            }
        finally:
            close_fn = getattr(result, "close", None)
            if callable(close_fn):
                close_fn()

    def initialize_schema(self) -> None:
        """Create node/relationship tables for ida-graphy graph model."""

        statements = [
            # Node tables
            "CREATE NODE TABLE Binary(hash STRING, name STRING, orig_name STRING, base_addr INT64, arch STRING, compile_ts INT64, export_manifest_file STRING, export_manifest_hash STRING, PRIMARY KEY(hash));",
            "CREATE NODE TABLE Function(uid STRING, rva INT64, name STRING, orig_name STRING, size INT64, is_lib BOOLEAN, func_type STRING, signature STRING, complexity INT64, binary_id STRING, binary_name STRING, decompiled_file STRING, pseudocode_hash STRING, PRIMARY KEY(uid));",
            "CREATE NODE TABLE DataSlot(uid STRING, base_type STRING, base_type_orig STRING, offset INT64, size INT64, name STRING, orig_name STRING, is_global BOOLEAN, struct_file STRING, PRIMARY KEY(uid));",
            "CREATE NODE TABLE String(hash STRING, content STRING, orig_name STRING, encoding STRING, PRIMARY KEY(hash));",
            # Relationship tables
            "CREATE REL TABLE CONTAINS(FROM Binary TO Function, FROM Binary TO DataSlot, FROM Binary TO String);",
            "CREATE REL TABLE EMBEDS(FROM DataSlot TO DataSlot);",
            "CREATE REL TABLE CALLS(FROM Function TO Function, call_type STRING, call_count INT64, loc INT64, seq_order INT64, in_condition BOOLEAN, in_loop BOOLEAN, loop_depth INT64, const_args STRING, return_used BOOLEAN, return_in_condition BOOLEAN);",
            "CREATE REL TABLE LINKS_TO(FROM Function TO Function, dll_name STRING, func_name STRING);",
            "CREATE REL TABLE REFERENCES(FROM Function TO String);",
            "CREATE REL TABLE WRITES(FROM Function TO DataSlot, op_type STRING, loc INT64, const_val STRING);",
            "CREATE REL TABLE READS(FROM Function TO DataSlot, in_condition BOOLEAN, loc INT64, op_type STRING, const_val STRING);",
        ]

        for stmt in statements:
            self.execute(stmt)

    def _ensure_external_link_targets(self, graph_data: GraphData) -> List[FunctionNode]:
        existing_uids = {f.uid for f in graph_data.functions}
        externals: List[FunctionNode] = []

        for edge in graph_data.links_to:
            if edge.to_id in existing_uids:
                continue
            externals.append(
                FunctionNode(
                    uid=edge.to_id,
                    rva=0,
                    name=edge.func_name or "",
                    orig_name="",
                    size=0,
                    is_lib=True,
                    func_type="EXPORT",
                    signature="",
                    complexity=0,
                    binary_id="EXTERNAL",
                    binary_name=edge.dll_name or "",
                )
            )
            existing_uids.add(edge.to_id)

        return externals

    def import_graph_data(self, graph_data: GraphData) -> Dict[str, int]:
        """Bulk import GraphData into LadybugDB.

        Returns a stats dict compatible with the old exporter shape.
        """

        external_funcs = self._ensure_external_link_targets(graph_data)

        binaries = list(graph_data.binaries)
        functions = list(graph_data.functions) + external_funcs
        dataslots = list(graph_data.dataslots)
        strings = list(graph_data.strings)

        csv_opts = "HEADER=false, PARALLEL=false, auto_detect=false"

        with tempfile.TemporaryDirectory(prefix="ladybug_import_", dir=os.path.dirname(self.db_path) or ".") as tmp_dir:
            # Node CSVs (no header; order matches table definitions)
            binary_csv = os.path.join(tmp_dir, "Binary.csv")
            function_csv = os.path.join(tmp_dir, "Function.csv")
            dataslot_csv = os.path.join(tmp_dir, "DataSlot.csv")
            string_csv = os.path.join(tmp_dir, "String.csv")

            _write_csv(
                binary_csv,
                (
                    (
                        b.hash,
                        b.name,
                        b.orig_name,
                        int(b.base_addr),
                        b.arch,
                        int(b.compile_ts or 0),
                        b.export_manifest_file,
                        b.export_manifest_hash,
                    )
                    for b in binaries
                ),
            )

            _write_csv(
                function_csv,
                (
                    (
                        f.uid,
                        int(f.rva),
                        f.name,
                        f.orig_name,
                        int(f.size),
                        _bool(f.is_lib),
                        f.func_type,
                        f.signature,
                        int(f.complexity),
                        f.binary_id,
                        f.binary_name,
                        f.decompiled_file or "",
                        f.pseudocode_hash or "",
                    )
                    for f in functions
                ),
            )

            _write_csv(
                dataslot_csv,
                (
                    (
                        d.uid,
                        d.base_type,
                        d.base_type_orig,
                        int(d.offset),
                        int(d.size),
                        d.name,
                        d.orig_name,
                        _bool(d.is_global),
                        d.struct_file or "",
                    )
                    for d in dataslots
                ),
            )

            _write_csv(
                string_csv,
                (
                    (
                        s.hash,
                        s.content,
                        s.orig_name,
                        s.encoding,
                    )
                    for s in strings
                ),
            )

            # Relationship CSVs
            contains_fn_csv = os.path.join(tmp_dir, "CONTAINS_Binary_Function.csv")
            contains_ds_csv = os.path.join(tmp_dir, "CONTAINS_Binary_DataSlot.csv")
            contains_str_csv = os.path.join(tmp_dir, "CONTAINS_Binary_String.csv")

            contains_fn_rows: List[Tuple[str, str]] = []
            contains_ds_rows: List[Tuple[str, str]] = []
            contains_str_rows: List[Tuple[str, str]] = []

            func_uids = {f.uid for f in functions}
            dataslot_uids = {d.uid for d in dataslots}
            string_hashes = {s.hash for s in strings}

            for edge in graph_data.contains:
                if edge.to_id in func_uids:
                    contains_fn_rows.append((edge.from_id, edge.to_id))
                elif edge.to_id in dataslot_uids:
                    contains_ds_rows.append((edge.from_id, edge.to_id))
                elif edge.to_id in string_hashes:
                    contains_str_rows.append((edge.from_id, edge.to_id))

            _write_csv(contains_fn_csv, contains_fn_rows)
            _write_csv(contains_ds_csv, contains_ds_rows)
            _write_csv(contains_str_csv, contains_str_rows)

            embeds_csv = os.path.join(tmp_dir, "EMBEDS.csv")
            _write_csv(embeds_csv, ((e.from_id, e.to_id) for e in graph_data.embeds))

            calls_csv = os.path.join(tmp_dir, "CALLS.csv")
            _write_csv(
                calls_csv,
                (
                    (
                        c.from_id,
                        c.to_id,
                        c.call_type,
                        int(c.count),
                        int(c.loc),
                        int(c.seq_order),
                        _bool(c.in_condition),
                        _bool(c.in_loop),
                        int(c.loop_depth),
                        c.const_args or "",
                        _bool(c.return_used),
                        _bool(c.return_in_condition),
                    )
                    for c in graph_data.calls
                ),
            )

            links_to_csv = os.path.join(tmp_dir, "LINKS_TO.csv")
            _write_csv(
                links_to_csv,
                (
                    (
                        l.from_id,
                        l.to_id,
                        l.dll_name or "",
                        l.func_name or "",
                    )
                    for l in graph_data.links_to
                ),
            )

            references_csv = os.path.join(tmp_dir, "REFERENCES.csv")
            _write_csv(references_csv, ((r.from_id, r.to_id) for r in graph_data.references))

            writes_csv = os.path.join(tmp_dir, "WRITES.csv")
            _write_csv(
                writes_csv,
                (
                    (
                        w.from_id,
                        w.to_id,
                        w.op_type,
                        int(w.loc),
                        w.const_val or "",
                    )
                    for w in graph_data.writes
                ),
            )

            reads_csv = os.path.join(tmp_dir, "READS.csv")
            _write_csv(
                reads_csv,
                (
                    (
                        r.from_id,
                        r.to_id,
                        _bool(r.condition),
                        int(r.loc),
                        r.op_type or "",
                        r.const_val or "",
                    )
                    for r in graph_data.reads
                ),
            )

            # Configure file search path (best-effort; absolute paths still work)
            try:
                self.execute(f"CALL file_search_path={_cypher_str(tmp_dir)};")
            except Exception:
                logger.debug("LadybugDB: failed to set file_search_path; continuing")

            # COPY nodes first
            # Disable parallel CSV reader to support quoted newlines in string fields.
            self.execute(f"COPY Binary FROM {_cypher_str(binary_csv)} ({csv_opts});")
            self.execute(f"COPY Function FROM {_cypher_str(function_csv)} ({csv_opts});")
            self.execute(f"COPY DataSlot FROM {_cypher_str(dataslot_csv)} ({csv_opts});")
            self.execute(f"COPY String FROM {_cypher_str(string_csv)} ({csv_opts});")

            # COPY relationships
            # CONTAINS is multi FROM-TO; specify which child table to load
            if contains_fn_rows:
                self.execute(
                    f"COPY CONTAINS FROM {_cypher_str(contains_fn_csv)} (from='Binary', to='Function', {csv_opts});"
                )
            if contains_ds_rows:
                self.execute(
                    f"COPY CONTAINS FROM {_cypher_str(contains_ds_csv)} (from='Binary', to='DataSlot', {csv_opts});"
                )
            if contains_str_rows:
                self.execute(
                    f"COPY CONTAINS FROM {_cypher_str(contains_str_csv)} (from='Binary', to='String', {csv_opts});"
                )

            if graph_data.embeds:
                self.execute(f"COPY EMBEDS FROM {_cypher_str(embeds_csv)} ({csv_opts});")
            if graph_data.calls:
                self.execute(f"COPY CALLS FROM {_cypher_str(calls_csv)} ({csv_opts});")
            if graph_data.links_to:
                self.execute(f"COPY LINKS_TO FROM {_cypher_str(links_to_csv)} ({csv_opts});")
            if graph_data.references:
                self.execute(f"COPY REFERENCES FROM {_cypher_str(references_csv)} ({csv_opts});")
            if graph_data.writes:
                self.execute(f"COPY WRITES FROM {_cypher_str(writes_csv)} ({csv_opts});")
            if graph_data.reads:
                self.execute(f"COPY READS FROM {_cypher_str(reads_csv)} ({csv_opts});")

        node_count = len(binaries) + len(functions) + len(dataslots) + len(strings)
        rel_count = (
            len(graph_data.contains)
            + len(graph_data.embeds)
            + len(graph_data.calls)
            + len(graph_data.links_to)
            + len(graph_data.references)
            + len(graph_data.writes)
            + len(graph_data.reads)
        )

        return {
            "nodes_created": node_count,
            "relationships_created": rel_count,
            "nodes_deleted": 0,
        }

    def get_database_stats(self) -> Dict[str, int]:
        """Return simple node/relationship counts."""
        stats = {"total_nodes": 0, "total_relationships": 0}

        try:
            res = self.execute("MATCH (n) RETURN count(n);")
            if hasattr(res, "has_next") and res.has_next():
                row = res.get_next()
                stats["total_nodes"] = int(row[0])
        except Exception as e:
            logger.debug("LadybugDB node count failed: %s", e)

        try:
            res = self.execute("MATCH ()-[r]->() RETURN count(r);")
            if hasattr(res, "has_next") and res.has_next():
                row = res.get_next()
                stats["total_relationships"] = int(row[0])
        except Exception as e:
            logger.debug("LadybugDB relationship count failed: %s", e)

        return stats

    @staticmethod
    def test_connection() -> Dict[str, object]:
        """Smoke test for Python bindings."""
        if not HAS_LADYBUG:
            return {"connected": False, "error": "LadybugDB bindings not installed"}

        try:
            db = _lb.Database("")
            conn = _lb.Connection(db)
            conn.execute("CREATE NODE TABLE _Ping(id INT64, PRIMARY KEY(id));")
            # Keep the smoke test minimal and compatible: basic DDL + DML + read.
            # Avoid COPY/LOAD syntax differences across LadybugDB builds.
            conn.execute("CREATE (:_Ping {id: 1});")
            res = conn.execute("MATCH (n:_Ping) RETURN count(n);")
            count = None
            if hasattr(res, "has_next") and res.has_next():
                count = int(res.get_next()[0])
            return {"connected": True, "count": count}
        except Exception as e:  # pragma: no cover
            return {"connected": False, "error": str(e)}
