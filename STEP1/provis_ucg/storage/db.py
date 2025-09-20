# provis_ucg/storage/db.py
from __future__ import annotations

from collections.abc import Iterator

# -----------------------------------------------------------------------------
# DuckDB connection utilities: pragmas, schema ensure, transaction helper
# -----------------------------------------------------------------------------
from contextlib import contextmanager

import duckdb

from .schema import ensure_schema

DEFAULT_PRAGMAS = {
    # Keep default temp directory; enable object cache for compiled queries
    "memory_limit": "2GB",
    "threads": "8",
    "enable_object_cache": "true",
    # JSON + Parquet already enabled by default in DuckDB
}


def connect(db_path: str, *, apply_pragmas: bool = True) -> duckdb.DuckDBPyConnection:
    """
    Open (or create) a DuckDB database, apply pragmas, and ensure schema.
    """
    con = duckdb.connect(db_path, read_only=False)
    if apply_pragmas:
        for k, v in DEFAULT_PRAGMAS.items():
            con.execute(f"PRAGMA {k}={v};")
    ensure_schema(con)
    return con


@contextmanager
def with_txn(con: duckdb.DuckDBPyConnection) -> Iterator[duckdb.DuckDBPyConnection]:
    """
    Transaction context with rollback on exceptions.
    """
    con.execute("BEGIN;")
    try:
        yield con
        con.execute("COMMIT;")
    except Exception:
        con.execute("ROLLBACK;")
        raise
