# provis_ucg/storage/writer.py
from __future__ import annotations
# -----------------------------------------------------------------------------
# Batch writers with replace-by-(path, blob_sha256) semantics
# - Streaming-friendly inserts
# - Redaction of previews/secrets before persistence
# - Idempotent by PKs (node_id/edge_id/effect_id/etc.)
# -----------------------------------------------------------------------------

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import hashlib
import json
import re
import time

import duckdb

from ..models import (
    Anomaly, Language,
)
from ..normalize.lift import UCGNode, UCGEdge, Span
from .db import with_txn

# ----------------------------- Utilities --------------------------------------

def _as_json(obj: Any) -> Any:
    """DuckDB handles Python lists/dicts to JSON automatically; ensure serializable."""
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_as_json(o) for o in obj]
    if isinstance(obj, dict):
        return {k: _as_json(v) for k, v in obj.items()}
    return obj

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'["\']([A-Za-z0-9+/]{32,}={0,2})["\']'), "base64"),
    (re.compile(r'["\']([A-Fa-f0-9]{32,})["\']'), "hex"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), "email"),
    (re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'), "card"),
]

def redact_preview(text: Optional[str], max_chars: int = 200) -> tuple[str, str]:
    """
    Deterministically mask plausible secrets, keep length/last 4 chars.
    Returns (redacted_text, sha256_of_redacted_text)
    """
    if not text:
        return "", hashlib.sha256(b"").hexdigest()
    t = text
    for pat, _typ in _SECRET_PATTERNS:
        def _repl(m):
            s = m.group(0)
            return "***" if len(s) <= 8 else f"***{s[-4:]}"
        t = pat.sub(_repl, t)
    if len(t) > max_chars:
        t = t[:max_chars] + "…"
    h = hashlib.sha256(t.encode("utf-8", errors="ignore")).hexdigest()
    return t, h

def _now_ts() -> str:
    # DuckDB will coerce ISO 8601 string to TIMESTAMP
    return time.strftime("%Y-%m-%d %H:%M:%S")

# ----------------------------- Replace semantics ------------------------------

def replace_file_artifacts(
    con: duckdb.DuckDBPyConnection,
    *,
    repo_id: str,
    run_id: str,
    path: str,
    blob_sha256: str,
) -> None:
    """
    Delete any previous rows for this (repo_id, run_id, path) OR prior blob for same path in this run,
    to guarantee replace-by-(path, blob_sha256) before inserting fresh artifacts.
    """
    with with_txn(con) as c:
        # Remove previous entries for the same path in this run (any prior blob)
        c.execute("DELETE FROM edges   WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])
        c.execute("DELETE FROM nodes   WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])
        c.execute("DELETE FROM symbols WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])
        c.execute("DELETE FROM cfg_edges WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])
        c.execute("DELETE FROM cfg_blocks WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])
        c.execute("DELETE FROM dfg_facts WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])
        c.execute("DELETE FROM effects WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])
        # Keep anomalies and metrics historically; they’re keyed per (path, blob)
        # Files table for this run+path is replaced:
        c.execute("DELETE FROM files WHERE repo_id=? AND run_id=? AND path=?", [repo_id, run_id, path])

# ----------------------------- Inserts (files, nodes, edges, …) ---------------

def insert_file_row(
    con: duckdb.DuckDBPyConnection,
    *,
    repo_id: str,
    run_id: str,
    language: Language,
    path: str,
    rel_path: Optional[str],
    blob_sha256: str,
    size_bytes: int,
    is_symlink: bool,
    vendor: bool,
    minified: bool,
    generated: bool,
) -> None:
    flags = {"vendor": vendor, "minified": minified, "generated": generated}
    con.execute(
        """
        INSERT INTO files (repo_id, run_id, language, path, rel_path, blob_sha256, size_bytes, is_symlink, flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [repo_id, run_id, language.value, path, rel_path, blob_sha256, size_bytes, is_symlink, json.dumps(flags)],
    )

def insert_nodes_edges_effects_cfg_dfg(
    con: duckdb.DuckDBPyConnection,
    *,
    repo_id: str,
    run_id: str,
    language: Language,
    path: str,
    blob_sha256: str,
    nodes: Sequence[UCGNode],
    edges: Sequence[UCGEdge],
    symbols: Sequence[UCGNode],
    cfg_blocks: Sequence[dict] | None = None,
    cfg_edges: Sequence[dict] | None = None,
    dfg_facts: Sequence[dict] | None = None,
    effects: Sequence[dict] | None = None,
) -> None:
    """
    Bulk insert all artifacts for one file. Caller should have called replace_file_artifacts() first.
    """
    lang = language.value

    with with_txn(con) as c:
        # nodes
        if nodes:
            c.executemany(
                """
                INSERT INTO nodes (repo_id, run_id, language, path, blob_sha256,
                                   node_id, semantic_type, raw_type, name, qualified_name,
                                   spans, reason_label, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    [
                        repo_id, run_id, lang, path, blob_sha256,
                        n.node_id, n.semantic_type.value, n.raw_type, n.name, n.qualified_name,
                        json.dumps(_as_json(n.spans)), n.spans[0].reason_label if n.spans else None,
                        json.dumps(_as_json(_maybe_redact_node_extra(n))),
                    ]
                    for n in nodes
                ],
            )

        # edges
        if edges:
            c.executemany(
                """
                INSERT INTO edges (repo_id, run_id, language, path, blob_sha256,
                                   edge_id, kind, src_id, dst_id, flags, confidence, spans, reason_label)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    [
                        repo_id, run_id, lang, path, blob_sha256,
                        e.edge_id, e.kind, e.src_id, e.dst_id,
                        json.dumps(e.flags or []), e.confidence,
                        json.dumps(_as_json(e.spans)), e.reason_label,
                    ]
                    for e in edges
                ],
            )

        # symbols (UCGNode with semantic_type == Symbol)
        if symbols:
            c.executemany(
                """
                INSERT INTO symbols (repo_id, run_id, language, path, blob_sha256,
                                     symbol_id, name, kind, scope_qname, spans, type_hint, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    [
                        repo_id, run_id, lang, path, blob_sha256,
                        s.node_id, s.name, s.raw_type, s.qualified_name,
                        json.dumps(_as_json(s.spans)), (s.extra or {}).get("type_hint"),
                        json.dumps(_as_json(s.extra or {})),
                    ]
                    for s in symbols
                ],
            )

        # cfg blocks
        if cfg_blocks:
            c.executemany(
                """
                INSERT INTO cfg_blocks (repo_id, run_id, language, path, blob_sha256,
                                        fn_id, block_id, kind, spans)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    [repo_id, run_id, lang, path, blob_sha256,
                     b["fn_id"], b["block_id"], b["kind"], json.dumps(_as_json(b["spans"]))]
                    for b in cfg_blocks
                ],
            )

        # cfg edges
        if cfg_edges:
            c.executemany(
                """
                INSERT INTO cfg_edges (repo_id, run_id, language, path, blob_sha256,
                                       fn_id, edge_id, src_block_id, dst_block_id, cond_label, spans)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    [repo_id, run_id, lang, path, blob_sha256,
                     e["fn_id"], e["edge_id"], e["src_block_id"], e["dst_block_id"],
                     e.get("cond_label"), json.dumps(_as_json(e["spans"]))]
                    for e in cfg_edges
                ],
            )

        # dfg facts
        if dfg_facts:
            c.executemany(
                """
                INSERT INTO dfg_facts (repo_id, run_id, language, path, blob_sha256,
                                       fn_id, fact_id, src, dst, op_kind, flags, spans)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    [repo_id, run_id, lang, path, blob_sha256,
                     f["fn_id"], f["fact_id"], f.get("src"), f.get("dst"),
                     f.get("op_kind"), json.dumps(f.get("flags") or []), json.dumps(_as_json(f["spans"]))]
                    for f in dfg_facts
                ],
            )

        # effects
        if effects:
            c.executemany(
                """
                INSERT INTO effects (repo_id, run_id, language, path, blob_sha256,
                                     effect_id, kind, provider, family, owner_fn_id,
                                     literals, normalized_values, receipt_id, spans, reason_label)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    [
                        repo_id, run_id, lang, path, blob_sha256,
                        eff["effect_id"], eff["kind"], eff.get("provider"), eff.get("family"),
                        eff.get("owner_fn_id"),
                        json.dumps(_as_json(_redact_literals(eff.get("literals")))),
                        json.dumps(_as_json(eff.get("normalized_values") or {})),
                        eff["receipt_id"],
                        json.dumps(_as_json(eff["spans"])),
                        eff.get("reason_label"),
                    ]
                    for eff in effects
                ],
            )

def insert_metrics(
    con: duckdb.DuckDBPyConnection,
    *,
    repo_id: str,
    run_id: str,
    path: str,
    blob_sha256: str,
    language: Language,
    cache_state: str,
    node_count: int,
    effect_count: int,
    parse_time_ms: int,
) -> None:
    con.execute(
        """
        INSERT INTO metrics (repo_id, run_id, path, blob_sha256, language,
                             cache_state, node_count, effect_count, parse_time_ms, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            repo_id, run_id, path, blob_sha256, language.value,
            cache_state, node_count, effect_count, parse_time_ms, _now_ts()
        ],
    )

def insert_anomalies(
    con: duckdb.DuckDBPyConnection,
    *,
    repo_id: str,
    run_id: str,
    path: str,
    blob_sha256: Optional[str],
    anomalies: Sequence[Anomaly],
) -> None:
    if not anomalies:
        return
    con.executemany(
        """
        INSERT INTO anomalies (repo_id, run_id, path, blob_sha256, anomaly_type, severity, spans, reason_detail, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            [
                repo_id, run_id, path, blob_sha256,
                a.typ.value if hasattr(a.typ, "value") else str(a.typ),
                a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                json.dumps(_as_json(getattr(a, "spans", None))),
                getattr(a, "reason_detail", None),
                _now_ts(),
            ]
            for a in anomalies
        ],
    )

def insert_run_info(
    con: duckdb.DuckDBPyConnection,
    *,
    repo_id: str,
    run_id: str,
    schema_version: int,
    ucg_version: str,
    git_tree_sha: Optional[str],
    parent_run_id: Optional[str],
    grammar_commits: dict,
    typed_tool_versions: dict,
    rule_pack_versions: dict,
    host_info: dict,
    started_at: str,
    finished_at: str,
) -> None:
    con.execute(
        """
        INSERT INTO run_info
        (repo_id, run_id, git_tree_sha, parent_run_id, schema_version, ucg_version,
         grammar_commits, typed_tool_versions, rule_pack_versions, host_info,
         started_at, finished_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            repo_id, run_id, git_tree_sha, parent_run_id, schema_version, ucg_version,
            json.dumps(grammar_commits or {}), json.dumps(typed_tool_versions or {}),
            json.dumps(rule_pack_versions or {}), json.dumps(host_info or {}),
            started_at, finished_at,
        ],
    )

# ----------------------------- Redaction helpers ------------------------------

def _maybe_redact_node_extra(n: UCGNode) -> Dict[str, Any]:
    extra = dict(n.extra or {})
    # Redact preview text if present (normalize.lift puts call/import previews here)
    pv = extra.get("preview")
    if isinstance(pv, str):
        red, h = redact_preview(pv, max_chars=200)
        extra["preview"] = red
        extra["preview_sha256"] = h
    return extra

def _redact_literals(lits: Any) -> Any:
    if not isinstance(lits, list):
        return lits
    out = []
    for v in lits:
        if isinstance(v, str):
            red, _ = redact_preview(v, max_chars=200)
            out.append(red)
        else:
            out.append(v)
    return out
