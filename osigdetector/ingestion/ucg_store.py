# osigdetector/ingestion/ucg_store.py
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Dict, Iterable, List, Optional, Tuple

from .ast_to_ucg import (
    UCGBatch, UCGFile, UCGFunction, UCGClass, UCGSymbol, UCGEdge, Provenance
)
from .cfg_builder import CFGBundle, CFGBlock, CFGEdge
from .dfg_builder import DFGBundle, DFGBinding
from .effect_annotator import EffectsBundle, EffectRecord


class UCGStore:
    """
    SQLite-backed store for Step-1 artifacts:
      - files, functions, classes, symbols, edges (+ provenance)
      - cfg_blocks, cfg_edges
      - dfg_bindings
      - effects

    Design:
      - Idempotent writes via UNIQUE constraints + INSERT OR REPLACE where appropriate.
      - JSON columns for 'anomalies' and 'raw_fields'.
      - All tables have lightweight indexes for fast lookup.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        with self._conn() as con:
            self._pragma(con)
            self._ensure_schema(con)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def write_all(
        self,
        ucg: UCGBatch,
        cfg_by_func: Optional[Dict[str, CFGBundle]] = None,
        dfg_by_func: Optional[Dict[str, DFGBundle]] = None,
        effects: Optional[EffectsBundle] = None,
    ) -> None:
        """
        Persist a full Step-1 run into the store.
        Safe to call repeatedly; uses REPLACE where stable keys exist.
        """
        cfg_by_func = cfg_by_func or {}
        dfg_by_func = dfg_by_func or {}
        effects = effects or EffectsBundle(effects=[])

        with self._conn() as con:
            cur = con.cursor()

            # Files
            for f in ucg.files:
                cur.execute(
                    """
                    INSERT INTO files
                      (rel_path, file_id_hint, language, size_bytes, mtime, content_hash, abs_locator)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(rel_path) DO UPDATE SET
                      file_id_hint=excluded.file_id_hint,
                      language=excluded.language,
                      size_bytes=excluded.size_bytes,
                      mtime=excluded.mtime,
                      content_hash=excluded.content_hash,
                      abs_locator=excluded.abs_locator
                    """,
                    (f.rel_path, f.file_id_hint, f.language, f.size_bytes, f.mtime, f.content_hash, f.abs_locator),
                )

            # Functions
            for fn in ucg.functions:
                self._insert_function(cur, fn)

            # Classes
            for cls in ucg.classes:
                self._insert_class(cur, cls)

            # Symbols
            for sym in ucg.symbols:
                self._insert_symbol(cur, sym)

            # Structural edges (defines/imports/calls)
            for e in ucg.edges:
                self._insert_edge(cur, e)

            # CFG
            for qname, bundle in cfg_by_func.items():
                for blk in bundle.blocks:
                    self._insert_cfg_block(cur, blk)
                for ed in bundle.edges:
                    self._insert_cfg_edge(cur, ed)

            # DFG
            for qname, bundle in dfg_by_func.items():
                for b in bundle.bindings:
                    self._insert_dfg_binding(cur, b)

            # Effects
            for eff in effects.effects:
                self._insert_effect(cur, eff)

            con.commit()

    # ------------------------- Simple readers ------------------------- #

    def get_file(self, rel_path: str) -> Optional[dict]:
        with self._conn() as con:
            cur = con.cursor()
            row = cur.execute("SELECT * FROM files WHERE rel_path=?", (rel_path,)).fetchone()
            return self._row_to_dict(cur, row) if row else None

    def list_functions(self, rel_path: Optional[str] = None) -> List[dict]:
        with self._conn() as con:
            cur = con.cursor()
            if rel_path:
                rows = cur.execute("SELECT * FROM functions WHERE file_rel=? ORDER BY qname", (rel_path,)).fetchall()
            else:
                rows = cur.execute("SELECT * FROM functions ORDER BY file_rel, qname").fetchall()
            return [self._row_to_dict(cur, r) for r in rows]

    def list_effects(self, kind: Optional[str] = None) -> List[dict]:
        with self._conn() as con:
            cur = con.cursor()
            if kind:
                rows = cur.execute("SELECT * FROM effects WHERE effect_type=? ORDER BY file_rel, effect_id", (kind,)).fetchall()
            else:
                rows = cur.execute("SELECT * FROM effects ORDER BY file_rel, effect_id").fetchall()
            return [self._row_to_dict(cur, r) for r in rows]

    # ------------------------------------------------------------------ #
    # Internals: schema & inserts
    # ------------------------------------------------------------------ #

    @contextmanager
    def _conn(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            yield con
        finally:
            con.close()

    def _pragma(self, con: sqlite3.Connection) -> None:
        cur = con.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.execute("PRAGMA temp_store=MEMORY;")
        cur.execute("PRAGMA mmap_size=134217728;")  # 128MB
        con.commit()

    def _ensure_schema(self, con: sqlite3.Connection) -> None:
        c = con.cursor()

        # files
        c.execute("""
        CREATE TABLE IF NOT EXISTS files(
            rel_path      TEXT PRIMARY KEY,
            file_id_hint  TEXT,
            language      TEXT,
            size_bytes    INTEGER,
            mtime         REAL,
            content_hash  TEXT,
            abs_locator   TEXT
        );""")

        # functions
        c.execute("""
        CREATE TABLE IF NOT EXISTS functions(
            qname        TEXT PRIMARY KEY,
            file_rel     TEXT NOT NULL,
            name         TEXT,
            scope_qname  TEXT,
            prov_file    TEXT,
            prov_sl      INTEGER,
            prov_el      INTEGER,
            prov_sbyte   INTEGER,
            prov_ebyte   INTEGER,
            anomalies    TEXT,
            FOREIGN KEY(file_rel) REFERENCES files(rel_path) ON DELETE CASCADE
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_file ON functions(file_rel);")

        # classes
        c.execute("""
        CREATE TABLE IF NOT EXISTS classes(
            qname        TEXT PRIMARY KEY,
            file_rel     TEXT NOT NULL,
            name         TEXT,
            scope_qname  TEXT,
            prov_file    TEXT,
            prov_sl      INTEGER,
            prov_el      INTEGER,
            prov_sbyte   INTEGER,
            prov_ebyte   INTEGER,
            anomalies    TEXT,
            FOREIGN KEY(file_rel) REFERENCES files(rel_path) ON DELETE CASCADE
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_classes_file ON classes(file_rel);")

        # symbols
        c.execute("""
        CREATE TABLE IF NOT EXISTS symbols(
            symbol_id    INTEGER PRIMARY KEY,
            file_rel     TEXT NOT NULL,
            name         TEXT,
            kind         TEXT,
            scope_qname  TEXT,
            prov_file    TEXT,
            prov_sl      INTEGER,
            prov_el      INTEGER,
            prov_sbyte   INTEGER,
            prov_ebyte   INTEGER,
            anomalies    TEXT,
            UNIQUE(file_rel, scope_qname, name),
            FOREIGN KEY(file_rel) REFERENCES files(rel_path) ON DELETE CASCADE
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_rel);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_symbols_scope ON symbols(scope_qname);")

        # structural edges
        c.execute("""
        CREATE TABLE IF NOT EXISTS edges(
            edge_id      INTEGER PRIMARY KEY,
            file_rel     TEXT NOT NULL,
            src_qname    TEXT,
            dst_qname    TEXT,
            kind         TEXT,          -- defines|imports|calls
            prov_file    TEXT,
            prov_sl      INTEGER,
            prov_el      INTEGER,
            prov_sbyte   INTEGER,
            prov_ebyte   INTEGER,
            note         TEXT,
            FOREIGN KEY(file_rel) REFERENCES files(rel_path) ON DELETE CASCADE
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_file ON edges(file_rel);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_qname);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_kind ON edges(kind);")

        # CFG
        c.execute("""
        CREATE TABLE IF NOT EXISTS cfg_blocks(
            block_id     INTEGER PRIMARY KEY,
            func_qname   TEXT NOT NULL,
            start_line   INTEGER,
            end_line     INTEGER,
            exit_kind    TEXT,          -- return|raise|fallthrough|unknown
            prov_file    TEXT,
            prov_sl      INTEGER,
            prov_el      INTEGER,
            note         TEXT
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cfg_func ON cfg_blocks(func_qname);")

        c.execute("""
        CREATE TABLE IF NOT EXISTS cfg_edges(
            edge_id      INTEGER PRIMARY KEY,
            func_qname   TEXT NOT NULL,
            from_block   INTEGER,
            to_block     INTEGER,
            kind         TEXT            -- normal|exception
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cfge_func ON cfg_edges(func_qname);")

        # DFG
        c.execute("""
        CREATE TABLE IF NOT EXISTS dfg_bindings(
            binding_id   INTEGER PRIMARY KEY,
            func_qname   TEXT NOT NULL,
            var_name     TEXT,
            value_kind   TEXT,          -- literal|concat|template|dict|unknown
            value_norm   TEXT,
            prov_file    TEXT,
            prov_sl      INTEGER,
            prov_el      INTEGER,
            prov_sbyte   INTEGER,
            prov_ebyte   INTEGER,
            anomalies    TEXT
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_dfg_func ON dfg_bindings(func_qname);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_dfg_var ON dfg_bindings(var_name);")

        # Effects
        c.execute("""
        CREATE TABLE IF NOT EXISTS effects(
            effect_id      INTEGER PRIMARY KEY,
            file_rel       TEXT NOT NULL,
            func_qname     TEXT,
            effect_type    TEXT,       -- route|db|external|schema|queue|scheduler|cli|guard|search|email|event
            lang           TEXT,
            framework_hint TEXT,
            raw_fields     TEXT,       -- JSON
            prov_file      TEXT,
            prov_sl        INTEGER,
            prov_el        INTEGER,
            prov_sbyte     INTEGER,
            prov_ebyte     INTEGER,
            anomalies      TEXT,       -- JSON
            note           TEXT,
            FOREIGN KEY(file_rel) REFERENCES files(rel_path) ON DELETE CASCADE
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_effects_file ON effects(file_rel);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_effects_type ON effects(effect_type);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_effects_func ON effects(func_qname);")

        # Anchors (Step 2 proto-OSigs)
        c.execute("""
        CREATE TABLE IF NOT EXISTS anchors(
            anchor_id        INTEGER PRIMARY KEY,
            effect_id        INTEGER,
            file_rel         TEXT NOT NULL,
            func_qname       TEXT,
            kind             TEXT,       -- http_response, db_write, etc
            raw_fields       TEXT,       -- JSON (from Step 2)
            resolved_fields  TEXT,       -- JSON (from Step 3)
            anomalies        TEXT,       -- JSON
            static_confidence REAL,
            confidence_static REAL,      -- Step 3 confidence
            prov_file        TEXT,
            prov_sl          INTEGER,
            prov_el          INTEGER,
            note             TEXT,
            FOREIGN KEY(effect_id) REFERENCES effects(effect_id)
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_anchors_kind ON anchors(kind);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_anchors_file ON anchors(file_rel);")

        # Context Packs (Step 4 - LLM input preparation)
        c.execute("""
        CREATE TABLE IF NOT EXISTS context_packs(
            pack_id          INTEGER PRIMARY KEY,
            anchor_id        INTEGER NOT NULL,
            bundle           TEXT NOT NULL,       -- JSON context bundle
            size_bytes       INTEGER,
            created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(anchor_id) REFERENCES anchors(anchor_id)
        );""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_context_packs_anchor ON context_packs(anchor_id);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_context_packs_size ON context_packs(size_bytes);")

        con.commit()

    # ------------------------- Insert helpers ------------------------- #

    def _insert_function(self, cur: sqlite3.Cursor, fn: UCGFunction) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO functions
              (qname, file_rel, name, scope_qname,
               prov_file, prov_sl, prov_el, prov_sbyte, prov_ebyte, anomalies)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fn.qname, fn.file_rel, fn.name, fn.scope_qname,
                fn.prov.file_rel, fn.prov.start_line, fn.prov.end_line,
                fn.prov.start_byte, fn.prov.end_byte,
                json.dumps(fn.anomalies or []),
            ),
        )

    def _insert_class(self, cur: sqlite3.Cursor, cls: UCGClass) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO classes
              (qname, file_rel, name, scope_qname,
               prov_file, prov_sl, prov_el, prov_sbyte, prov_ebyte, anomalies)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cls.qname, cls.file_rel, cls.name, cls.scope_qname,
                cls.prov.file_rel, cls.prov.start_line, cls.prov.end_line,
                cls.prov.start_byte, cls.prov.end_byte,
                json.dumps(cls.anomalies or []),
            ),
        )

    def _insert_symbol(self, cur: sqlite3.Cursor, sym: UCGSymbol) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO symbols
              (symbol_id, file_rel, name, kind, scope_qname,
               prov_file, prov_sl, prov_el, prov_sbyte, prov_ebyte, anomalies)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sym.symbol_id, sym.file_rel, sym.name, sym.kind, sym.scope_qname,
                sym.prov.file_rel, sym.prov.start_line, sym.prov.end_line,
                sym.prov.start_byte, sym.prov.end_byte,
                json.dumps(sym.anomalies or []),
            ),
        )

    def _insert_edge(self, cur: sqlite3.Cursor, e: UCGEdge) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO edges
              (edge_id, file_rel, src_qname, dst_qname, kind,
               prov_file, prov_sl, prov_el, prov_sbyte, prov_ebyte, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                e.edge_id, e.file_rel, e.src_qname, e.dst_qname, e.kind,
                e.prov.file_rel, e.prov.start_line, e.prov.end_line,
                e.prov.start_byte, e.prov.end_byte, e.note,
            ),
        )

    def _insert_cfg_block(self, cur: sqlite3.Cursor, b: CFGBlock) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO cfg_blocks
              (block_id, func_qname, start_line, end_line, exit_kind,
               prov_file, prov_sl, prov_el, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                b.block_id, b.func_qname, b.start_line, b.end_line, b.exit_kind,
                b.prov.file_rel, b.prov.start_line, b.prov.end_line, b.prov.note,
            ),
        )

    def _insert_cfg_edge(self, cur: sqlite3.Cursor, e: CFGEdge) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO cfg_edges
              (edge_id, func_qname, from_block, to_block, kind)
            VALUES (?, ?, ?, ?, ?)
            """,
            (e.edge_id, e.func_qname, e.from_block, e.to_block, e.kind),
        )

    def _insert_dfg_binding(self, cur: sqlite3.Cursor, b: DFGBinding) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO dfg_bindings
              (binding_id, func_qname, var_name, value_kind, value_norm,
               prov_file, prov_sl, prov_el, prov_sbyte, prov_ebyte, anomalies)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                b.binding_id, b.func_qname, b.var_name, b.value_kind, b.value_norm,
                b.prov.file_rel, b.prov.start_line, b.prov.end_line,
                b.prov.start_byte, b.prov.end_byte, json.dumps(b.anomalies or []),
            ),
        )

    def _insert_effect(self, cur: sqlite3.Cursor, e: EffectRecord) -> None:
        cur.execute(
            """
            INSERT OR REPLACE INTO effects
              (effect_id, file_rel, func_qname, effect_type, lang, framework_hint,
               raw_fields, prov_file, prov_sl, prov_el, prov_sbyte, prov_ebyte, anomalies, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                e.effect_id, e.file_rel, e.func_qname, e.effect_type, e.lang, e.framework_hint,
                json.dumps(e.raw_fields or {}),
                e.prov.file_rel, e.prov.start_line, e.prov.end_line, e.prov.start_byte, e.prov.end_byte,
                json.dumps(e.anomalies or []), e.note,
            ),
        )

    def insert_anchor(self, cur, anchor) -> None:
        import json
        prov = anchor.prov
        cur.execute(
            """
            INSERT OR REPLACE INTO anchors
              (anchor_id, effect_id, file_rel, func_qname, kind,
               raw_fields, resolved_fields, anomalies, static_confidence, confidence_static,
               prov_file, prov_sl, prov_el, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                anchor.anchor_id,
                anchor.effect_id,
                anchor.file_rel,
                anchor.func_qname,
                anchor.kind,
                json.dumps(anchor.raw_fields),
                json.dumps(getattr(anchor, 'resolved_fields', {})),
                json.dumps(anchor.anomalies),
                anchor.static_confidence,
                getattr(anchor, 'confidence_static', None),
                prov.file_rel if prov else None,
                prov.start_line if prov else None,
                prov.end_line if prov else None,
                anchor.note,
            ),
        )

    # ------------------------- util ------------------------- #

    @staticmethod
    def _row_to_dict(cur: sqlite3.Cursor, row: sqlite3.Row) -> dict:
        cols = [d[0] for d in cur.description]
        out = {c: row[idx] for idx, c in enumerate(cols)}
        # try JSON decode common fields
        for k in ("anomalies", "raw_fields"):
            if k in out and isinstance(out[k], str):
                try:
                    out[k] = json.loads(out[k])
                except Exception:
                    pass
        return out
