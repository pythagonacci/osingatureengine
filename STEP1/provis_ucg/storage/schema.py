# provis_ucg/storage/schema.py
from __future__ import annotations

# -----------------------------------------------------------------------------
# DuckDB schema & migrations (append-only) for Step-1 UCG persistence
# -----------------------------------------------------------------------------
import duckdb

SCHEMA_VERSION = 1  # bump on additive migrations only

# ---------------------------- DDL (version 1) ---------------------------------

DDL_V1_TABLES: list[str] = [
    # Run metadata (one row per run)
    """
    CREATE TABLE IF NOT EXISTS run_info (
        repo_id            VARCHAR NOT NULL,
        run_id             VARCHAR NOT NULL,
        git_tree_sha       VARCHAR,
        parent_run_id      VARCHAR,
        schema_version     INTEGER NOT NULL,
        ucg_version        VARCHAR,
        grammar_commits    JSON,          -- {"python": "...", "javascript": "...", "typescript": "..."}
        typed_tool_versions JSON,         -- {"ts":"5.4.x","pyright":"1.1.x","mypy":"1.x"}
        rule_pack_versions JSON,
        host_info          JSON,          -- {"os":"...","arch":"...","locale":"..."}
        started_at         TIMESTAMP,
        finished_at        TIMESTAMP,
        PRIMARY KEY (repo_id, run_id)
    );
    """,
    # Files observed in the run (supported + skipped w/ flags)
    """
    CREATE TABLE IF NOT EXISTS files (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,       -- 'python' | 'javascript' | 'typescript'
        path            VARCHAR NOT NULL,       -- absolute or repo-relative canonical
        rel_path        VARCHAR,                -- repo-relative for UX
        blob_sha256     VARCHAR NOT NULL,
        size_bytes      BIGINT,
        is_symlink      BOOLEAN DEFAULT FALSE,
        flags           JSON,                   -- {"vendor":true,"minified":false,"generated":false}
        PRIMARY KEY (repo_id, run_id, path, blob_sha256)
    );
    """,
    # UCG nodes (definitions, calls, imports, literals, etc.)
    """
    CREATE TABLE IF NOT EXISTS nodes (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        node_id         VARCHAR NOT NULL,      -- content-addressed id
        semantic_type   VARCHAR NOT NULL,      -- File/Module/Class/Function/Method/Call/Import/...
        raw_type        VARCHAR,
        name            VARCHAR,
        qualified_name  VARCHAR,
        spans           JSON NOT NULL,         -- [{"path":...,"byte_start":...,"reason_label":...}, ...]
        reason_label    VARCHAR,               -- optional friendly label for main span
        extra           JSON,                  -- arbitrary aux (signature, preview hash, etc.)
        PRIMARY KEY (repo_id, run_id, node_id)
    );
    """,
    # UCG edges (defines/imports/exports/calls/reads/writes/...)
    """
    CREATE TABLE IF NOT EXISTS edges (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        edge_id         VARCHAR NOT NULL,
        kind            VARCHAR NOT NULL,      -- defines/imports/aliases/references/...
        src_id          VARCHAR NOT NULL,
        dst_id          VARCHAR NOT NULL,
        flags           JSON,                  -- ["RESOLVED","PARTIAL","UNRESOLVED","DYNAMIC",...]
        confidence      DOUBLE,
        spans           JSON NOT NULL,
        reason_label    VARCHAR,
        PRIMARY KEY (repo_id, run_id, edge_id)
    );
    """,
    # Symbols (stable identities derived from defs)
    """
    CREATE TABLE IF NOT EXISTS symbols (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        symbol_id       VARCHAR NOT NULL,
        name            VARCHAR,
        kind            VARCHAR,              -- "symbol","function","class",...
        scope_qname     VARCHAR,
        spans           JSON,
        type_hint       VARCHAR,
        extra           JSON,
        PRIMARY KEY (repo_id, run_id, symbol_id)
    );
    """,
    # CFG blocks & edges (per function)
    """
    CREATE TABLE IF NOT EXISTS cfg_blocks (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        fn_id           VARCHAR NOT NULL,      -- owning Function/Method node_id
        block_id        VARCHAR NOT NULL,      -- unique within fn_id
        kind            VARCHAR NOT NULL,      -- entry|normal|exit|exception
        spans           JSON NOT NULL,         -- representative span(s)
        PRIMARY KEY (repo_id, run_id, fn_id, block_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cfg_edges (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        fn_id           VARCHAR NOT NULL,
        edge_id         VARCHAR NOT NULL,
        src_block_id    VARCHAR NOT NULL,
        dst_block_id    VARCHAR NOT NULL,
        cond_label      VARCHAR,               -- e.g., "case: 'GET'", "else", "except: ValueError"
        spans           JSON NOT NULL,
        PRIMARY KEY (repo_id, run_id, fn_id, edge_id)
    );
    """,
    # SSA-lite DFG facts (effect-relevant variables)
    """
    CREATE TABLE IF NOT EXISTS dfg_facts (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        fn_id           VARCHAR NOT NULL,      -- owner function/method
        fact_id         VARCHAR NOT NULL,
        src             VARCHAR,               -- symbol_id | literal | argN
        dst             VARCHAR,               -- symbol_id | return | argN
        op_kind         VARCHAR,               -- "assign","concat","join","format","phi","const"
        flags           JSON,
        spans           JSON NOT NULL,
        PRIMARY KEY (repo_id, run_id, fn_id, fact_id)
    );
    """,
    # Effect carriers
    """
    CREATE TABLE IF NOT EXISTS effects (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        effect_id       VARCHAR NOT NULL,
        kind            VARCHAR NOT NULL,      -- route | sql | graphql | messaging | io | subprocess | cache | flag | auth | scheduler | openapi | ...
        provider        VARCHAR,               -- fastapi | express | prisma | sqlalchemy | ...
        family          VARCHAR,               -- GET|POST, SELECT|INSERT, etc.
        owner_fn_id     VARCHAR,               -- nullable
        literals        JSON,                  -- raw literal list (redacted)
        normalized_values JSON,                -- JSON dict of normalized fields (path_family, table, topic, key, ...)
        receipt_id      VARCHAR NOT NULL,      -- hash(path, span, reason_label)
        spans           JSON NOT NULL,
        reason_label    VARCHAR NOT NULL,
        PRIMARY KEY (repo_id, run_id, effect_id)
    );
    """,
    # Anomalies
    """
    CREATE TABLE IF NOT EXISTS anomalies (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR,
        anomaly_type    VARCHAR NOT NULL,
        severity        VARCHAR NOT NULL,
        spans           JSON,
        reason_detail   VARCHAR,
        ts              TIMESTAMP DEFAULT NOW(),
        id              BIGINT PRIMARY KEY DEFAULT nextval('seq_anom')
    );
    """,
    # Metrics per file
    """
    CREATE TABLE IF NOT EXISTS metrics (
        repo_id         VARCHAR NOT NULL,
        run_id          VARCHAR NOT NULL,
        path            VARCHAR NOT NULL,
        blob_sha256     VARCHAR NOT NULL,
        language        VARCHAR NOT NULL,
        cache_state     VARCHAR,               -- miss | hit | incremental | error
        node_count      BIGINT,
        effect_count    BIGINT,
        parse_time_ms   BIGINT,
        ts              TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (repo_id, run_id, path, blob_sha256)
    );
    """,
]

DDL_V1_SEQUENCES = ["CREATE SEQUENCE IF NOT EXISTS seq_anom;"]

DDL_V1_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_nodes_path ON nodes (path);",
    "CREATE INDEX IF NOT EXISTS idx_edges_kind ON edges (kind);",
    "CREATE INDEX IF NOT EXISTS idx_effects_kind ON effects (kind);",
    "CREATE INDEX IF NOT EXISTS idx_effects_receipt ON effects (receipt_id);",
    "CREATE INDEX IF NOT EXISTS idx_files_blob ON files (path, blob_sha256);",
    "CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics (ts);",
]

# Helpful views
DDL_V1_VIEWS = [
    # latest_by_path – pick newest (by ts in metrics) per path for convenience
    """
    CREATE VIEW IF NOT EXISTS latest_by_path AS
    SELECT m.repo_id, m.run_id, m.path, m.blob_sha256, m.language,
           m.cache_state, m.node_count, m.effect_count, m.parse_time_ms, m.ts
    FROM metrics m
    QUALIFY ROW_NUMBER() OVER (PARTITION BY m.repo_id, m.path ORDER BY m.ts DESC) = 1;
    """,
    # effects_by_kind – exploded view for quick analytics
    """
    CREATE VIEW IF NOT EXISTS effects_by_kind AS
    SELECT repo_id, run_id, language, kind, provider, family,
           path, blob_sha256, owner_fn_id, normalized_values, receipt_id
    FROM effects;
    """,
    # callsites_by_callee – edges filtered to call relations (if produced later)
    """
    CREATE VIEW IF NOT EXISTS callsites_by_callee AS
    SELECT e.repo_id, e.run_id, e.path, e.language, e.src_id, e.dst_id, e.spans
    FROM edges e
    WHERE e.kind IN ('calls','instantiates');
    """,
]


def ensure_schema(con: duckdb.DuckDBPyConnection) -> None:
    """Create base schema, sequences, and views if missing; verify version."""
    # Ensure sequences first (used by anomalies)
    for ddl in DDL_V1_SEQUENCES:
        con.execute(ddl)

    # Create/verify schema_version store
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS _schema_meta (
            key   VARCHAR PRIMARY KEY,
            value VARCHAR
        );
    """
    )
    # If no version, initialize
    cur = con.execute("SELECT value FROM _schema_meta WHERE key = 'version';").fetchone()
    if cur is None:
        con.execute(
            "INSERT INTO _schema_meta (key, value) VALUES ('version', ?)", [str(SCHEMA_VERSION)]
        )

    # Apply tables & indexes & views (idempotent)
    for ddl in DDL_V1_TABLES:
        con.execute(ddl)
    for ddl in DDL_V1_INDEXES:
        con.execute(ddl)
    for ddl in DDL_V1_VIEWS:
        con.execute(ddl)

    # Verify version compat
    row = con.execute("SELECT value FROM _schema_meta WHERE key = 'version'").fetchone()
    version = int(row[0])
    if version != SCHEMA_VERSION:
        # Only support exact match for now (append-only upgrades can be added here)
        raise RuntimeError(f"DuckDB schema version mismatch: db={version}, code={SCHEMA_VERSION}")
