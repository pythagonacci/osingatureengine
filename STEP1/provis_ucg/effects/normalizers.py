# provis_ucg/effects/normalizers.py
from __future__ import annotations

# -----------------------------------------------------------------------------
# Normalizers for paths/URLs, SQL, topics, blobs; secret-safe previews.
# Optional: sqlglot. Degrade gracefully when unavailable.
# -----------------------------------------------------------------------------
import hashlib
import re

try:
    import sqlglot  # type: ignore

    _HAS_SQLGLOT = True
except Exception:
    _HAS_SQLGLOT = False

_SECRET_PATTERNS = [
    re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'),  # base64-like
    re.compile(r'["\']([A-Fa-f0-9]{40,})["\']'),  # long hex
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # emails
    re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),  # card-ish
]


def redact_preview(s: str, max_chars: int = 200) -> str:
    s = s[:max_chars]
    for pat in _SECRET_PATTERNS:

        def repl(m):
            g = m.group(0)
            return "***" if len(g) <= 8 else f"***{g[-4:]}"

        s = pat.sub(repl, s)
    return s


def normalize_http_path(path: str) -> str:
    """
    Convert '/users/{id}' / '/users/[id]' / '/users/${id}' / '/users/:id' to '/users/:id'.
    Collapse multiple slashes; strip trailing slash (but keep root '/').
    """
    if not path:
        return path
    t = path.strip().strip("\"'")
    # NextJS [id], [..slug], [id?]
    t = re.sub(r"\[(\.\.\.)?([A-Za-z0-9_]+)\??\]", r":\2", t)
    # Express :id already okay; convert {id}, ${id}, :param<regex> → :param
    t = re.sub(r"\{([A-Za-z0-9_]+)\}", r":\1", t)
    t = re.sub(r"\$\{([A-Za-z0-9_]+)\}", r":\1", t)
    t = re.sub(r":([A-Za-z0-9_]+)<[^>]+>", r":\1", t)
    # Remove duplicate slashes, strip trailing slash (except root)
    t = re.sub(r"//+", "/", t)
    if len(t) > 1 and t.endswith("/"):
        t = t[:-1]
    return t or "/"


def normalize_method(m: str) -> str:
    return (m or "").strip().upper()


_SQL_OP_RE = re.compile(
    r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b", re.IGNORECASE
)


def normalize_sql(sql: str) -> tuple[str, str | None, str | None]:
    """
    Returns (op, table, normalized_sql_or_none).
    If sqlglot present, use it to parse; else regex fallback on first table-ish word.
    """
    if not sql:
        return "", None, None
    s = sql.strip().strip('`"')
    m = _SQL_OP_RE.match(s)
    op = m.group(1).upper() if m else ""
    table = None
    norm = None
    if _HAS_SQLGLOT:
        try:
            # basic normalization
            expr = sqlglot.parse_one(s)
            tables = [t.name for t in expr.find_all(sqlglot.exp.Table)]
            table = tables[0] if tables else None
            norm = expr.sql(dialect="ansi", pretty=False)
        except Exception:
            pass
    if table is None:
        # very rough fallback: SELECT ... FROM <word>
        if op == "SELECT":
            mf = re.search(r'\bFROM\s+([A-Za-z0-9_\."]+)', s, re.IGNORECASE)
            if mf:
                table = mf.group(1).strip('"')
        elif op in ("INSERT", "UPDATE", "DELETE"):
            mt = re.search(r'\b(?:INTO|UPDATE|FROM)\s+([A-Za-z0-9_\."]+)', s, re.IGNORECASE)
            if mt:
                table = mt.group(1).strip('"')
    return op, table, norm


def normalize_topic(name: str) -> str:
    """Kafka/SNS/SQS/etc.: strip quotes, collapse slashes/dots."""
    t = (name or "").strip().strip("\"'")
    t = re.sub(r"//+", "/", t)
    return t


def receipt_id(path: str, byte_start: int, byte_end: int, reason_label: str) -> str:
    h = hashlib.sha256()
    h.update(path.encode("utf-8", errors="ignore"))
    h.update(b"\0")
    h.update(str(byte_start).encode())
    h.update(b"\0")
    h.update(str(byte_end).encode())
    h.update(b"\0")
    h.update(reason_label.encode("utf-8", errors="ignore"))
    return h.hexdigest()[:24]
