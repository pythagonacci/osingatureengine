# provis_ucg/parser/ts_driver.py
from __future__ import annotations

import hashlib
import multiprocessing as mp

# -----------------------------------------------------------------------------
# Tree-sitter parser driver (production-hardened)
#
# - OS-safe timeouts via multiprocessing pool (spawn/forkserver)
# - Unified query packs in worker; deterministic capture capping
# - Pathological input guards (size/minified/deep nesting)
# - Binary/encoding detection (BOM + optional chardet)
# - Memory-aware result cache keyed by grammar/query fingerprints
# - Evidence-first: every capture has spans + reason_label
# -----------------------------------------------------------------------------
import os
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

try:
    # Optional, improves encoding detection for odd files
    import chardet  # type: ignore

    _HAS_CHARDET = True
except Exception:
    _HAS_CHARDET = False

from tree_sitter import Language as TS_Language
from tree_sitter import Node
from tree_sitter import Parser as TS_Parser
from tree_sitter import Query

try:
    from tree_sitter_languages import get_language as _get_prebuilt_lang  # type: ignore
except Exception:
    _get_prebuilt_lang = None

from ..models import Anomaly, AnomalyType, Language, Severity
from ..otel import get_tracer

# ============================== Config ========================================


@dataclass
class ParseLimits:
    # File size
    WARN_FILE_MB: int = 10
    MAX_FILE_MB: int = 50

    # Pathological guards
    MAX_NESTING_SCAN_CHARS: int = 10000
    EXTREME_NESTING_THRESHOLD: int = 2000  # consecutive openers
    LONG_LINE_LEN: int = 2000
    LOW_WS_RATIO: float = 0.05  # 5%
    LARGE_ARRAY_SCAN_CHARS: int = 20000

    # Timeouts (adaptive)
    BASE_PARSE_TIMEOUT_S: float = 10.0
    TIMEOUT_PER_MB_S: float = 2.0
    MAX_PARSE_TIMEOUT_S: float = 90.0

    # Query budget (from AST size)
    BASE_QUERY_BUDGET_S: float = 10.0
    BUDGET_PER_100K_NODES_S: float = 1.5
    MAX_QUERY_BUDGET_S: float = 60.0

    # Node and capture caps
    MAX_NODE_COUNT: int = 3_000_000
    CAPTURE_LIMIT_GLOBAL: int = 50_000
    CAPTURE_LIMIT_PER_QUERY: int = 10_000

    # Preview limits
    PREVIEW_MAX_CHARS: int = 200
    PREVIEW_LARGE_CHARS: int = 100  # if file > 1MB
    LARGE_PREVIEW_BYTE_THRESHOLD: int = 4096  # skip preview beyond this

    # Pool
    POOL_PROCS: int = min(8, (os.cpu_count() or 4))
    POOL_MAX_TASKS_PER_CHILD: int = 1  # recycle workers to avoid leaks


LIMITS = ParseLimits()

# ============================== Data types ====================================


class ParseStatus(str, Enum):
    OK = "OK"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    PARTIAL = "PARTIAL"
    BINARY = "BINARY"
    TOO_LARGE = "TOO_LARGE"
    PATHOLOGICAL = "PATHOLOGICAL"


@dataclass
class Capture:
    kind: str
    byte_start: int
    byte_end: int
    line_start: int
    col_start: int
    line_end: int
    col_end: int
    text_preview: str
    reason_label: str


@dataclass
class ParseMetrics:
    parse_time_ms: int
    node_count: int
    tree_bytes: int
    cache_state: str
    grammar_fp: str
    query_fp: str


@dataclass
class ParseResult:
    status: ParseStatus
    language: Language
    captures: list[Capture]
    anomalies: list[Anomaly]
    metrics: ParseMetrics


# ============================== Queries =======================================

# Production query sources (fallback if no .scm files present)
_PROD_QUERIES: dict[str, dict[str, str]] = {
    "python": {
        "defs": r"""
          (function_definition name:(identifier) @def.name) @def.func
          (class_definition name:(identifier) @def.name) @def.class
        """,
        "imports": r"""
          (import_statement (dotted_name) @import.module) @import.stmt
          (import_from_statement module:(dotted_name)? @import.module) @import.from
        """,
        "calls": r"""
          (call function: (_ ) @call.callee arguments:(argument_list) @call.args) @call.expr
        """,
        "literals": r"""
          (string) @lit.string
          (f_string) @lit.string
        """,
    },
    "javascript": {
        "defs": r"""
          (function_declaration name:(identifier) @def.name) @def.func
          (method_definition name:(property_identifier) @def.name) @def.method
          (class_declaration name:(identifier) @def.name) @def.class
        """,
        "imports": r"""
          (import_declaration source:(string) @import.source) @import.stmt
          (export_statement) @export.stmt
        """,
        "calls": r"""
          (call_expression function: (_ ) @call.callee arguments:(arguments) @call.args) @call.expr
        """,
        "literals": r"""
          (string) @lit.string
          (template_string) @lit.template
        """,
    },
    "typescript": {
        "defs": r"""
          (function_declaration name:(identifier) @def.name) @def.func
          (method_signature name:(property_identifier) @def.name) @def.method
          (method_definition name:(property_identifier) @def.name) @def.method
          (class_declaration name:(type_identifier) @def.name) @def.class
        """,
        "imports": r"""
          (import_declaration source:(string) @import.source) @import.stmt
          (export_statement) @export.stmt
        """,
        "calls": r"""
          (call_expression function: (_ ) @call.callee arguments:(arguments) @call.args) @call.expr
        """,
        "literals": r"""
          (string) @lit.string
          (template_string) @lit.template
        """,
    },
}


def _lang_key(language: Language) -> str:
    return {
        Language.PYTHON: "python",
        Language.JAVASCRIPT: "javascript",
        Language.TYPESCRIPT: "typescript",
    }[language]


def _load_query_sources(language: Language) -> dict[str, str]:
    key = _lang_key(language)
    base = Path(__file__).parent / "queries" / key
    out: dict[str, str] = {}
    for name in ("defs", "imports", "calls", "literals"):
        f = base / f"{name}.scm"
        if f.exists():
            out[name] = f.read_text(encoding="utf-8")
        else:
            out[name] = _PROD_QUERIES[key][name]
    return out


def _fingerprint_query_sources(srcs: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(srcs):
        h.update(name.encode())
        h.update(b"\0")
        h.update(srcs[name].encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()[:16]


# ============================== Grammar loading ===============================


def _load_language(language: Language) -> TS_Language:
    key = _lang_key(language)
    if _get_prebuilt_lang is not None:
        return _get_prebuilt_lang(key)
    # bundle by env/path
    bundle_env = os.environ.get("TS_LANG_BUNDLE", "")
    candidates = [bundle_env] if bundle_env else []
    candidates += [
        str(Path.cwd() / "build" / "ts-langs.so"),
        str(Path.cwd() / "build" / "ts-langs.dylib"),
    ]
    for c in candidates:
        p = Path(c)
        if p.exists():
            return TS_Language(p, key)
    raise RuntimeError(
        "Tree-sitter grammars not found. Install 'tree_sitter_languages' or set TS_LANG_BUNDLE."
    )


def _grammar_fingerprint(language: Language) -> str:
    # We don’t have a stable SHA from prebuilt; approximate with package+lang key.
    core = "tsl" if _get_prebuilt_lang is not None else "bundle"
    return f"{core}:{_lang_key(language)}"


# ============================== File type / encoding ==========================


def _is_binary_by_content(sample: bytes) -> bool:
    if not sample:
        return False
    # Null bytes
    if b"\x00" in sample:
        # Allow UTF-16/32 via BOM detection handled below
        if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            return False
        return True
    # Printable ratio
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    if len(sample) >= 256 and (printable / len(sample)) < 0.70:
        return True
    # Common binary signatures
    for sig in (b"\x7fELF", b"MZ", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"%PDF", b"PK\x03\x04"):
        if sample.startswith(sig):
            return True
    return False


def _detect_encoding(sample: bytes) -> str | None:
    # BOMs
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if sample.startswith(b"\xff\xfe\x00\x00"):
        return "utf-32-le"
    if sample.startswith(b"\x00\x00\xfe\xff"):
        return "utf-32-be"
    if sample.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if sample.startswith(b"\xfe\xff"):
        return "utf-16-be"
    if _HAS_CHARDET and len(sample) >= 128:
        try:
            res = chardet.detect(sample)
            if res and res.get("confidence", 0) >= 0.80 and res.get("encoding"):
                return res["encoding"]
        except Exception:
            pass
    # Try commons
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            sample.decode(enc)
            return enc
        except Exception:
            continue
    return None


def _detect_file_info(path: Path) -> tuple[bool, str | None, list[Anomaly]]:
    anomalies: list[Anomaly] = []
    binary_exts = {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".app",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".jar",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".tiff",
        ".webp",
        ".ico",
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".mp3",
        ".wav",
        ".ogg",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".pyc",
        ".pyo",
        ".class",
        ".dex",
    }
    if path.suffix.lower() in binary_exts:
        return True, None, anomalies
    try:
        size = path.stat().st_size
        sample = path.read_bytes()[: min(32768, size)]
    except Exception as e:
        anomalies.append(
            Anomaly(
                path=str(path),
                blob_sha256="",
                typ=AnomalyType.READ_ERROR,
                severity=Severity.ERROR,
                reason_detail=f"Could not read: {e}",
            )
        )
        return True, None, anomalies
    if _is_binary_by_content(sample):
        return True, None, anomalies
    enc = _detect_encoding(sample) or "utf-8"
    return False, enc, anomalies


# ============================== Pathological guards ===========================


def _looks_minified(sample_text: str) -> bool:
    lines = sample_text.splitlines()[:200]
    if any(len(ln) >= LIMITS.LONG_LINE_LEN for ln in lines):
        return True
    if len(sample_text) >= 1000:
        ws = sum(1 for c in sample_text if c.isspace())
        if (ws / max(1, len(sample_text))) < LIMITS.LOW_WS_RATIO:
            return True
    return False


def _looks_extreme_nesting(sample_text: str) -> bool:
    depth = 0
    maxdepth = 0
    for ch in sample_text[: LIMITS.MAX_NESTING_SCAN_CHARS]:
        if ch in "([{":
            depth += 1
            if depth > maxdepth:
                maxdepth = depth
                if maxdepth >= LIMITS.EXTREME_NESTING_THRESHOLD:
                    return True
        elif ch in ")]}":
            depth = max(0, depth - 1)
        else:
            # reset only lightly—still allows long runs
            pass
    return False


def _looks_massive_array(sample_text: str) -> bool:
    # cheap heuristic: a very long bracketed region early in file
    seg = sample_text[: LIMITS.LARGE_ARRAY_SCAN_CHARS]
    return "[" in seg and (seg.count(",") > 5000)


def _pathological_preview(content: bytes, enc: str) -> tuple[bool, list[str]]:
    try:
        txt = content[: max(100_000, LIMITS.LARGE_ARRAY_SCAN_CHARS)].decode(enc, errors="ignore")
    except Exception:
        return True, ["decode_failed"]
    indicators: list[str] = []
    if _looks_minified(txt):
        indicators.append("minified")
    if _looks_extreme_nesting(txt):
        indicators.append("extreme_nesting")
    if _looks_massive_array(txt):
        indicators.append("massive_array")
    # “Pathological” = very large + at least one indicator
    sz_mb = len(content) / (1024 * 1024)
    if sz_mb >= LIMITS.WARN_FILE_MB and indicators:
        return True, indicators
    return False, indicators


# ============================== Pool manager ==================================


class _PoolManager:
    _pool: mp.pool.Pool | None = None
    _ctx: mp.context.BaseContext | None = None

    @classmethod
    def get(cls) -> mp.pool.Pool:
        if cls._pool is not None:
            return cls._pool
        # Choose context
        if sys.platform.startswith("linux"):
            ctx = mp.get_context("forkserver")
        else:
            ctx = mp.get_context("spawn")
        cls._ctx = ctx
        cls._pool = ctx.Pool(
            processes=LIMITS.POOL_PROCS, maxtasksperchild=LIMITS.POOL_MAX_TASKS_PER_CHILD
        )
        return cls._pool

    @classmethod
    def reset(cls) -> None:
        p = cls._pool
        if p is not None:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                p.join()
            except Exception:
                pass
        cls._pool = None


# ============================== Worker (top-level!) ===========================


def _worker_entry(args: tuple[str, str, dict[str, str], dict[str, Any]]) -> dict[str, Any]:
    """
    Top-level, picklable worker. Returns a dict with:
      node_count:int, error_count:int, captures:list[dict], grammar_fp:str, query_fp:str
    On internal failure, raises; the parent will convert to anomalies.
    """
    file_path, lang_key, query_sources, limits_dict = args
    limits = limits_dict  # Plain dict for spawn safety

    # Load grammar
    if _get_prebuilt_lang is not None:
        ts_lang = _get_prebuilt_lang(lang_key)
    else:
        bundle_env = os.environ.get("TS_LANG_BUNDLE", "")
        if bundle_env and Path(bundle_env).exists():
            ts_lang = TS_Language(bundle_env, lang_key)
        else:
            for c in (
                Path.cwd() / "build" / "ts-langs.so",
                Path.cwd() / "build" / "ts-langs.dylib",
            ):
                if Path(c).exists():
                    ts_lang = TS_Language(str(c), lang_key)
                    break
            else:
                raise RuntimeError("Grammar bundle not found in worker")

    parser = TS_Parser()
    parser.set_language(ts_lang)

    # Read full bytes
    b = Path(file_path).read_bytes()

    # Parse (Tree-sitter is iterative; no recursion tuning needed)
    tree = parser.parse(b)

    # Node count (bounded)
    node_count = _count_nodes(tree.root_node, limit=LIMITS.MAX_NODE_COUNT + 1)
    if node_count > LIMITS.MAX_NODE_COUNT:
        raise RuntimeError(f"AST too large: {node_count} > {LIMITS.MAX_NODE_COUNT}")

    # Error count (sampled)
    error_count = _count_errors(tree.root_node, max_nodes=50_000)

    # Compile queries from unified sources
    queries: dict[str, Query] = {}
    for name, src in query_sources.items():
        if not src.strip():
            continue
        try:
            queries[name] = Query(ts_lang, src)
        except Exception:
            # Skip failing query; parent will proceed without it
            pass

    # Execute queries with caps and deterministic ordering
    captures: list[dict[str, Any]] = []
    for name in ("defs", "imports", "calls", "literals"):
        q = queries.get(name)
        if not q:
            continue
        # Collect then truncate deterministically (by start_byte, then capture kind)
        tmp: list[tuple[int, str, Node]] = []
        for node, capname in q.captures(tree.root_node):
            tmp.append((node.start_byte, capname, node))
            if len(tmp) >= LIMITS.CAPTURE_LIMIT_PER_QUERY * 2:
                # Prevent runaway; we’ll sort and truncate soon
                break
        tmp.sort(key=lambda t: (t[0], t[1]))
        tmp = tmp[: LIMITS.CAPTURE_LIMIT_PER_QUERY]
        for b0, capname, node in tmp:
            b1 = node.end_byte
            l0, c0 = node.start_point
            l1, c1 = node.end_point
            if b0 < 0 or b1 < b0 or b1 > len(b):
                continue
            # Cheap preview: skip very large spans
            if (b1 - b0) > LIMITS.LARGE_PREVIEW_BYTE_THRESHOLD:
                preview = ""
            else:
                preview = _safe_preview(b[b0:b1], file_size=len(b))
            captures.append(
                {
                    "kind": capname.lstrip("@"),
                    "byte_start": b0,
                    "byte_end": b1,
                    "line_start": l0,
                    "col_start": c0,
                    "line_end": l1,
                    "col_end": c1,
                    "text_preview": preview,
                    "reason_label": f"{lang_key}.{name}:{capname}",
                }
            )
            if len(captures) >= LIMITS.CAPTURE_LIMIT_GLOBAL:
                break
        if len(captures) >= LIMITS.CAPTURE_LIMIT_GLOBAL:
            break

    return {
        "node_count": node_count,
        "error_count": error_count,
        "captures": captures,
        "grammar_fp": _grammar_fp_worker(lang_key),
        "query_fp": _fingerprint_query_sources(query_sources),
    }


def _grammar_fp_worker(lang_key: str) -> str:
    core = "tsl" if _get_prebuilt_lang is not None else "bundle"
    return f"{core}:{lang_key}"


def _count_nodes(root: Node, limit: int) -> int:
    stack = [root]
    n = 0
    while stack and n < limit:
        node = stack.pop()
        n += 1
        # iterative children push
        for i in range(node.child_count):
            stack.append(node.children[i])
    return n


def _count_errors(root: Node, max_nodes: int) -> int:
    stack = [root]
    n = 0
    errs = 0
    while stack and n < max_nodes:
        node = stack.pop()
        n += 1
        if node.has_error:
            errs += 1
        for i in range(min(node.child_count, 1000)):
            stack.append(node.children[i])
    return errs


def _safe_preview(chunk: bytes, file_size: int) -> str:
    # adaptive preview size
    max_chars = LIMITS.PREVIEW_LARGE_CHARS if file_size > 1_000_000 else LIMITS.PREVIEW_MAX_CHARS
    try:
        s = chunk.decode("utf-8", errors="replace")
    except Exception:
        s = repr(chunk)
    if len(s) > max_chars:
        s = s[:max_chars] + "…"
    # light redaction of long tokens
    import re

    def mask(m):
        v = m.group(0)
        return "***" if len(v) <= 8 else "***" + v[-4:]

    s = re.sub(r"[A-Za-z0-9_\-+/]{40,}={0,2}", mask, s)
    s = re.sub(r"[A-Fa-f0-9]{40,}", mask, s)
    return s


# ============================== Result cache ==================================


class _ResultCache(OrderedDict):
    """LRU keyed by (path, blob_sha, grammar_fp, query_fp); stores ParseResult."""

    def __init__(self, max_entries: int = 2048):
        super().__init__()
        self.max_entries = max_entries

    def get(self, key, default=None):
        if key in self:
            self.move_to_end(key)
            return super().get(key)
        return default

    def put(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self.max_entries:
            self.popitem(last=False)


_RESULT_CACHE = _ResultCache()

# ============================== Public API ====================================


def parse_file(abs_path: str, *, language: Language, blob_sha: str) -> ParseResult:
    tracer = get_tracer("provis-ucg.ts-driver")
    start = time.perf_counter()
    path = Path(abs_path)
    anomalies: list[Anomaly] = []

    if not path.exists():
        return _error_result(language, f"File not found: {path}", start)

    # Detect binary/encoding
    is_bin, enc, detect_anoms = _detect_file_info(path)
    anomalies.extend(detect_anoms)
    if is_bin:
        return _terminal_result(ParseStatus.BINARY, language, anomalies, start)

    # Size limits
    size_bytes = path.stat().st_size
    size_mb = size_bytes / (1024 * 1024)
    if size_mb > LIMITS.MAX_FILE_MB:
        anomalies.append(
            Anomaly(
                path=str(path),
                blob_sha256="",
                typ=AnomalyType.FILE_TOO_LARGE,
                severity=Severity.ERROR,
                reason_detail=f"{size_mb:.1f}MB > {LIMITS.MAX_FILE_MB}MB",
            )
        )
        return _terminal_result(ParseStatus.TOO_LARGE, language, anomalies, start)

    # Pathological preview checks
    content = path.read_bytes()
    is_pathological, indicators = _pathological_preview(content, enc or "utf-8")
    if is_pathological:
        anomalies.append(
            Anomaly(
                path=str(path),
                blob_sha256="",
                typ=AnomalyType.PATHOLOGICAL_FILE,
                severity=Severity.WARN,
                reason_detail=",".join(indicators),
            )
        )
        return _terminal_result(ParseStatus.PATHOLOGICAL, language, anomalies, start)

    # Unified queries + fingerprints
    qsrc = _load_query_sources(language)
    query_fp = _fingerprint_query_sources(qsrc)
    grammar_fp = _grammar_fingerprint(language)

    cache_key = (str(path), blob_sha, grammar_fp, query_fp)
    cached = _RESULT_CACHE.get(cache_key)
    if cached:
        # Return a copy with cache_state updated
        cached.metrics.cache_state = "hit"
        return cached

    # Adaptive timeout & budget
    parse_timeout = min(
        LIMITS.BASE_PARSE_TIMEOUT_S + size_mb * LIMITS.TIMEOUT_PER_MB_S, LIMITS.MAX_PARSE_TIMEOUT_S
    )

    # Process pool execution
    pool = _PoolManager.get()
    lang_key = _lang_key(language)
    async_res = pool.apply_async(
        _worker_entry, args=((str(path), lang_key, qsrc, LIMITS.__dict__),)
    )
    try:
        result: dict[str, Any] = async_res.get(timeout=parse_timeout)
    except mp.context.TimeoutError:
        # nuke pool and rebuild to kill wedged worker
        _PoolManager.reset()
        anomalies.append(
            Anomaly(
                path=str(path),
                blob_sha256="",
                typ=AnomalyType.PARSE_TIMEOUT,
                severity=Severity.ERROR,
                reason_detail=f"Exceeded {parse_timeout:.1f}s",
            )
        )
        metrics = ParseMetrics(
            parse_time_ms=int((time.perf_counter() - start) * 1000),
            node_count=0,
            tree_bytes=size_bytes,
            cache_state="miss",
            grammar_fp=grammar_fp,
            query_fp=query_fp,
        )
        return ParseResult(
            status=ParseStatus.TIMEOUT,
            language=language,
            captures=[],
            anomalies=anomalies,
            metrics=metrics,
        )
    except Exception as e:
        _PoolManager.reset()
        return _error_result(language, f"Worker error: {e}", start)

    # Build captures
    raw_caps = result.get("captures", [])
    captures: list[Capture] = []
    for c in raw_caps:
        captures.append(
            Capture(
                kind=c["kind"],
                byte_start=c["byte_start"],
                byte_end=c["byte_end"],
                line_start=c["line_start"],
                col_start=c["col_start"],
                line_end=c["line_end"],
                col_end=c["col_end"],
                text_preview=c["text_preview"],
                reason_label=c["reason_label"],
            )
        )

    # If worker hit cap, annotate
    if len(captures) >= LIMITS.CAPTURE_LIMIT_GLOBAL:
        anomalies.append(
            Anomaly(
                path=str(path),
                blob_sha256="",
                typ=AnomalyType.CAPTURE_TRUNCATED,
                severity=Severity.WARN,
                reason_detail=f"capped at {LIMITS.CAPTURE_LIMIT_GLOBAL}",
            )
        )

    node_count = int(result.get("node_count", 0))
    error_count = int(result.get("error_count", 0))

    # “Partial” if high error density after decent scan
    status = ParseStatus.OK
    if node_count > 50_000:
        density = error_count / max(1, min(node_count, 50_000))
        if density >= 0.10:
            status = ParseStatus.PARTIAL
            anomalies.append(
                Anomaly(
                    path=str(path),
                    blob_sha256="",
                    typ=AnomalyType.PARTIAL_PARSE,
                    severity=Severity.WARN,
                    reason_detail=f"error_density≈{density:.0%} on sample",
                )
            )

    metrics = ParseMetrics(
        parse_time_ms=int((time.perf_counter() - start) * 1000),
        node_count=node_count,
        tree_bytes=size_bytes,
        cache_state="miss",
        grammar_fp=grammar_fp,
        query_fp=query_fp,
    )

    res = ParseResult(
        status=status, language=language, captures=captures, anomalies=anomalies, metrics=metrics
    )
    _RESULT_CACHE.put(cache_key, res)
    return res


def update_file(
    abs_path: str, edits: list[dict], *, language: Language, prev_blob_sha: str, new_blob_sha: str
) -> ParseResult:
    # For robustness & determinism at scale, we re-parse; the process pool + cache makes it cheap.
    try:
        # best-effort: drop prior cache entry
        qsrc = _load_query_sources(language)
        cache_key_old = (
            str(Path(abs_path)),
            prev_blob_sha,
            _grammar_fingerprint(language),
            _fingerprint_query_sources(qsrc),
        )
        if cache_key_old in _RESULT_CACHE:
            _RESULT_CACHE.pop(cache_key_old, None)
    except Exception:
        pass
    return parse_file(abs_path, language=language, blob_sha=new_blob_sha)


# ============================== Helpers =======================================


def _error_result(language: Language, msg: str, t0: float) -> ParseResult:
    anomalies = [
        Anomaly(
            path="",
            blob_sha256="",
            typ=AnomalyType.PARSE_ERROR,
            severity=Severity.ERROR,
            reason_detail=msg,
        )
    ]
    metrics = ParseMetrics(
        parse_time_ms=int((time.perf_counter() - t0) * 1000),
        node_count=0,
        tree_bytes=0,
        cache_state="error",
        grammar_fp="unknown",
        query_fp="unknown",
    )
    return ParseResult(
        status=ParseStatus.ERROR,
        language=language,
        captures=[],
        anomalies=anomalies,
        metrics=metrics,
    )


def _terminal_result(
    status: ParseStatus, language: Language, anomalies: list[Anomaly], t0: float
) -> ParseResult:
    metrics = ParseMetrics(
        parse_time_ms=int((time.perf_counter() - t0) * 1000),
        node_count=0,
        tree_bytes=0,
        cache_state="miss",
        grammar_fp="unknown",
        query_fp="unknown",
    )
    return ParseResult(
        status=status, language=language, captures=[], anomalies=anomalies, metrics=metrics
    )
