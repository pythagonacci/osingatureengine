# provis_ucg/normalize/lift.py
from __future__ import annotations
# -----------------------------------------------------------------------------
# Lift Tree-sitter ParseResult -> Uniform Code Graph (UCG) IR (production-hardened)
#
# Key improvements:
# - Language-aware name & signature extraction (Unicode identifiers, decorators, async, generics)
# - Stable symbol IDs via normalized signatures: (name, arity, type-seq, flags)
# - Proper nested scope resolution using interval containment from spans
# - Nuanced capture mapping (fn/method/ctor/arrow/get/set/async)
# - Graceful degradation with explicit anomalies; never drop evidence silently
# -----------------------------------------------------------------------------

import re
import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import (
    Anomaly,
    AnomalyType,
    Language,
    Severity,
)
from ..parser.ts_driver import Capture, ParseResult

# ----------------------------- UCG IR datatypes -------------------------------

class SemanticType(str, Enum):
    FILE = "File"
    MODULE = "Module"
    CLASS = "Class"
    FUNCTION = "Function"
    METHOD = "Method"
    CALL = "Call"
    IMPORT = "Import"
    EXPORT = "Export"
    SYMBOL = "Symbol"
    LITERAL = "Literal"
    TEMPLATE_PART = "TemplatePart"
    UNKNOWN = "Unknown"

@dataclass(frozen=True)
class Span:
    path: str
    byte_start: int
    byte_end: int
    line_start: int
    col_start: int
    line_end: int
    col_end: int
    reason_label: str

@dataclass
class UCGNode:
    node_id: str
    semantic_type: SemanticType
    raw_type: str
    name: Optional[str]
    qualified_name: Optional[str]
    language: Language
    spans: List[Span]
    extra: Dict[str, object]

@dataclass
class UCGEdge:
    edge_id: str
    kind: str
    src_id: str
    dst_id: str
    flags: List[str]
    confidence: float
    spans: List[Span]
    reason_label: str

# ----------------------------- Hashing helpers --------------------------------

def _sha256_hex(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\0")
    return h.hexdigest()

def _edge_id(kind: str, src: str, dst: str, span_key: str) -> str:
    return _sha256_hex("edge", kind, src, dst, span_key)[:24]

def _node_id(sem: SemanticType, lang: Language, qname: str, span_key: str) -> str:
    return _sha256_hex("node", sem.value, lang.value, qname, span_key)[:24]

def _sym_id(lang: Language, qname: str, decl_kind: str, sig_norm: str) -> str:
    return _sha256_hex("sym", lang.value, qname, decl_kind, sig_norm)[:24]

def _span_key(path: str, b0: int, b1: int) -> str:
    return f"{path}:{b0}-{b1}"

# ----------------------------- Capture → semantic kind ------------------------

# We accept multiple variants produced by ts_driver queries.
CAPTURE_KIND_TO_SEM: Dict[str, Tuple[SemanticType, str]] = {
    # Python
    "def.func":            (SemanticType.FUNCTION, "function"),
    "def.method":          (SemanticType.METHOD,   "method"),
    "def.class":           (SemanticType.CLASS,    "class"),
    # JS/TS defs
    "def.arrow":           (SemanticType.FUNCTION, "arrow_function"),
    "def.var_func":        (SemanticType.FUNCTION, "function_expression"),
    # Methods/classes for JS/TS
    "def.method_sig":      (SemanticType.METHOD,   "method_signature"),
    # Calls
    "call.expr":           (SemanticType.CALL,     "call"),
    "call.new":            (SemanticType.CALL,     "constructor_call"),
    "call.constructor":    (SemanticType.SYMBOL,   "constructor_name"),
    "call.method":         (SemanticType.SYMBOL,   "method_name"),
    "call.func":           (SemanticType.SYMBOL,   "function_name"),
    "call.callee":         (SemanticType.SYMBOL,   "callee_name"),
    # Imports / exports
    "import.stmt":         (SemanticType.IMPORT,   "import"),
    "import.from":         (SemanticType.IMPORT,   "import_from"),
    "import.module":       (SemanticType.SYMBOL,   "import_module"),
    "import.source":       (SemanticType.SYMBOL,   "import_source"),
    "export.stmt":         (SemanticType.EXPORT,   "export"),
    # Literals/templates
    "lit.string":          (SemanticType.LITERAL,        "string"),
    "lit.template":        (SemanticType.TEMPLATE_PART,  "template"),
}

# ----------------------------- Identifier patterns ----------------------------

# Unicode-aware identifier: start with letter/_/$, then letters/digits/_/$ (keep conservative)
_ID_START = r"[^\W\d_]|_|$"  # any unicode letter OR underscore OR $
_ID_CONT  = r"[^\W_]|_|$|\d" # letter/digit/underscore/$
IDENT_RE  = re.compile(fr"({_ID_START})(({_ID_CONT})*)", re.UNICODE)

# ----------------------------- Signature normalization ------------------------

@dataclass(frozen=True)
class SigNorm:
    """Normalized signature for stable symbol identity."""
    name: str
    arity: int
    types: Tuple[str, ...]        # language-normalized type tokens (optional)
    flags: Tuple[str, ...]        # e.g., ('async', 'getter', 'setter', 'static', 'ctor')

    def as_str(self) -> str:
        # Avoid param names; include arity + coarse type sequence + flags (sorted for determinism)
        types_str = ",".join(self.types) if self.types else ""
        flags_str = ",".join(sorted(self.flags)) if self.flags else ""
        return f"{self.name}({self.arity})|{types_str}|{flags_str}"

# ----------------------------- Scope tree from spans --------------------------

@dataclass
class DefSite:
    sem: SemanticType                # CLASS / FUNCTION / METHOD
    raw_kind: str
    name: Optional[str]
    span: Span
    sig: Optional[SigNorm]
    parent_idx: Optional[int] = None # index into defs[] for enclosing definition
    qname: Optional[str] = None      # qualified name after tree build
    node_id: Optional[str] = None
    symbol_id: Optional[str] = None

def _encloses(outer: Span, inner: Span) -> bool:
    return (outer.byte_start <= inner.byte_start) and (outer.byte_end >= inner.byte_end)

def _build_scope_tree(defs: List[DefSite]) -> None:
    # Sort by (start, -end) to ensure parents come before children for equal starts
    order = sorted(range(len(defs)), key=lambda i: (defs[i].span.byte_start, -defs[i].span.byte_end))
    stack: List[int] = []
    for i in order:
        cur = defs[i]
        while stack and not _encloses(defs[stack[-1]].span, cur.span):
            stack.pop()
        cur.parent_idx = stack[-1] if stack else None
        stack.append(i)

def _qname_chain(module_qname: str, defs: List[DefSite], idx: Optional[int], leaf_name: str) -> str:
    parts: List[str] = []
    j = idx
    while j is not None:
        nm = defs[j].name or "<anonymous>"
        parts.append(nm)
        j = defs[j].parent_idx
    parts.reverse()
    scope = "::".join([module_qname] + parts) if parts else module_qname
    return f"{scope}::{leaf_name}" if leaf_name else scope

# ----------------------------- Name & signature extraction --------------------

def _strip_decorators_and_leading_markers(s: str, language: Language) -> str:
    lines = s.splitlines()
    out = []
    skip = True
    for ln in lines:
        if language == Language.PYTHON and ln.lstrip().startswith("@"):
            continue  # decorator
        # first non-decorator line flips skip
        out.append(ln)
        if ln.strip():
            break
    # Trim leading async/def/class/exports/etc. markers loosely; callers handle specifics
    return "\n".join(out)

def _first_identifier(s: str) -> Optional[str]:
    m = IDENT_RE.search(s)
    return m.group(0) if m else None

def _extract_py_def(s: str) -> Tuple[Optional[str], int, Tuple[str, ...], Tuple[str, ...]]:
    """
    Extract (name, arity, types, flags) from a Python def/method/class preview.
    Types are coarse (from annotations if visible); arity counts parameters excluding 'self'/'cls'.
    Flags may include 'async', 'ctor'.
    """
    flags: List[str] = []
    ss = s.strip()
    if ss.startswith("async"):
        flags.append("async")
        ss = ss[5:].lstrip()

    if ss.startswith("def "):
        # def name(params) -> type:
        after = ss[4:]
        name = _first_identifier(after)
        if not name:
            return None, 0, (), tuple(flags)
        # find param list
        params = _slice_parens(after, opener="(", closer=")")
        arity, types = _normalize_param_list_python(params)
        return name, arity, types, tuple(flags)

    if ss.startswith("class "):
        after = ss[6:]
        name = _first_identifier(after)
        if not name:
            return None, 0, (), tuple(flags)
        # ctor signature is not on class preview; treat as class symbol
        flags.append("class")
        return name, 0, (), tuple(flags)

    # Fallback: property/getter-like?
    name = _first_identifier(ss)
    return (name, 0, (), tuple(flags)) if name else (None, 0, (), tuple(flags))

def _normalize_param_list_python(param_block: Optional[str]) -> Tuple[int, Tuple[str, ...]]:
    """
    param_block like "(self, x: List[int], *, y: str = 'a', **kw) -> T"
    returns (arity_without_selfcls, ('List', 'str', '*', '**', ...))
    """
    if not param_block:
        return 0, ()
    # Strip outer parens
    inner = param_block.strip()[1:-1] if param_block.startswith("(") else param_block
    # Remove annotations default values roughly; split on commas respecting nesting
    parts = _split_top_level(inner, sep=",")
    types: List[str] = []
    arity = 0
    for p in parts:
        t = p.strip()
        if not t:
            continue
        if t.startswith("self") or t.startswith("cls"):
            continue
        if t.startswith("**"):
            types.append("**")
            arity += 1
            continue
        if t.startswith("*"):
            types.append("*")
            # varargs counts as one
            arity += 1
            continue
        # annotation: name: Type
        typ = None
        if ":" in t:
            typ = t.split(":", 1)[1].strip()
        if typ:
            # keep only coarse type tokens (cap first identifier/Identifier[]/Dict/Optional)
            types.append(_coarse_type_token(typ))
        else:
            types.append("?")
        arity += 1
    # return type is not counted in params
    return arity, tuple(types[:32])  # cap

def _extract_ts_js_def(s: str) -> Tuple[Optional[str], int, Tuple[str, ...], Tuple[str, ...]]:
    """
    Extract (name, arity, types, flags) from TS/JS function/method/class/arrow preview.
    """
    ss = s.strip()
    flags: List[str] = []
    # getters/setters
    if ss.startswith("get "):
        flags.append("getter")
        ss = ss[4:].lstrip()
    if ss.startswith("set "):
        flags.append("setter")
        ss = ss[4:].lstrip()
    if ss.startswith("async "):
        flags.append("async")
        ss = ss[6:].lstrip()

    # class
    if ss.startswith("class "):
        nm = _first_identifier(ss[6:])
        return nm, 0, (), tuple(flags + ["class"]) if nm else (None, 0, (), tuple(flags))

    # function <T>(...) name may appear before/after; try to grab identifier nearest to '('
    name = _first_identifier(ss)
    # Arrow functions often appear as "identifier = (...)" or "const name = (...) =>"
    # Try pattern: identifier '=' '('
    m = re.search(rf"({IDENT_RE.pattern})\s*=\s*\(", ss)
    if m and "=>" in ss:
        nm = m.group(1)
        params = _slice_parens(ss[m.end()-1:], opener="(", closer=")")
        arity, types = _normalize_param_list_ts(params)
        return nm, arity, types, tuple(flags + ["arrow"])

    # Regular function / method declaration: name(...) or <T>(...) name?
    # Find the first identifier followed by '(' somewhere later
    if name:
        idx = ss.find(name)
        after_nm = ss[idx + len(name):]
        params = _slice_parens(after_nm, opener="(", closer=")")
        arity, types = _normalize_param_list_ts(params)
        return name, arity, types, tuple(flags)

    return None, 0, (), tuple(flags)

def _slice_parens(s: str, opener: str, closer: str) -> Optional[str]:
    """Return substring including balanced parens from the first opener; None if not found."""
    i = s.find(opener)
    if i < 0:
        return None
    depth = 0
    for j, ch in enumerate(s[i:], start=i):
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return s[i:j+1]
    return None

def _split_top_level(s: str, sep: str = ",") -> List[str]:
    out: List[str] = []
    depth = 0
    cur = []
    for ch in s:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out

def _coarse_type_token(t: str) -> str:
    # For TS: strip generics and module paths; for Py: keep base identifier
    t = t.strip()
    # remove generic payload <...>
    while "<" in t and ">" in t:
        t = re.sub(r"<[^<>]*>", "", t)
    # remove array suffixes and | unions compressively
    t = t.replace("[]", "[]")
    # keep first identifier-like token
    m = IDENT_RE.search(t)
    return m.group(0) if m else "?"

def _normalize_param_list_ts(param_block: Optional[str]) -> Tuple[int, Tuple[str, ...]]:
    if not param_block:
        return 0, ()
    inner = param_block.strip()[1:-1] if param_block.startswith("(") else param_block
    parts = _split_top_level(inner, ",")
    arity = 0
    types: List[str] = []
    for p in parts:
        t = p.strip()
        if not t:
            continue
        # Drop default values and param names; keep type annotation after ':'
        typ = None
        if ":" in t:
            typ = t.split(":", 1)[1].strip()
        if typ:
            types.append(_coarse_type_token(typ))
        else:
            types.append("?")
        arity += 1
    return arity, tuple(types[:32])

# ----------------------------- Public result type -----------------------------

@dataclass
class LiftResult:
    nodes: List[UCGNode]
    edges: List[UCGEdge]
    symbols: List[UCGNode]
    anomalies: List[Anomaly]
    metrics: Dict[str, object]

# ----------------------------- Main API --------------------------------------

def lift_to_ucg(
    path: str,
    blob_sha: str,
    parse: ParseResult,
    *,
    module_root: Optional[str] = None,
) -> LiftResult:
    anomalies: List[Anomaly] = []
    nodes: List[UCGNode] = []
    edges: List[UCGEdge] = []
    symbols: List[UCGNode] = []

    language = parse.language
    abs_path = Path(path).as_posix()
    module_qname = _infer_module_qname(abs_path, module_root)
    file_node_id = _node_id(SemanticType.FILE, language, abs_path, _span_key(abs_path, 0, 0))
    module_node_id = _node_id(SemanticType.MODULE, language, module_qname, _span_key(abs_path, 0, 0))

    file_node = UCGNode(
        node_id=file_node_id,
        semantic_type=SemanticType.FILE,
        raw_type="file",
        name=Path(abs_path).name,
        qualified_name=abs_path,
        language=language,
        spans=[Span(abs_path, 0, 0, 0, 0, 0, 0, "seed:file")],
        extra={"blob_sha256": blob_sha},
    )
    module_node = UCGNode(
        node_id=module_node_id,
        semantic_type=SemanticType.MODULE,
        raw_type="module",
        name=module_qname,
        qualified_name=module_qname,
        language=language,
        spans=[Span(abs_path, 0, 0, 0, 0, 0, 0, "seed:module")],
        extra={"blob_sha256": blob_sha},
    )
    nodes.extend([file_node, module_node])
    edges.append(_mk_edge("defines", file_node_id, module_node_id, Span(abs_path, 0, 0, 0, 0, 0, 0, "seed:defines")))

    # 1) First pass: collect candidate def sites with conservative name + signature
    def_sites: List[DefSite] = []
    for cap in parse.captures:
        sem_map = CAPTURE_KIND_TO_SEM.get(cap.kind)
        if not sem_map:
            anomalies.append(Anomaly(path=abs_path, blob_sha256=blob_sha,
                                     typ=AnomalyType.PARTIAL_PARSE, severity=Severity.INFO,
                                     reason_detail=f"Unknown capture kind: {cap.kind}"))
            continue
        sem, raw_kind = sem_map
        if sem not in (SemanticType.CLASS, SemanticType.FUNCTION, SemanticType.METHOD):
            continue

        sp = _cap_span(abs_path, cap)
        name, sig = _extract_name_and_sig(language, sem, cap.text_preview or "")
        def_sites.append(DefSite(sem=sem, raw_kind=raw_kind, name=name, span=sp, sig=sig))

    # 2) Build scope tree by interval containment so methods/inner functions attach to nearest parent
    _build_scope_tree(def_sites)

    # 3) Create nodes for defs with qualified names based on the scope tree
    for i, d in enumerate(def_sites):
        leaf = d.name or "<anonymous>"
        qname = _qname_chain(module_qname, def_sites, d.parent_idx, leaf) if d.parent_idx is not None \
                else f"{module_qname}::{leaf}"
        d.qname = qname
        span_key = _span_key(abs_path, d.span.byte_start, d.span.byte_end)
        nid = _node_id(d.sem, language, qname, span_key)
        d.node_id = nid

        sig_norm = d.sig.as_str() if d.sig else f"{leaf}()"
        sid = _sym_id(language, qname, d.raw_kind, sig_norm)
        d.symbol_id = sid

        # Emit def node
        nodes.append(UCGNode(
            node_id=nid,
            semantic_type=d.sem,
            raw_type=d.raw_kind,
            name=d.name,
            qualified_name=qname,
            language=language,
            spans=[d.span],
            extra={"symbol_id": sid, "signature": sig_norm},
        ))
        # Module defines node
        edges.append(_mk_edge("defines", module_node_id, nid, d.span))
        # Node defines its symbol (keeps symbol lookup simple)
        sym_node = UCGNode(
            node_id=sid,
            semantic_type=SemanticType.SYMBOL,
            raw_type="symbol",
            name=d.name,
            qualified_name=qname,
            language=language,
            spans=[d.span],
            extra={},
        )
        symbols.append(sym_node)
        edges.append(_mk_edge("defines", nid, sid, d.span))

    # 4) Non-def captures -> nodes
    for cap in parse.captures:
        sem_map = CAPTURE_KIND_TO_SEM.get(cap.kind)
        if not sem_map:
            continue
        sem, raw_kind = sem_map
        if sem in (SemanticType.CLASS, SemanticType.FUNCTION, SemanticType.METHOD):
            continue  # already handled

        sp = _cap_span(abs_path, cap)
        span_key = _span_key(abs_path, cap.byte_start, cap.byte_end)

        if sem == SemanticType.CALL:
            q = f"{module_qname}::call@{cap.byte_start}"
            nid = _node_id(SemanticType.CALL, language, q, span_key)
            nodes.append(UCGNode(
                node_id=nid, semantic_type=SemanticType.CALL, raw_type=raw_kind,
                name=None, qualified_name=q, language=language, spans=[sp],
                extra={"preview": cap.text_preview}
            ))
            edges.append(_mk_edge("defines", module_node_id, nid, sp))
            continue

        if sem in (SemanticType.IMPORT, SemanticType.EXPORT, SemanticType.LITERAL, SemanticType.TEMPLATE_PART):
            q = f"{module_qname}::{sem.value.lower()}@{cap.byte_start}"
            nid = _node_id(sem, language, q, span_key)
            nodes.append(UCGNode(
                node_id=nid, semantic_type=sem, raw_type=raw_kind,
                name=None, qualified_name=q, language=language, spans=[sp],
                extra={"preview": cap.text_preview}
            ))
            edges.append(_mk_edge("defines", module_node_id, nid, sp))
            continue

        # SYMBOL & everything else → create a symbol occurrence (placeholder)
        name = _first_identifier(cap.text_preview or "") or f"sym@{cap.byte_start}"
        q = f"{module_qname}::{name}"
        sid = _sym_id(language, q, "symbol", name)
        nodes.append(UCGNode(
            node_id=sid, semantic_type=SemanticType.SYMBOL, raw_type="symbol",
            name=name, qualified_name=q, language=language, spans=[sp], extra={}
        ))
        # Do not attach defines edge from Module for symbol occurrences; binding pass will connect.

    # 5) Sanity anomalies
    if not parse.captures and parse.metrics.node_count > 0:
        anomalies.append(Anomaly(
            path=abs_path, blob_sha256=blob_sha,
            typ=AnomalyType.PARTIAL_PARSE, severity=Severity.WARN,
            reason_detail="AST present but no captures; check queries/grammar pin."
        ))

    metrics = {
        "defs": sum(1 for d in def_sites),
        "calls": sum(1 for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] == SemanticType.CALL),
        "imports": sum(1 for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] == SemanticType.IMPORT),
        "exports": sum(1 for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] == SemanticType.EXPORT),
        "literals": sum(1 for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] in (SemanticType.LITERAL, SemanticType.TEMPLATE_PART)),
        "unknown_captures": sum(1 for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind) is None),
        "node_count": parse.metrics.node_count,
        "parse_time_ms": parse.metrics.parse_time_ms,
    }

    return LiftResult(nodes=nodes, edges=edges, symbols=symbols, anomalies=anomalies, metrics=metrics)

# ----------------------------- Internals --------------------------------------

def _cap_span(path: str, cap: Capture) -> Span:
    return Span(
        path=path,
        byte_start=cap.byte_start, byte_end=cap.byte_end,
        line_start=cap.line_start, col_start=cap.col_start,
        line_end=cap.line_end, col_end=cap.col_end,
        reason_label=cap.reason_label,
    )

def _mk_edge(kind: str, src: str, dst: str, span: Span) -> UCGEdge:
    return UCGEdge(
        edge_id=_edge_id(kind, src, dst, _span_key(span.path, span.byte_start, span.byte_end)),
        kind=kind,
        src_id=src,
        dst_id=dst,
        flags=["RESOLVED"],
        confidence=1.0,
        spans=[span],
        reason_label=span.reason_label,
    )

def _infer_module_qname(path: str, module_root: Optional[str]) -> str:
    p = Path(path)
    if module_root:
        try:
            root = Path(module_root).resolve()
            rel = Path(path).resolve().relative_to(root)
            return rel.as_posix()
        except Exception:
            return p.as_posix()
    return p.as_posix()

def _extract_name_and_sig(language: Language, sem: SemanticType, preview: str) -> Tuple[Optional[str], Optional[SigNorm]]:
    """
    Robust, language-aware extraction. Works from previews (span slices) produced by ts_driver.
    Never throws: returns (name, SigNorm|None). Missing info yields conservative SigNorm.
    """
    s = _strip_decorators_and_leading_markers(preview or "", language)
    if language == Language.PYTHON:
        nm, ar, tys, flags = _extract_py_def(s)
        if sem == SemanticType.METHOD and nm in ("__init__",):
            flags = tuple(sorted(set(flags) | {"ctor"}))
        if nm:
            return nm, SigNorm(nm, ar, tys, flags)
        return None, None

    # TS / JS
    nm, ar, tys, flags = _extract_ts_js_def(s)
    if nm:
        if sem == SemanticType.METHOD and "getter" in flags:
            # getter has 0-arity; keep distinct flag
            pass
        return nm, SigNorm(nm, ar, tys, flags)
    return None, None
