# provis_ucg/normalize/lift.py
from __future__ import annotations
# -----------------------------------------------------------------------------
# Lift Tree-sitter ParseResult -> Uniform Code Graph (UCG) IR (production-hardened)
#
# This version extends your implementation with:
# - Grouping of captures into single logical statement nodes (imports/exports/calls)
# - Caller→Call and Call→Callee placeholder edges
# - Conservative import alias extraction (JS/TS + Python)
# - Placeholder Symbol nodes for imported names and callees
# - Deterministic ordering and richer metrics
# - No silent drops: WARN anomalies emitted for unknown capture kinds
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

CAPTURE_KIND_TO_SEM: Dict[str, Tuple[SemanticType, str]] = {
    # Python
    "def.func":            (SemanticType.FUNCTION, "function"),
    "def.method":          (SemanticType.METHOD,   "method"),
    "def.class":           (SemanticType.CLASS,    "class"),
    # JS/TS defs
    "def.arrow":           (SemanticType.FUNCTION, "arrow_function"),
    "def.var_func":        (SemanticType.FUNCTION, "function_expression"),
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
    "import.named":        (SemanticType.SYMBOL,   "import_named"),
    "import.default":      (SemanticType.SYMBOL,   "import_default"),
    "import.alias":        (SemanticType.SYMBOL,   "import_alias"),
    "export.stmt":         (SemanticType.EXPORT,   "export"),
    # Literals/templates
    "lit.string":          (SemanticType.LITERAL,        "string"),
    "lit.template":        (SemanticType.TEMPLATE_PART,  "template"),
}

# ----------------------------- Identifier patterns ----------------------------

_ID_START = r"[^\W\d_]|_|$"
_ID_CONT  = r"[^\W_]|_|$|\d"
IDENT_RE  = re.compile(fr"({_ID_START})(({_ID_CONT})*)", re.UNICODE)

# ----------------------------- Signature normalization ------------------------

@dataclass(frozen=True)
class SigNorm:
    name: str
    arity: int
    types: Tuple[str, ...]
    flags: Tuple[str, ...]
    def as_str(self) -> str:
        types_str = ",".join(self.types) if self.types else ""
        flags_str = ",".join(sorted(self.flags)) if self.flags else ""
        return f"{self.name}({self.arity})|{types_str}|{flags_str}"

# ----------------------------- Scope tree from spans --------------------------

@dataclass
class DefSite:
    sem: SemanticType
    raw_kind: str
    name: Optional[str]
    span: Span
    sig: Optional[SigNorm]
    parent_idx: Optional[int] = None
    qname: Optional[str] = None
    node_id: Optional[str] = None
    symbol_id: Optional[str] = None

def _encloses(outer: Span, inner: Span) -> bool:
    return (outer.byte_start <= inner.byte_start) and (outer.byte_end >= inner.byte_end)

def _build_scope_tree(defs: List[DefSite]) -> None:
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
    for ln in lines:
        if language == Language.PYTHON and ln.lstrip().startswith("@"):
            continue
        out.append(ln)
        if ln.strip():
            break
    return "\n".join(out)

def _first_identifier(s: str) -> Optional[str]:
    m = IDENT_RE.search(s)
    return m.group(0) if m else None

def _extract_py_def(s: str) -> Tuple[Optional[str], int, Tuple[str, ...], Tuple[str, ...]]:
    flags: List[str] = []
    ss = s.strip()
    if ss.startswith("async"):
        flags.append("async")
        ss = ss[5:].lstrip()
    if ss.startswith("def "):
        after = ss[4:]
        name = _first_identifier(after)
        if not name:
            return None, 0, (), tuple(flags)
        params = _slice_parens(after, opener="(", closer=")")
        arity, types = _normalize_param_list_python(params)
        return name, arity, types, tuple(flags)
    if ss.startswith("class "):
        after = ss[6:]
        name = _first_identifier(after)
        if not name:
            return None, 0, (), tuple(flags)
        flags.append("class")
        return name, 0, (), tuple(flags)
    name = _first_identifier(ss)
    return (name, 0, (), tuple(flags)) if name else (None, 0, (), tuple(flags))

def _normalize_param_list_python(param_block: Optional[str]) -> Tuple[int, Tuple[str, ...]]:
    if not param_block:
        return 0, ()
    inner = param_block.strip()[1:-1] if param_block.startswith("(") else param_block
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
            types.append("**"); arity += 1; continue
        if t.startswith("*"):
            types.append("*"); arity += 1; continue
        typ = None
        if ":" in t:
            typ = t.split(":", 1)[1].strip()
        types.append(_coarse_type_token(typ) if typ else "?")
        arity += 1
    return arity, tuple(types[:32])

def _extract_ts_js_def(s: str) -> Tuple[Optional[str], int, Tuple[str, ...], Tuple[str, ...]]:
    ss = s.strip()
    flags: List[str] = []
    if ss.startswith("get "):
        flags.append("getter"); ss = ss[4:].lstrip()
    if ss.startswith("set "):
        flags.append("setter"); ss = ss[4:].lstrip()
    if ss.startswith("async "):
        flags.append("async"); ss = ss[6:].lstrip()
    if ss.startswith("class "):
        nm = _first_identifier(ss[6:])
        return nm, 0, (), tuple(flags + (["class"] if nm else []))
    name = _first_identifier(ss)
    m = re.search(rf"({IDENT_RE.pattern})\s*=\s*\(", ss)
    if m and "=>" in ss:
        nm = m.group(1)
        params = _slice_parens(ss[m.end()-1:], opener="(", closer=")")
        arity, types = _normalize_param_list_ts(params)
        return nm, arity, types, tuple(flags + ["arrow"])
    if name:
        idx = ss.find(name)
        after_nm = ss[idx + len(name):]
        params = _slice_parens(after_nm, opener="(", closer=")")
        arity, types = _normalize_param_list_ts(params)
        return name, arity, types, tuple(flags)
    return None, 0, (), tuple(flags)

def _slice_parens(s: str, opener: str, closer: str) -> Optional[str]:
    i = s.find(opener)
    if i < 0: return None
    depth = 0
    for j, ch in enumerate(s[i:], start=i):
        if ch == opener: depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0: return s[i:j+1]
    return None

def _split_top_level(s: str, sep: str = ",") -> List[str]:
    out: List[str] = []
    depth = 0; cur = []
    for ch in s:
        if ch in "([{<": depth += 1
        elif ch in ")]}>": depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out

def _coarse_type_token(t: Optional[str]) -> str:
    if not t: return "?"
    x = t.strip()
    while "<" in x and ">" in x:
        x = re.sub(r"<[^<>]*>", "", x)
    m = IDENT_RE.search(x)
    return m.group(0) if m else "?"

def _normalize_param_list_ts(param_block: Optional[str]) -> Tuple[int, Tuple[str, ...]]:
    if not param_block: return 0, ()
    inner = param_block.strip()[1:-1] if param_block.startswith("(") else param_block
    parts = _split_top_level(inner, ",")
    arity = 0; types: List[str] = []
    for p in parts:
        t = p.strip()
        if not t: continue
        typ = t.split(":", 1)[1].strip() if ":" in t else None
        types.append(_coarse_type_token(typ))
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
        node_id=file_node_id, semantic_type=SemanticType.FILE, raw_type="file",
        name=Path(abs_path).name, qualified_name=abs_path, language=language,
        spans=[Span(abs_path, 0, 0, 0, 0, 0, 0, "seed:file")],
        extra={"blob_sha256": blob_sha},
    )
    module_node = UCGNode(
        node_id=module_node_id, semantic_type=SemanticType.MODULE, raw_type="module",
        name=module_qname, qualified_name=module_qname, language=language,
        spans=[Span(abs_path, 0, 0, 0, 0, 0, 0, "seed:module")],
        extra={"blob_sha256": blob_sha},
    )
    nodes.extend([file_node, module_node])
    edges.append(_mk_edge("defines", file_node_id, module_node_id, Span(abs_path, 0, 0, 0, 0, 0, 0, "seed:defines")))

    # 1) Collect def sites
    def_sites: List[DefSite] = []
    unknown_count = 0
    for cap in parse.captures:
        sem_map = CAPTURE_KIND_TO_SEM.get(cap.kind)
        if not sem_map:
            unknown_count += 1
            anomalies.append(Anomaly(path=abs_path, blob_sha256=blob_sha,
                                     typ=AnomalyType.PARTIAL_PARSE, severity=Severity.WARN,
                                     reason_detail=f"Unknown capture kind: {cap.kind}"))
            continue
        sem, raw_kind = sem_map
        if sem not in (SemanticType.CLASS, SemanticType.FUNCTION, SemanticType.METHOD):
            continue
        sp = _cap_span(abs_path, cap)
        name, sig = _extract_name_and_sig(language, sem, cap.text_preview or "")
        def_sites.append(DefSite(sem=sem, raw_kind=raw_kind, name=name, span=sp, sig=sig))

    # 2) Scope tree (nested containment)
    _build_scope_tree(def_sites)

    # 3) Materialize def nodes + symbol nodes
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

        nodes.append(UCGNode(
            node_id=nid, semantic_type=d.sem, raw_type=d.raw_kind,
            name=d.name, qualified_name=qname, language=language,
            spans=[d.span], extra={"symbol_id": sid, "signature": sig_norm},
        ))
        edges.append(_mk_edge("defines", module_node_id, nid, d.span))
        sym_node = UCGNode(
            node_id=sid, semantic_type=SemanticType.SYMBOL, raw_type="symbol",
            name=d.name, qualified_name=qname, language=language,
            spans=[d.span], extra={},
        )
        symbols.append(sym_node)
        edges.append(_mk_edge("defines", nid, sid, d.span))

    # Build index for caller lookup
    decl_spans = sorted([(d.span, d.node_id) for d in def_sites], key=lambda x: (x[0].byte_start, -x[0].byte_end))

    # 4) Group & materialize IMPORT/EXPORT/CALL + placeholders
    import_caps: List[Capture] = [c for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] == SemanticType.IMPORT]
    export_caps: List[Capture] = [c for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] == SemanticType.EXPORT]
    call_caps:   List[Capture] = [c for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] == SemanticType.CALL]
    sym_caps:    List[Capture] = [c for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] == SemanticType.SYMBOL]
    lit_caps:    List[Capture] = [c for c in parse.captures if CAPTURE_KIND_TO_SEM.get(c.kind, (None, ""))[0] in (SemanticType.LITERAL, SemanticType.TEMPLATE_PART)]

    # Group helpers
    def _group(caps: List[Capture]) -> List[Tuple[Span, List[Capture]]]:
        if not caps: return []
        cs = sorted(caps, key=lambda c: (c.byte_start, c.byte_end))
        groups: List[Tuple[Span, List[Capture]]] = []
        buf: List[Capture] = []
        b0 = b1 = None
        for c in cs:
            if not buf:
                buf = [c]; b0, b1 = c.byte_start, c.byte_end; continue
            if c.byte_start <= b1:  # overlap → same statement
                buf.append(c); b1 = max(b1, c.byte_end)
            else:
                groups.append((Span(abs_path, b0, b1, buf[0].line_start, buf[0].col_start, buf[-1].line_end, buf[-1].col_end, "group"), buf))
                buf = [c]; b0, b1 = c.byte_start, c.byte_end
        if buf:
            groups.append((Span(abs_path, b0, b1, buf[0].line_start, buf[0].col_start, buf[-1].line_end, buf[-1].col_end, "group"), buf))
        return groups

    # Imports
    for gspan, gcaps in _group(import_caps + [c for c in sym_caps if c.kind.startswith("import.")]):
        span_key = _span_key(abs_path, gspan.byte_start, gspan.byte_end)
        q = f"{module_qname}::import@{gspan.byte_start}"
        import_id = _node_id(SemanticType.IMPORT, language, q, span_key)
        nodes.append(UCGNode(
            node_id=import_id, semantic_type=SemanticType.IMPORT, raw_type=";".join(sorted({c.kind for c in gcaps})),
            name=None, qualified_name=q, language=language, spans=[gspan],
            extra={"previews": [c.text_preview for c in gcaps if c.text_preview]},
        ))
        edges.append(_mk_edge("defines", module_node_id, import_id, gspan))

        # Infer alias names and create placeholder symbols; wire import → symbol (UNRESOLVED)
        for alias in _infer_import_aliases(gcaps, language):
            sym_q = f"{module_qname}::{alias}"
            sid = _sym_id(language, sym_q, "import", alias)
            sym_node = UCGNode(
                node_id=sid, semantic_type=SemanticType.SYMBOL, raw_type="import.symbol",
                name=alias, qualified_name=sym_q, language=language, spans=[gspan], extra={},
            )
            symbols.append(sym_node)
            edges.append(UCGEdge(
                edge_id=_edge_id("imports", import_id, sid, span_key),
                kind="imports", src_id=import_id, dst_id=sid,
                flags=["UNRESOLVED"], confidence=0.4, spans=[gspan], reason_label="normalize:import.binds",
            ))

    # Exports
    for gspan, gcaps in _group(export_caps):
        span_key = _span_key(abs_path, gspan.byte_start, gspan.byte_end)
        q = f"{module_qname}::export@{gspan.byte_start}"
        export_id = _node_id(SemanticType.EXPORT, language, q, span_key)
        nodes.append(UCGNode(
            node_id=export_id, semantic_type=SemanticType.EXPORT, raw_type=";".join(sorted({c.kind for c in gcaps})),
            name=None, qualified_name=q, language=language, spans=[gspan],
            extra={"previews": [c.text_preview for c in gcaps if c.text_preview]},
        ))
        edges.append(_mk_edge("defines", module_node_id, export_id, gspan))

    # Calls (group call.* + their nearby symbol captures)
    for gspan, gcaps in _group(call_caps + [c for c in sym_caps if c.kind.startswith("call.")]):
        span_key = _span_key(abs_path, gspan.byte_start, gspan.byte_end)
        q = f"{module_qname}::call@{gspan.byte_start}"
        call_id = _node_id(SemanticType.CALL, language, q, span_key)
        nodes.append(UCGNode(
            node_id=call_id, semantic_type=SemanticType.CALL, raw_type=";".join(sorted({c.kind for c in gcaps})),
            name=None, qualified_name=q, language=language, spans=[gspan],
            extra={"previews": [c.text_preview for c in gcaps if c.text_preview]},
        ))
        edges.append(_mk_edge("defines", module_node_id, call_id, gspan))

        # Caller: nearest enclosing def by containment
        caller = _nearest_enclosing_decl(decl_spans, gspan.byte_start, gspan.byte_end)
        if caller:
            edges.append(UCGEdge(
                edge_id=_edge_id("calls", caller, call_id, span_key),
                kind="calls", src_id=caller, dst_id=call_id,
                flags=["RESOLVED"], confidence=1.0, spans=[gspan], reason_label="normalize:callsite",
            ))

        # Callee placeholder symbol from previews
        callee_name = _infer_callee_name_from_group(gcaps)
        if callee_name:
            sym_q = callee_name  # raw; binding will resolve to qname later
            sid = _sym_id(language, sym_q, "symbol.ref", "")
            sym_node = UCGNode(
                node_id=sid, semantic_type=SemanticType.SYMBOL, raw_type="symbol.ref",
                name=callee_name, qualified_name=sym_q, language=language, spans=[gspan], extra={},
            )
            symbols.append(sym_node)
            edges.append(UCGEdge(
                edge_id=_edge_id("calls", call_id, sid, span_key),
                kind="calls", src_id=call_id, dst_id=sid,
                flags=["UNRESOLVED"], confidence=0.5, spans=[gspan], reason_label="normalize:callee",
            ))

    # Literals/templates
    for c in lit_caps:
        sp = _cap_span(abs_path, c)
        span_key = _span_key(abs_path, c.byte_start, c.byte_end)
        sem, raw = CAPTURE_KIND_TO_SEM.get(c.kind, (SemanticType.LITERAL, "literal"))
        q = f"{module_qname}::{sem.value.lower()}@{c.byte_start}"
        nid = _node_id(sem, language, q, span_key)
        nodes.append(UCGNode(
            node_id=nid, semantic_type=sem, raw_type=raw,
            name=None, qualified_name=q, language=language, spans=[sp],
            extra={"preview": c.text_preview},
        ))
        edges.append(_mk_edge("defines", module_node_id, nid, sp))

    # 5) Sanity anomalies
    if not parse.captures and parse.metrics.node_count > 0:
        anomalies.append(Anomaly(
            path=abs_path, blob_sha256=blob_sha,
            typ=AnomalyType.PARTIAL_PARSE, severity=Severity.WARN,
            reason_detail="AST present but no captures; check queries/grammar pin."
        ))

    # Deterministic ordering
    nodes.sort(key=lambda n: (n.language.value, n.semantic_type.value, n.qualified_name or "", n.spans[0].byte_start))
    symbols.sort(key=lambda n: (n.qualified_name or "", n.spans[0].byte_start))
    edges.sort(key=lambda e: (e.kind, e.src_id, e.dst_id, e.spans[0].byte_start))

    metrics = {
        "defs": len(def_sites),
        "calls": len(call_caps),
        "imports": len(import_caps),
        "exports": len(export_caps),
        "literals": len(lit_caps),
        "unknown_captures": unknown_count,
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
        kind=kind, src_id=src, dst_id=dst,
        flags=["RESOLVED"], confidence=1.0,
        spans=[span], reason_label=span.reason_label,
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
    s = _strip_decorators_and_leading_markers(preview or "", language)
    if language == Language.PYTHON:
        nm, ar, tys, flags = _extract_py_def(s)
        if sem == SemanticType.METHOD and nm in ("__init__",):
            flags = tuple(sorted(set(flags) | {"ctor"}))
        return (nm, SigNorm(nm, ar, tys, flags)) if nm else (None, None)
    nm, ar, tys, flags = _extract_ts_js_def(s)
    return (nm, SigNorm(nm, ar, tys, flags)) if nm else (None, None)

# --------- New helpers: grouping, caller lookup, import/callee inference ------

def _nearest_enclosing_decl(decl_spans: List[Tuple[Span, str]], b0: int, b1: int) -> Optional[str]:
    # decl_spans sorted by start asc, end desc
    best: Optional[Tuple[int, str]] = None  # (area, node_id)
    for sp, nid in decl_spans:
        if sp.byte_start <= b0 and b1 <= sp.byte_end:
            area = sp.byte_end - sp.byte_start
            if best is None or area < best[0]:
                best = (area, nid)
    return best[1] if best else None

def _infer_import_aliases(caps: List[Capture], language: Language) -> List[str]:
    previews = " ".join(c.text_preview or "" for c in caps)
    previews = " ".join(previews.split())
    out: List[str] = []

    if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        # default: import Foo from 'x'
        m = re.search(r"\bimport\s+([A-Za-z0-9_$]+)\s+from\b", previews)
        if m: out.append(m.group(1))
        # named: import { A as B, C } from 'x'
        brace = re.search(r"\{([^}]*)\}", previews)
        if brace:
            inside = brace.group(1)
            for part in _split_top_level(inside, ","):
                t = part.strip()
                if not t: continue
                if " as " in t:
                    out.append(t.split(" as ", 1)[1].strip())
                else:
                    out.append(t.split()[0].strip())
    elif language == Language.PYTHON:
        # from pkg import a as b, c
        m = re.search(r"\bfrom\b.+\bimport\b(.+)", previews)
        if m:
            tail = m.group(1)
            for part in _split_top_level(tail, ","):
                t = part.strip()
                if not t: continue
                if " as " in t:
                    out.append(t.split(" as ", 1)[1].strip())
                else:
                    out.append(t.split()[0].strip())
        # import os, sys as s
        elif previews.strip().startswith("import "):
            tail = previews.strip()[len("import "):]
            for part in _split_top_level(tail, ","):
                t = part.strip()
                if not t: continue
                if " as " in t:
                    out.append(t.split(" as ", 1)[1].strip())
                else:
                    out.append(t.split(".", 1)[0].strip())

    # de-dupe stable
    seen = set(); uniq: List[str] = []
    for n in out:
        n2 = _sanitize_ident(n)
        if n2 and n2 not in seen:
            seen.add(n2); uniq.append(n2)
    return uniq

def _infer_callee_name_from_group(caps: List[Capture]) -> Optional[str]:
    # Prefer more specific captures
    byk = {c.kind: c for c in caps}
    for k in ("call.method", "call.func", "call.constructor", "call.callee"):
        c = byk.get(k)
        if c and c.text_preview:
            return _sanitize_ident(c.text_preview)
    # fallback to any token in previews
    for c in caps:
        if c.text_preview:
            ident = _sanitize_ident(c.text_preview)
            if ident: return ident
    return None

def _sanitize_ident(s: str) -> str:
    m = IDENT_RE.search(s)
    return m.group(0) if m else ""

