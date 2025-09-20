# provis_ucg/binding/resolver.py
from __future__ import annotations
# -----------------------------------------------------------------------------
# Binding & Scopes (Step 1 fast pass) — Production-hardened
#
# Purpose:
#   - Build intra-file lexical scopes (module → class → fn/method → inner fns)
#   - Parse IMPORT nodes' previews (or exact source via fallback) into bindings
#   - Emit edges: imports | aliases | references (local best-effort)
#   - Maintain alias index (alias simple name → canonical symbol id)
#   - Never fail silently: add anomalies with spans and reason_labels
#
# Non-goals:
#   - Cross-file resolution or whole-program call binding
#   - Precise typing beyond coarse tokens (typed enrichers backfill later)
#
# Determinism:
#   - Parent-child scope by byte-interval containment
#   - Sorted, content-addressed edge ids
# -----------------------------------------------------------------------------

import re
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Callable

from ..models import (
    Anomaly,
    AnomalyType,
    Language,
    Severity,
)
from ..normalize.lift import (
    UCGNode, UCGEdge, Span, SemanticType,
)

# ============================== Edge helpers ==================================

def _sha256_hex(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\0")
    return h.hexdigest()

def _span_key(sp: Span) -> str:
    return f"{sp.path}:{sp.byte_start}-{sp.byte_end}"

def _edge_id(kind: str, src: str, dst: str, sp: Span) -> str:
    return _sha256_hex("edge", kind, src, dst, _span_key(sp))[:24]

def _mk_edge(kind: str, src_id: str, dst_id: str, sp: Span,
             flags: List[str], confidence: float, reason_label: str) -> UCGEdge:
    return UCGEdge(
        edge_id=_edge_id(kind, src_id, dst_id, sp),
        kind=kind,
        src_id=src_id,
        dst_id=dst_id,
        flags=flags,
        confidence=confidence,
        spans=[sp],
        reason_label=reason_label,
    )

# ============================== Data structures ===============================

@dataclass
class ScopeEntry:
    """A symbol declared in a scope."""
    name: str
    node_id: str
    sem: SemanticType  # CLASS / FUNCTION / METHOD / SYMBOL (defs)
    qname: str

@dataclass
class ScopeFrame:
    """Lexical scope with byte interval for containment checks."""
    name: str
    node_id: str
    sem: SemanticType
    span: Span
    parent_idx: Optional[int]    # index into frames, or None for module
    qname: str
    symbols: Dict[str, ScopeEntry]  # by simple name

@dataclass
class ImportBinding:
    """Conservative parse of one import binding."""
    source: Optional[str]          # module/package path (if visible)
    imported_name: Optional[str]   # "foo" in "from x import foo" / "default" / "*"
    alias: Optional[str]           # "bar" in "import x as bar" or "{foo as bar}"
    kind: str                      # 'default' | 'named' | 'namespace' | 'star' | 'module'
    is_type_only: bool             # TS 'import type'
    span: Span
    reason: str

@dataclass
class BindingResult:
    edges: List[UCGEdge]
    alias_index: Dict[str, str]    # alias simple name -> canonical symbol node_id (placeholder id)
    anomalies: List[Anomaly]
    metrics: Dict[str, int]

# ============================== Public API ====================================

def build_scopes_and_symbols(nodes: List[UCGNode], *, language: Language) -> List[ScopeFrame]:
    """
    Build lexical scopes from UCG definition nodes for a single file.
    Order: sort by (start, -end), then assign parent by containment.
    """
    module_nodes = [n for n in nodes if n.semantic_type == SemanticType.MODULE]
    if not module_nodes:
        return []
    module = module_nodes[0]
    mspan = module.spans[0]
    frames: List[ScopeFrame] = [
        ScopeFrame(
            name=module.name or "<module>",
            node_id=module.node_id,
            sem=SemanticType.MODULE,
            span=mspan,
            parent_idx=None,
            qname=module.qualified_name or (module.name or ""),
            symbols={},
        )
    ]

    definers = [n for n in nodes if n.semantic_type in (SemanticType.CLASS, SemanticType.FUNCTION, SemanticType.METHOD)]
    order = sorted(definers, key=lambda n: (n.spans[0].byte_start, -n.spans[0].byte_end))
    stack: List[int] = [0]  # indices into frames (module at 0)

    for n in order:
        sp = n.spans[0]
        while len(stack) > 0 and not _encloses(frames[stack[-1]].span, sp):
            stack.pop()
        parent_idx = stack[-1] if stack else 0
        parent = frames[parent_idx]
        frame = ScopeFrame(
            name=n.name or "<anonymous>",
            node_id=n.node_id,
            sem=n.semantic_type,
            span=sp,
            parent_idx=parent_idx,
            qname=(n.qualified_name or f"{parent.qname}::{n.name or '<anonymous>'}"),
            symbols={},
        )
        frames.append(frame)
        stack.append(len(frames) - 1)

        simple = n.name or "<anonymous>"
        if simple not in parent.symbols:
            parent.symbols[simple] = ScopeEntry(name=simple, node_id=n.node_id, sem=n.semantic_type, qname=frame.qname)

    return frames

def resolve_aliases_and_imports(
    nodes: List[UCGNode],
    frames: List[ScopeFrame],
    *,
    language: Language,
    typed_hints: Optional[Dict] = None,
    get_source_slice: Optional[Callable[[str, int, int], str]] = None,  # (path, b0, b1) -> exact source
) -> BindingResult:
    """
    Resolve imports and aliases conservatively using IMPORT node previews/spans.
    Emits:
      - edges(kind='imports'): Import node -> canonical symbol placeholder
      - edges(kind='aliases'): local alias symbol -> canonical symbol
      - edges(kind='references'): symbol occurrences -> nearest local definition
    """
    anomalies: List[Anomaly] = []
    edges: List[UCGEdge] = []
    alias_index: Dict[str, str] = {}
    metrics = dict(imports_seen=0, imports_resolved=0, imports_partial=0, alias_edges=0, local_refs=0)

    module = next((f for f in frames if f.sem == SemanticType.MODULE), None)
    if not module:
        return BindingResult(edges=[], alias_index={}, anomalies=[], metrics=metrics)

    # --- Parse import nodes to bindings (robust to multi-import previews) ---
    import_nodes = [n for n in nodes if n.semantic_type == SemanticType.IMPORT]
    for imp in import_nodes:
        sp = imp.spans[0]
        metrics["imports_seen"] += 1
        preview = (imp.extra.get("preview") or "").strip()
        bset = _imports_from_preview(preview, language, sp, imp.raw_type)

        # Fallback: slice exact source if preview failed/truncated and callback is available
        if not bset and get_source_slice is not None:
            try:
                exact = get_source_slice(sp.path, sp.byte_start, sp.byte_end)
                bset = _imports_from_preview(exact, language, sp, imp.raw_type)
            except Exception:
                pass

        if not bset:
            anomalies.append(Anomaly(
                path=sp.path, blob_sha256="",
                typ=AnomalyType.UNCERTAIN_BINDING, severity=Severity.WARN,
                reason_detail=f"Unparsed import preview for {language.value}"
            ))
            continue

        for b in bset:
            canonical_key = f"{b.source or '<external>'}::{b.imported_name or '*'}"
            canonical_sym_id = _symbol_id_for_canonical(module.qname, canonical_key)

            alias_name = b.alias or b.imported_name
            if alias_name:
                alias_index.setdefault(alias_name, canonical_sym_id)
                edges.append(_mk_edge(
                    kind="aliases",
                    src_id=_symbol_id_for_alias(module.qname, alias_name),
                    dst_id=canonical_sym_id,
                    sp=b.span,
                    flags=["RESOLVED" if b.source else "PARTIAL"],
                    confidence=1.0 if b.source else 0.6,
                    reason_label=b.reason,
                ))
                metrics["imports_resolved"] += 1
                metrics["alias_edges"] += 1
            else:
                metrics["imports_partial"] += 1
                anomalies.append(Anomaly(
                    path=sp.path, blob_sha256="",
                    typ=AnomalyType.UNCERTAIN_BINDING, severity=Severity.WARN,
                    reason_detail=f"Import without alias/name: {b.reason}"
                ))

            edges.append(_mk_edge(
                kind="imports",
                src_id=imp.node_id,
                dst_id=canonical_sym_id,
                sp=b.span,
                flags=["RESOLVED" if b.source else "PARTIAL"],
                confidence=1.0 if b.source else 0.6,
                reason_label=b.reason,
            ))

    # --- Best-effort local references (symbols used that match local-def names) ---
    symbol_occurrences = [n for n in nodes if n.semantic_type == SemanticType.SYMBOL and n.raw_type == "symbol"]
    def_lookup = _build_def_lookup(frames)
    for sym in symbol_occurrences:
        sp = sym.spans[0]
        name = sym.name
        if not name:
            continue
        target = _nearest_def(def_lookup, frames, sp, name)
        if target:
            edges.append(_mk_edge(
                kind="references",
                src_id=sym.node_id,
                dst_id=target.node_id,
                sp=sp,
                flags=["RESOLVED"],
                confidence=0.9,
                reason_label="scope:nearest_def",
            ))
            metrics["local_refs"] += 1

    edges.sort(key=lambda e: (e.kind, e.src_id, e.dst_id, e.spans[0].byte_start if e.spans else 0))
    return BindingResult(edges=edges, alias_index=alias_index, anomalies=anomalies, metrics=metrics)

# ============================== Utilities =====================================

def _encloses(outer: Span, inner: Span) -> bool:
    return (outer.byte_start <= inner.byte_start) and (outer.byte_end >= inner.byte_end)

def _build_def_lookup(frames: List[ScopeFrame]) -> Dict[str, List[ScopeEntry]]:
    lut: Dict[str, List[ScopeEntry]] = {}
    for fr in frames:
        for name, sym in fr.symbols.items():
            lut.setdefault(name, []).append(sym)
    return lut

def _nearest_def(lut: Dict[str, List[ScopeEntry]], frames: List[ScopeFrame], sp: Span, name: str) -> Optional[ScopeEntry]:
    cands = lut.get(name)
    if not cands:
        return None
    ranked: List[Tuple[int, ScopeEntry]] = []
    for idx, fr in enumerate(frames):
        if name in fr.symbols and _encloses(fr.span, sp):
            depth = _depth(frames, idx)
            ranked.append((depth, fr.symbols[name]))
    if not ranked:
        # fallback to module-level if present
        for idx, fr in enumerate(frames):
            if fr.parent_idx is None and name in fr.symbols:
                ranked.append((0, fr.symbols[name]))
    if not ranked:
        return None
    ranked.sort(key=lambda t: -t[0])  # prefer deepest enclosing
    return ranked[0][1]

def _depth(frames: List[ScopeFrame], idx: int) -> int:
    d = 0
    j = idx
    while j is not None:
        j = frames[j].parent_idx
        d += 1
    return d

# -------- Alias/canonical symbol identity (within-file placeholders) ----------

def _symbol_id_for_alias(module_qname: str, alias_name: str) -> str:
    return _sha256_hex("sym", "alias", module_qname, alias_name)[:24]

def _symbol_id_for_canonical(module_qname: str, canonical_key: str) -> str:
    return _sha256_hex("sym", "canonical", module_qname, canonical_key)[:24]

# ============================== Import parsing (hardened) =====================

# Balanced split helpers (respect () [] {} <> nesting)
_BRACKETS_OPEN = "([{<"
_BRACKETS_CLOSE = ")]}>"
_PAIR = dict(zip(_BRACKETS_OPEN, _BRACKETS_CLOSE))

def _split_top_level_balanced(s: str, sep: str = ",") -> List[str]:
    out, buf = [], []
    stack = []
    i, L = 0, len(s)
    while i < L:
        ch = s[i]
        if ch in _BRACKETS_OPEN:
            stack.append(_PAIR[ch])
            buf.append(ch)
        elif ch in _BRACKETS_CLOSE:
            if stack and ch == stack[-1]:
                stack.pop()
            buf.append(ch)
        elif ch == sep and not stack:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        out.append("".join(buf).strip())
    return [p for p in out if p]

def _find_all_import_chunks_py(snippet: str) -> List[str]:
    chunks = []
    for raw in re.split(r"[;\n]+", snippet):
        t = raw.strip()
        if t.startswith("import ") or t.startswith("from "):
            chunks.append(t)
    return chunks

def _find_all_import_chunks_ts(snippet: str) -> List[str]:
    chunks = []
    text = " ".join(snippet.strip().split())
    for part in re.split(r";", text):
        t = part.strip()
        if t.startswith("import "):
            chunks.append(t)
    return chunks

# Python
def _parse_py_import(preview: str, sp: Span) -> List[ImportBinding]:
    res: List[ImportBinding] = []
    for chunk in _find_all_import_chunks_py(preview):
        m_from = re.match(r"^from\s+([A-Za-z0-9_\.]+)\s+import\s+(.+)$", chunk)
        if m_from:
            source = m_from.group(1)
            body = m_from.group(2).strip()
            parts = _split_top_level_balanced(body, ",")
            for p in parts:
                if p == "*":
                    res.append(ImportBinding(source=source, imported_name="*", alias=None,
                                             kind="star", is_type_only=False, span=sp, reason="py:from_import"))
                    continue
                if " as " in p:
                    name, alias = p.split(" as ", 1)
                    res.append(ImportBinding(source=source, imported_name=name.strip(), alias=alias.strip(),
                                             kind="named", is_type_only=False, span=sp, reason="py:from_import_as"))
                else:
                    name = p.strip()
                    res.append(ImportBinding(source=source, imported_name=name, alias=name,
                                             kind="named", is_type_only=False, span=sp, reason="py:from_import"))
            continue

        m_imp = re.match(r"^import\s+(.+)$", chunk)
        if m_imp:
            body = m_imp.group(1).strip()
            parts = _split_top_level_balanced(body, ",")
            for p in parts:
                if " as " in p:
                    name, alias = p.split(" as ", 1)
                    res.append(ImportBinding(source=name.strip(), imported_name=None, alias=alias.strip(),
                                             kind="module", is_type_only=False, span=sp, reason="py:import_as"))
                else:
                    name = p.strip()
                    res.append(ImportBinding(source=name, imported_name=None, alias=name,
                                             kind="module", is_type_only=False, span=sp, reason="py:import"))
    return res

# TS/JS
_TS_IMPORT_TYPE_RE = re.compile(r"\bimport\s+type\b", re.IGNORECASE)

def _parse_ts_js_import(preview: str, sp: Span) -> List[ImportBinding]:
    res: List[ImportBinding] = []
    for chunk in _find_all_import_chunks_ts(preview):
        is_type_only = bool(_TS_IMPORT_TYPE_RE.search(chunk))

        # Bare: import "module"
        m_bare = re.match(r'^import\s+["\']([^"\']+)["\']$', chunk)
        if m_bare:
            src = m_bare.group(1)
            res.append(ImportBinding(source=src, imported_name="*", alias=None, kind="star",
                                     is_type_only=is_type_only, span=sp, reason="ts:bare_import"))
            continue

        # import <clause> from "module"
        m_from = re.match(r'^import\s+(.+?)\s+from\s+["\']([^"\']+)["\']$', chunk)
        if not m_from:
            # (Dynamic or unusual forms are skipped conservatively)
            continue

        clause = m_from.group(1).strip()
        source = m_from.group(2).strip()

        # Namespace: * as ns
        m_ns = re.match(r'^\*\s+as\s+([A-Za-z_$][\w$]*)$', clause)
        if m_ns:
            res.append(ImportBinding(source=source, imported_name="*", alias=m_ns.group(1),
                                     kind="namespace", is_type_only=is_type_only, span=sp, reason="ts:namespace"))
            continue

        # Default (maybe followed by named)
        if clause and not clause.startswith("{"):
            default_name, named_tail = clause, None
            if "," in clause:
                default_name, named_tail = clause.split(",", 1)
                default_name = default_name.strip()
                named_tail = named_tail.strip()
            if default_name:
                res.append(ImportBinding(source=source, imported_name="default", alias=default_name,
                                         kind="default", is_type_only=is_type_only, span=sp, reason="ts:default"))
            clause = named_tail or ""

        # Named: { a, b as c }
        if clause.startswith("{"):
            inner = clause.strip()
            if inner.endswith("}"):
                inner = inner[1:-1].strip()
            parts = _split_top_level_balanced(inner, ",")
            for p in parts:
                if not p:
                    continue
                if " as " in p:
                    name, alias = p.split(" as ", 1)
                    res.append(ImportBinding(source=source, imported_name=name.strip(), alias=alias.strip(),
                                             kind="named", is_type_only=is_type_only, span=sp, reason="ts:named_as"))
                else:
                    name = p.strip()
                    res.append(ImportBinding(source=source, imported_name=name, alias=name,
                                             kind="named", is_type_only=is_type_only, span=sp, reason="ts:named"))
    return res

def _imports_from_preview(preview: str, language: Language, sp: Span, raw_kind: str) -> List[ImportBinding]:
    if language == Language.PYTHON:
        return _parse_py_import(preview, sp)
    else:
        return _parse_ts_js_import(preview, sp)
