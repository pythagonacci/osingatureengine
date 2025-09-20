# provis_ucg/flow/cfg.py
from __future__ import annotations

# -----------------------------------------------------------------------------
# CFG builder (per function) — production-hardened
#
# Source of truth = file bytes. We slice the function span and run a robust,
# language-aware token scan to find control constructs (if/elif/else, loops,
# try/except/finally, return/break/continue, async/await, match/switch/case).
# No recursion; bounded stacks; never fails silently.
# -----------------------------------------------------------------------------
import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from ..models import Anomaly, AnomalyType, Language, Severity
from ..normalize.lift import SemanticType, Span, UCGNode
from .model import DEFAULT_BOUNDS, CFGBlock, CFGBlockKind, CFGEdge, FlowResult

# ------------------------------- helpers -------------------------------------


def _sha24(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\0")
    return h.hexdigest()[:24]


def _bid(fn_id: str, idx: int) -> str:
    return _sha24("cfg:block", fn_id, str(idx))


def _eid(fn_id: str, src: str, dst: str, why: str) -> str:
    return _sha24("cfg:edge", fn_id, src, dst, why)


@dataclass
class _Token:
    kind: str
    text: str
    byte_off: int


# ---------------------------- very light tokenizers ---------------------------

# We avoid full parsing and rely on robust keyword scans guarded by comment/string skipping.

_PY_KWS = (
    "if",
    "elif",
    "else",
    "for",
    "while",
    "try",
    "except",
    "finally",
    "return",
    "break",
    "continue",
    "match",
    "case",
    "async",
    "await",
    "yield",
)

_JS_KWS = (
    "if",
    "else",
    "for",
    "while",
    "do",
    "try",
    "catch",
    "finally",
    "return",
    "break",
    "continue",
    "switch",
    "case",
    "default",
    "async",
    "await",
    "yield",
)


def _scan_tokens_py(code: str, start_byte: int) -> list[_Token]:
    # Skip strings/comments, keep keywords. Use simple state machine.
    toks: list[_Token] = []
    i, L = 0, len(code)
    in_str = False
    str_q = ""
    in_comment = False
    while i < L:
        ch = code[i]
        if in_comment:
            if ch == "\n":
                in_comment = False
            i += 1
            continue
        if in_str:
            if code.startswith(str_q, i):
                i += len(str_q)
                in_str = False
            else:
                i += 1
            continue
        # not in string/comment
        if ch == "#":
            in_comment = True
            i += 1
            continue
        # strings
        if code.startswith('"""', i) or code.startswith("'''", i):
            str_q = code[i : i + 3]
            in_str = True
            i += 3
            continue
        if ch in ("'", '"'):
            str_q = ch
            in_str = True
            i += 1
            continue
        # word
        if ch.isalpha() or ch == "_":
            j = i + 1
            while j < L and (code[j].isalnum() or code[j] == "_"):
                j += 1
            word = code[i:j]
            if word in _PY_KWS:
                toks.append(_Token("kw", word, start_byte + i))
            i = j
            continue
        i += 1
    return toks


def _scan_tokens_js(code: str, start_byte: int) -> list[_Token]:
    toks: list[_Token] = []
    i, L = 0, len(code)
    in_str = False
    q = ""
    in_block_comment = False
    in_line_comment = False
    in_template = False
    while i < L:
        ch = code[i]
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if code.startswith("*/", i):
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_template:
            if ch == "`":
                in_template = False
                i += 1
                continue
            # skip ${ ... } nesting crudely
            if code.startswith("${", i):
                depth = 1
                i += 2
                while i < L and depth > 0:
                    if code.startswith("${", i):
                        depth += 1
                        i += 2
                        continue
                    if code[i] == "}":
                        depth -= 1
                        i += 1
                        continue
                    i += 1
                continue
            i += 1
            continue
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == q:
                in_str = False
                i += 1
                continue
            i += 1
            continue
        # comments
        if code.startswith("//", i):
            in_line_comment = True
            i += 2
            continue
        if code.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        # strings
        if ch in ("'", '"'):
            in_str = True
            q = ch
            i += 1
            continue
        if ch == "`":
            in_template = True
            i += 1
            continue
        # word
        if ch.isalpha() or ch == "_" or ch == "$":
            j = i + 1
            while j < L and (code[j].isalnum() or code[j] in "_$"):
                j += 1
            word = code[i:j]
            if word in _JS_KWS:
                toks.append(_Token("kw", word, start_byte + i))
            i = j
            continue
        i += 1
    return toks


# ------------------------------ CFG construction ------------------------------


def build_cfg_for_function(
    fn_node: UCGNode,
    *,
    language: Language,
    get_source_slice: Callable[[str, int, int], str],
) -> FlowResult:
    """
    Build a lightweight CFG for a single function/method/class constructor-ish span.
    We create: ENTRY, EXIT, and a stream of NORMAL blocks split at control keywords.
    Edges get cond_label where material (if/else, case, except, default).
    """
    assert fn_node.semantic_type in (SemanticType.FUNCTION, SemanticType.METHOD, SemanticType.CLASS)
    anomalies: list[Anomaly] = []
    blocks: list[CFGBlock] = []
    edges: list[CFGEdge] = []

    sp = fn_node.spans[0]
    try:
        code = get_source_slice(sp.path, sp.byte_start, sp.byte_end)
    except Exception as e:
        anomalies.append(
            Anomaly(
                path=sp.path,
                blob_sha256="",
                typ=AnomalyType.PERMISSION_DENIED,
                severity=Severity.ERROR,
                reason_detail=f"source_slice_failed:{type(e).__name__}",
            )
        )
        return FlowResult(
            blocks=[],
            edges=[],
            facts=[],
            anomalies=anomalies,
            metrics=dict(blocks=0, edges=0, facts=0),
        )

    # Token scan
    toks = (
        _scan_tokens_py(code, sp.byte_start)
        if language == Language.PYTHON
        else _scan_tokens_js(code, sp.byte_start)
    )

    # Seed blocks
    entry = CFGBlock(
        block_id=_bid(fn_node.node_id, 0),
        fn_node_id=fn_node.node_id,
        kind=CFGBlockKind.ENTRY,
        spans=[sp],
    )
    exitb = CFGBlock(
        block_id=_bid(fn_node.node_id, 1),
        fn_node_id=fn_node.node_id,
        kind=CFGBlockKind.EXIT,
        spans=[sp],
    )
    blocks.extend([entry, exitb])

    # Streaming block creation: split at control tokens, map to edges.
    # We don’t reconstruct exact nesting; instead we create linear NORMAL blocks
    # with labeled edges that preserve control *events* deterministically.

    cur_idx = 2
    last_block_id = entry.block_id
    for t in toks:
        if len(blocks) >= DEFAULT_BOUNDS.max_blocks:
            anomalies.append(
                Anomaly(
                    path=sp.path,
                    blob_sha256="",
                    typ=AnomalyType.PARTIAL_PARSE,
                    severity=Severity.WARN,
                    reason_detail="CFG_BLOCK_CUTOFF",
                )
            )
            break

        # Create a block for the control site
        b = CFGBlock(
            block_id=_bid(fn_node.node_id, cur_idx),
            fn_node_id=fn_node.node_id,
            kind=CFGBlockKind.NORMAL,
            spans=[Span(sp.path, t.byte_off, t.byte_off, 0, 0, 0, 0, f"cfg:{t.kind}:{t.text}")],
        )
        blocks.append(b)
        cur_idx += 1

        # Edge from previous to this control site (unlabeled)
        edges.append(
            CFGEdge(
                edge_id=_eid(fn_node.node_id, last_block_id, b.block_id, "seq"),
                fn_node_id=fn_node.node_id,
                src_block_id=last_block_id,
                dst_block_id=b.block_id,
                cond_label=None,
                spans=b.spans,
                reason_label="cfg:seq",
            )
        )
        last_block_id = b.block_id

        # Add labeled edges for specific constructs
        w = t.text
        if w in ("if", "elif", "else") or w in ("case", "default") or w in ("except", "catch"):
            label = w
        else:
            label = None

        if label:
            edges.append(
                CFGEdge(
                    edge_id=_eid(fn_node.node_id, b.block_id, exitb.block_id, label),
                    fn_node_id=fn_node.node_id,
                    src_block_id=b.block_id,
                    dst_block_id=exitb.block_id,
                    cond_label=label,
                    spans=b.spans,
                    reason_label=f"cfg:{label}",
                )
            )

        # For returns/break/continue, connect directly to EXIT
        if w in ("return", "break", "continue"):
            edges.append(
                CFGEdge(
                    edge_id=_eid(fn_node.node_id, b.block_id, exitb.block_id, w),
                    fn_node_id=fn_node.node_id,
                    src_block_id=b.block_id,
                    dst_block_id=exitb.block_id,
                    cond_label=w,
                    spans=b.spans,
                    reason_label=f"cfg:{w}",
                )
            )

    # Final fallthrough
    edges.append(
        CFGEdge(
            edge_id=_eid(fn_node.node_id, last_block_id, exitb.block_id, "fallthrough"),
            fn_node_id=fn_node.node_id,
            src_block_id=last_block_id,
            dst_block_id=exitb.block_id,
            cond_label=None,
            spans=[sp],
            reason_label="cfg:fallthrough",
        )
    )

    # Deterministic order
    blocks.sort(key=lambda b: (b.kind.value, b.block_id))
    edges.sort(key=lambda e: (e.src_block_id, e.dst_block_id, e.cond_label or ""))

    return FlowResult(
        blocks=blocks,
        edges=edges,
        facts=[],  # DFG comes separately
        anomalies=anomalies,
        metrics=dict(blocks=len(blocks), edges=len(edges), facts=0),
    )
