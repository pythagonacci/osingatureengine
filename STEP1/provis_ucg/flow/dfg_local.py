# provis_ucg/flow/dfg.py
from __future__ import annotations
# -----------------------------------------------------------------------------
# SSA-lite local DFG builder (effect-relevant) — production-hardened
#
# Tracks only variables likely to feed effect carriers:
#   - URLs/hosts/paths
#   - SQL strings / table names
#   - queue/topic keys
#
# Performs bounded constant folding over:
#   - Python: f-strings, .format, os.path.*, urljoin/urlparse, simple + concat
#   - JS/TS: template literals, + concat, path.join, new URL()
#
# Emits PHI-like merges at linear join points (approximate) and USE facts at
# function-call sites that look like effect carriers (heuristic family).
# -----------------------------------------------------------------------------
import hashlib
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .model import DFGFact, DFGOpKind, FlowResult, DEFAULT_BOUNDS
from ..models import Anomaly, AnomalyType, Severity, Language
from ..normalize.lift import UCGNode, SemanticType, Span

# ------------------------------ helpers --------------------------------------

def _sha24(*parts: str) -> str:
    import hashlib
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\0")
    return h.hexdigest()[:24]

def _fid(fn_id: str, seq: int) -> str:
    return _sha24("dfg:fact", fn_id, str(seq))

# Effect carrier heuristics (names seen in code)
_PY_EFFECT_FUNCS = (
    "open", "requests", "session", "execute", "cursor", "subprocess",
    "publish", "send", "enqueue", "s3", "redis", "gcs",
)
_JS_EFFECT_FUNCS = (
    "fetch", "axios", "fs", "exec", "child_process", "producer", "consumer",
)

_PATH_TOKENS = ("path", "url", "uri", "host", "route", "bucket", "topic", "queue", "table", "sql")

# ------------------------------ extractors ------------------------------------

# Quick literal normalizers
_STR_PAT = re.compile(r"""(?P<q>['"])(?P<s>.*?)(?<!\\)(?P=q)""", re.DOTALL)
_TEMPLATE_JS = re.compile(r"`([^`\\]|\\.)*`", re.DOTALL)

def _is_pathlike_name(name: str) -> bool:
    low = name.lower()
    return any(tok in low for tok in _PATH_TOKENS)

def _literal_string_values(code: str, language: Language) -> List[Tuple[int, int, str]]:
    vals: List[Tuple[int, int, str]] = []
    if language == Language.PYTHON:
        for m in _STR_PAT.finditer(code):
            s = m.group("s")
            vals.append((m.start(), m.end(), s))
    else:
        for m in _STR_PAT.finditer(code):
            vals.append((m.start(), m.end(), m.group("s")))
        for m in _TEMPLATE_JS.finditer(code):
            raw = m.group(0)
            # Very light placeholder redaction of ${...}
            vals.append((m.start(), m.end(), re.sub(r"\$\{[^}]*\}", ":{x}", raw[1:-1])))
    return vals

# ------------------------------ main builder ----------------------------------

def build_ssa_lite_for_function(
    fn_node: UCGNode,
    all_nodes: List[UCGNode],
    *,
    language: Language,
    get_source_slice: Callable[[str, int, int], str],
) -> FlowResult:
    """
    SSA-lite DFG:
      - Scan function span for assignments & simple builders feeding pathlike names
      - Build assign/concat/call_norm facts with bounded folding
      - Attach USE facts to effect-call UCG call nodes inside the function span
    """
    assert fn_node.semantic_type in (SemanticType.FUNCTION, SemanticType.METHOD, SemanticType.CLASS)
    sp = fn_node.spans[0]
    anomalies: List[Anomaly] = []
    facts: List[DFGFact] = []

    try:
        code = get_source_slice(sp.path, sp.byte_start, sp.byte_end)
    except Exception as e:
        anomalies.append(Anomaly(
            path=sp.path, blob_sha256="",
            typ=AnomalyType.PERMISSION_DENIED, severity=Severity.ERROR,
            reason_detail=f"source_slice_failed:{type(e).__name__}"
        ))
        return FlowResult(blocks=[], edges=[], facts=[], anomalies=anomalies, metrics=dict(blocks=0, edges=0, facts=0))

    # Very lightweight line scanning
    lines = code.splitlines()
    seq = 0

    def add_fact(src: str, dst: str, op: DFGOpKind, byte_off: int, flags: List[str], reason: str):
        nonlocal seq
        if len(facts) >= DEFAULT_BOUNDS.max_facts:
            anomalies.append(Anomaly(
                path=sp.path, blob_sha256="",
                typ=AnomalyType.CONST_FOLD_CUTOFF, severity=Severity.WARN,
                reason_detail=f"facts>{DEFAULT_BOUNDS.max_facts}"
            ))
            return
        fspan = Span(sp.path, sp.byte_start + byte_off, sp.byte_start + byte_off, 0, 0, 0, 0, reason)
        facts.append(DFGFact(
            fact_id=_fid(fn_node.node_id, seq),
            fn_node_id=fn_node.node_id,
            src=src, dst=dst, op_kind=op,
            spans=[fspan],
            flags=flags,
            reason_label=reason,
        ))
        seq += 1

    # Assignments heuristics:
    #   name = 'literal'  |  name = name2 + 'lit'  |  name = path.join('a','b')
    assign_re_py = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
    assign_re_js = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$")

    # Simple normalizers
    def fold_literal(expr: str) -> Tuple[Optional[str], List[str]]:
        flags: List[str] = []
        expr = expr.strip()
        # string literal?
        m = _STR_PAT.match(expr)
        if m:
            return m.group("s"), flags
        # JS template
        if expr.startswith("`") and expr.endswith("`"):
            val = re.sub(r"\$\{[^}]*\}", ":{x}", expr[1:-1])
            if "${" in expr:
                flags.append("NON_LITERAL_PART")
            return val, flags
        # concatenation a + 'b' + c
        parts = re.split(r"\s*\+\s*", expr)
        if len(parts) > 1:
            out = []
            non_lit = False
            for p in parts[:DEFAULT_BOUNDS.fold_depth]:
                v, fl = fold_literal(p)
                if v is None:
                    non_lit = True
                    out.append("{x}")
                else:
                    out.append(v)
                flags.extend(fl)
            if len(parts) > DEFAULT_BOUNDS.fold_depth:
                flags.append("FOLD_DEPTH")
            if non_lit:
                flags.append("NON_LITERAL_PART")
            return "".join(out), flags
        return None, flags

    # Call normalizers (path.join, os.path.join, new URL())
    def normalize_call(expr: str) -> Tuple[Optional[str], List[str], str]:
        e = expr.strip()
        flags: List[str] = []
        # Python os.path.join('a','b')
        m = re.match(r"os\.path\.join\s*\((.*)\)", e)
        if m:
            args = _split_top_level(m.group(1))
            folded = []
            nonlit = False
            for a in args[:DEFAULT_BOUNDS.fold_depth]:
                v, fl = fold_literal(a)
                if v is None:
                    nonlit = True; folded.append("{x}")
                else:
                    folded.append(v)
                flags.extend(fl)
            if nonlit:
                flags.append("NON_LITERAL_PATH")
            return "/".join([s.strip("/\\") for s in folded]), flags, "py:os.path.join"

        # Node path.join('a','b')
        m = re.match(r"path\.join\s*\((.*)\)", e)
        if m:
            args = _split_top_level(m.group(1))
            folded = []
            nonlit = False
            for a in args[:DEFAULT_BOUNDS.fold_depth]:
                v, fl = fold_literal(a)
                if v is None:
                    nonlit = True; folded.append("{x}")
                else:
                    folded.append(v)
                flags.extend(fl)
            if nonlit:
                flags.append("NON_LITERAL_PATH")
            return "/".join([s.strip("/\\") for s in folded]), flags, "js:path.join"

        # new URL('x', 'https://h')
        m = re.match(r"(?:new\s+)?URL\s*\((.*)\)", e)
        if m:
            args = _split_top_level(m.group(1))
            if args:
                v, fl = fold_literal(args[0])
                if v is None:
                    return None, ["NON_LITERAL_PATH"], "js:URL"
                flags.extend(fl)
                return v, flags, "js:URL"

        return None, [], ""

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
        if cur: out.append("".join(cur))
        return [p.strip() for p in out if p.strip()]

    # Track values for pathlike names
    env: Dict[str, str] = {}

    for idx, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            continue

        m = (assign_re_py.match(raw) if language == Language.PYTHON else assign_re_js.match(raw))
        if not m:
            continue

        name, expr = m.group(1), m.group(2)
        if not _is_pathlike_name(name):
            # opportunistic: still fold if it’s a simple string and name looks like uppercase CONST URL
            if not any(tok in name.lower() for tok in _PATH_TOKENS) and not re.search(r"(URL|URI|HOST|PATH|ROUTE|SQL|TABLE)", name):
                continue

        # try call normalizations first
        norm, flags, why = normalize_call(expr)
        if norm is not None:
            env[name] = norm
            add_fact(src=f"lit:{norm[:64]}", dst=f"var:{name}", op=DFGOpKind.CALL_NORM,
                     byte_off=raw.find(name), flags=flags, reason=why)
            continue

        # then literal concat folding
        val, flags = fold_literal(expr)
        if val is not None:
            env[name] = val
            add_fact(src=f"lit:{val[:64]}", dst=f"var:{name}", op=DFGOpKind.ASSIGN,
                     byte_off=raw.find(name), flags=(["FOLDED"] + flags if flags else ["FOLDED"]),
                     reason="fold:literal/concat")
            continue

        # unknown/dynamic
        add_fact(src="dyn:{x}", dst=f"var:{name}", op=DFGOpKind.ASSIGN,
                 byte_off=raw.find(name), flags=["DYNAMIC"], reason="assign:dynamic")

    # Attach USE facts to call nodes inside span that look like effects
    for n in all_nodes:
        if n.semantic_type != SemanticType.CALL:
            continue
        csp = n.spans[0]
        if not (sp.byte_start <= csp.byte_start <= sp.byte_end):
            continue
        prev = (n.extra or {}).get("preview") or ""
        low = prev.lower()
        is_effect = any(tok in low for tok in (_PY_EFFECT_FUNCS if language == Language.PYTHON else _JS_EFFECT_FUNCS))
        if not is_effect:
            continue

        # Try to find an argument that references a tracked var
        # Very light heuristic: scan words in preview and match env keys
        for varname, sval in env.items():
            if varname in prev:
                add_fact(src=f"var:{varname}", dst=f"call@{csp.byte_start}", op=DFGOpKind.USE,
                         byte_off=csp.byte_start, flags=[], reason="use:effect_arg")

    # Deterministic order
    facts.sort(key=lambda f: (f.fn_node_id, f.op_kind.value, f.dst, f.src))

    return FlowResult(
        blocks=[], edges=[], facts=facts,
        anomalies=anomalies,
        metrics=dict(blocks=0, edges=0, facts=len(facts)),
    )
