# provis_ucg/effects/detector.py
from __future__ import annotations

# -----------------------------------------------------------------------------
# Effect Carrier Detection Engine
#
# Inputs:
#   - UCG nodes/edges from normalization
#   - (Optional) CFG edges / SSA-lite DFG facts to refine literals
#   - Rule packs (versioned) describing patterns & field extraction
#
# Outputs:
#   - Effect facts with normalized_values, literals preview, receipts
#   - Anomalies for any ambiguous/failed extraction
#   - Telemetry per rule-pack & rule id
# -----------------------------------------------------------------------------
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..models import Anomaly, AnomalyType, Language, Severity
from ..normalize.lift import SemanticType, Span, UCGEdge, UCGNode
from .normalizers import (
    normalize_http_path,
    normalize_method,
    normalize_sql,
    normalize_topic,
    receipt_id,
    redact_preview,
)
from .rules.loader import RuleRegistry
from .rules.schema import EffectRule, RulePack

# ----------------------------- Public datatypes --------------------------------


@dataclass
class Effect:
    effect_id: str
    kind: str  # e.g., 'http.route','db.sql','db.orm','graphql','messaging', etc.
    provider: str  # e.g., 'fastapi','express','sequelize','prisma'
    family: str  # subfamily 'router','view','model','topic','bucket','queue'
    owner_fn_id: str | None  # nearest enclosing def node id
    literals: dict[str, str]  # raw literal fields as seen (redacted/previewed)
    normalized_values: dict[str, Any]  # normalized fields (method,path,db.op,table,...)
    receipt_id: str
    spans: list[Span]
    reason_label: str


@dataclass
class DetectResult:
    effects: list[Effect]
    anomalies: list[Anomaly]
    metrics: dict[str, int]


# ----------------------------- Engine -----------------------------------------


class EffectDetector:
    """
    Run rule-based detection across UCG nodes.
    - Pattern matching is conservative (prefix/regex).
    - Field extraction draws from node previews (Import/Call/Literal/TemplatePart) and from rule arguments.
    - Owner function is chosen by span containment (nearest def).
    """

    def __init__(self, registry: RuleRegistry) -> None:
        self.registry = registry

    # ---------- Public API ----------

    def detect_effects(
        self,
        nodes: list[UCGNode],
        edges: list[UCGEdge],
        *,
        language: Language,
        rule_pack_names: Iterable[str],
        cfg_edges: list[Any] | None = None,  # placeholder for future refinement
        dfg_facts: list[Any] | None = None,  # placeholder for future refinement
    ) -> DetectResult:
        anomalies: list[Anomaly] = []
        effects: list[Effect] = []
        metrics = dict(candidate_calls=0, matched=0, pack_errors=0, fields_missing=0)

        # Build quick indices
        module = next((n for n in nodes if n.semantic_type == SemanticType.MODULE), None)
        defs = [
            n
            for n in nodes
            if n.semantic_type in (SemanticType.CLASS, SemanticType.FUNCTION, SemanticType.METHOD)
        ]
        calls = [n for n in nodes if n.semantic_type == SemanticType.CALL]
        literals = [
            n
            for n in nodes
            if n.semantic_type in (SemanticType.LITERAL, SemanticType.TEMPLATE_PART)
        ]

        # Prepare owner-fn lookup via span containment
        def_owner = _DefOwner(defs)

        # Load and validate rule packs
        packs: list[RulePack] = []
        for name in rule_pack_names:
            pack = self.registry.get(name)
            if not pack:
                anomalies.append(
                    Anomaly(
                        path=module.spans[0].path if module else "<file>",
                        blob_sha256="",
                        typ=AnomalyType.PARSE_ERROR,
                        severity=Severity.WARN,
                        reason_detail=f"Rule pack not loaded: {name}",
                    )
                )
                metrics["pack_errors"] += 1
                continue
            packs.append(pack)

        # Candidate selection: currently focus on CALL nodes (most effect hooks)
        for call in calls:
            metrics["candidate_calls"] += 1
            preview = (call.extra.get("preview") or "").strip()
            # callee name heuristic within preview (best-effort)
            callee_token = _first_identifier(preview)
            owner = def_owner.nearest(call.spans[0]) if defs else None

            # try each pack/rule
            for pack in packs:
                if pack.language not in ("any", language.value):
                    continue

                for rule in pack.rules:
                    if not _matches(rule, language, call, preview, callee_token, module):
                        continue

                    eff = self._extract_effect(rule, call, preview, literals, owner, language)
                    if eff:
                        effects.append(eff)
                        metrics["matched"] += 1
                        # telemetry
                        tag = pack.telemetry_tag or pack.name
                        self.registry.telemetry[tag] = self.registry.telemetry.get(tag, 0) + 1
                    else:
                        metrics["fields_missing"] += 1

        return DetectResult(effects=effects, anomalies=anomalies, metrics=metrics)

    # ---------- Internals ----------

    def _extract_effect(
        self,
        rule: EffectRule,
        call: UCGNode,
        preview: str,
        literals: list[UCGNode],
        owner: UCGNode | None,
        language: Language,
    ) -> Effect | None:
        """
        Use FieldSpec to build literals + normalized_values dictionaries.
        We only have preview text (span slice). Argument extraction is best-effort
        using a balanced split on the first top-level '(...)" block if present.
        """
        sp = call.spans[0]
        args_block = _slice_parens(preview, "(", ")")
        arg_list, kw_map = _split_args(args_block)

        raw: dict[str, str] = {}
        norm: dict[str, Any] = {}
        missing: list[str] = []

        for f in rule.fields:
            val_raw = None

            if f.source == "arg" and f.index is not None:
                if 0 <= f.index < len(arg_list):
                    val_raw = arg_list[f.index].strip()
            elif f.source == "kw" and f.key:
                val_raw = kw_map.get(f.key)
            elif f.source == "literal" and f.value_expr:
                val_raw = _format_value_expr(f.value_expr, arg_list, kw_map)
            elif f.source == "filename":
                val_raw = sp.path
            elif f.source == "decorator":
                # not available on CALL; rule could still supply; leave None
                pass

            if val_raw is None:
                missing.append(f.name)
                continue

            val_red = redact_preview(val_raw, 200)
            raw[f.name] = val_red

            # normalization per field name
            if rule.effect_kind == "http.route":
                if f.name.lower() in ("path", "route"):
                    norm["path"] = normalize_http_path(val_red)
                elif f.name.lower() in ("method", "verb"):
                    norm["method"] = normalize_method(val_red)
                elif f.name.lower() in ("status", "status_code"):
                    m = re.search(r"\d{3}", val_red)
                    if m:
                        norm["status"] = int(m.group(0))
                elif f.name.lower() in ("host", "base_url"):
                    norm["host"] = val_red.strip("\"'")
            elif rule.effect_kind in ("db.sql", "db.orm"):
                if f.name.lower() in ("sql", "query"):
                    op, table, normsql = normalize_sql(val_red)
                    norm.setdefault("db", {})["op"] = op
                    if table:
                        norm.setdefault("db", {})["table"] = table
                    if normsql:
                        norm.setdefault("db", {})["normalized_sql"] = normsql
                elif f.name.lower() in ("table", "model"):
                    norm.setdefault("db", {})["table"] = val_red.strip("\"'")
                elif f.name.lower() in ("op", "operation"):
                    norm.setdefault("db", {})["op"] = val_red.upper()
            elif rule.effect_kind in ("messaging",):
                if f.name.lower() in ("topic", "queue"):
                    norm["topic"] = normalize_topic(val_red)
            elif rule.effect_kind in ("graphql", "rpc"):
                if f.name.lower() in ("operation", "op", "operation_name"):
                    norm["operation"] = val_red
                if f.name.lower() in ("type", "op_type"):
                    norm["op_type"] = val_red.lower()
            elif rule.effect_kind in ("io.file", "io.blob"):
                if f.name.lower() in ("path", "key", "bucket"):
                    norm[f.name] = val_red.strip("\"'")
            elif rule.effect_kind in ("feature_flag",):
                if f.name.lower() in ("flag", "key"):
                    norm["flag_key"] = val_red.strip("\"'")
            elif rule.effect_kind in ("auth",):
                if f.name.lower() in ("provider", "scope", "audience"):
                    norm[f.name] = val_red.strip("\"'")
            elif rule.effect_kind in ("scheduler",):
                if f.name.lower() in ("cron", "interval"):
                    norm[f.name] = val_red.strip("\"'")
            else:
                # generic passthrough
                norm[f.name] = val_red.strip("\"'")

        # let providers adjust defaults (e.g., if method missing but pattern encodes it)
        _infer_provider_defaults(rule, preview, norm)

        if missing and len(missing) == len(rule.fields):
            # rule pattern matched but all fields missing → treat as miss
            return None

        rid = receipt_id(sp.path, sp.byte_start, sp.byte_end, call.spans[0].reason_label)
        eff = Effect(
            effect_id=rid,
            kind=rule.effect_kind,
            provider=rule.provider,
            family=rule.family,
            owner_fn_id=owner.node_id if owner else None,
            literals=raw,
            normalized_values=norm,
            receipt_id=rid,
            spans=[sp],
            reason_label=call.spans[0].reason_label,
        )
        return eff


# ----------------------------- Pattern matching -------------------------------


def _matches(
    rule: EffectRule,
    language: Language,
    call: UCGNode,
    preview: str,
    callee: str | None,
    module: UCGNode | None,
) -> bool:
    # coarse language filter
    if rule.effect_kind and rule.provider:
        pass  # keep for clarity
    ok_any = False
    for p in rule.patterns:
        if p.language not in ("any", language.value):
            continue
        if p.kind == "filename" and p.filename_glob and module:
            if _glob_match(module.spans[0].path, p.filename_glob):
                ok_any = True
        elif p.kind in ("call", "decorator"):
            # On CALL nodes, we have preview like "router.get('/path', handler)"
            if p.callee and _callee_match(preview, p.callee):
                ok_any = True
            if p.object_method and _object_method_match(preview, p.object_method):
                ok_any = True
            # arg counts if present
            if p.arg_count_min is not None or p.arg_count_max is not None:
                block = _slice_parens(preview, "(", ")")
                args, _ = _split_args(block)
                if p.arg_count_min is not None and len(args) < p.arg_count_min:
                    return False
                if p.arg_count_max is not None and len(args) > p.arg_count_max:
                    return False
        # class/function kinds could be added later for decorator-only frameworks
    return ok_any


def _callee_match(preview: str, spec: str) -> bool:
    # spec can be dotted or 're:...'
    if spec.startswith("re:"):
        return re.search(spec[3:], preview) is not None
    # dotted name must appear just before '(' or as member call
    dotted = spec.replace(" ", "")
    return dotted in preview


def _object_method_match(preview: str, spec: str) -> bool:
    if spec.startswith("re:"):
        return re.search(spec[3:], preview) is not None
    return f"{spec}(" in preview or f".{spec}(" in preview


def _glob_match(path: str, pattern: str) -> bool:
    # simple '**' and '*' matcher
    from fnmatch import fnmatch

    return fnmatch(path, pattern)


# ----------------------------- Owner (enclosing def) --------------------------


class _DefOwner:
    def __init__(self, defs: list[UCGNode]) -> None:
        # sort by (start, -end) for proper nesting
        self._defs = sorted(defs, key=lambda n: (n.spans[0].byte_start, -n.spans[0].byte_end))

    def nearest(self, sp: Span) -> UCGNode | None:
        stack: list[UCGNode] = []
        best = None
        for d in self._defs:
            if _encloses(d.spans[0], sp):
                best = d
        return best


def _encloses(outer: Span, inner: Span) -> bool:
    return (outer.byte_start <= inner.byte_start) and (outer.byte_end >= inner.byte_end)


# ----------------------------- Preview helpers --------------------------------

_IDENT = r"[A-Za-z_\$][A-Za-z0-9_\$]*"


def _first_identifier(s: str) -> str | None:
    m = re.search(_IDENT, s)
    return m.group(0) if m else None


def _slice_parens(s: str, opener: str, closer: str) -> str | None:
    if not s:
        return None
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
                return s[i : j + 1]
    return None


def _split_args(param_block: str | None) -> tuple[list[str], dict[str, str]]:
    """
    Split "(a, b=1, {x:1}, fn(x,y))" into ['a','b=1','{x:1}','fn(x,y)'] + {'b':'1'}
    """
    if not param_block:
        return [], {}
    inner = param_block[1:-1] if param_block.startswith("(") else param_block
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    kw: dict[str, str] = {}
    for ch in inner:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            tok = "".join(buf).strip()
            if tok:
                parts.append(tok)
                if "=" in tok and not tok.strip().startswith("=>"):
                    k, v = tok.split("=", 1)
                    kw[k.strip()] = v.strip()
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
        if "=" in tail and not tail.strip().startswith("=>"):
            k, v = tail.split("=", 1)
            kw[k.strip()] = v.strip()
    return parts, kw


def _format_value_expr(expr: str, args: list[str], kw: dict[str, str]) -> str:
    """
    Replace ${i} with args[i] and ${kw:name} with kw[name].
    """

    def repl(m):
        token = m.group(1)
        if token.startswith("kw:"):
            return kw.get(token[3:], "")
        try:
            idx = int(token)
            return args[idx] if 0 <= idx < len(args) else ""
        except Exception:
            return ""

    return re.sub(r"\$\{([^}]+)\}", repl, expr)


def _infer_provider_defaults(rule: EffectRule, preview: str, norm: dict[str, Any]) -> None:
    if rule.effect_kind == "http.route" and "method" not in norm:
        # Some APIs encode method in the callee/member, infer with regex
        m = re.search(r"\b(get|post|put|patch|delete|head|options)\b", preview, re.IGNORECASE)
        if m:
            norm["method"] = m.group(1).upper()
