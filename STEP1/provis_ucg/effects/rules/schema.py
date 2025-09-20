# provis_ucg/effects/rules/schema.py
from __future__ import annotations

# -----------------------------------------------------------------------------
# Rule-pack schema (versioned) for Effect Carrier detection
# - Format: YAML or JSON
# - Version pinning and validation
# - Minimal deps (PyYAML/sqlglot optional)
# -----------------------------------------------------------------------------
from dataclasses import dataclass, field
from typing import Literal

RuleVersion = Literal["1.0"]

# --------------------------- Public dataclasses -------------------------------


@dataclass(frozen=True)
class FieldSpec:
    """How to extract a field from a capture/match: positional arg / kw / literal path."""

    name: str  # normalized field name: method, path, status, host, db.table, db.op, gql.op, topic, bucket, key, flag_key, cron, etc.
    source: Literal["arg", "kw", "literal", "decorator", "filename"]
    # arg index or kw name if source is arg/kw; for literal/filename, value_expr may be used
    index: int | None = None
    key: str | None = None  # kw name when source="kw"
    value_expr: str | None = (
        None  # e.g. '${0}/${1}' or regex group ref; resolved via normalizers
    )


@dataclass(frozen=True)
class Pattern:
    """
    A detection pattern. Examples:
      - callee: 'fastapi.APIRouter.get' or regex '^app\.(get|post)$'
      - decorator: '@router.get'
      - object_method: 'express:app.use' or 'sequelize:Model.findAll'
      - filename_hint: 'pages/api/**/route.ts'
      - node_type: 'Call' | 'Decorator' | 'Class' | 'Function'
    """

    language: Literal["python", "javascript", "typescript", "any"]
    kind: Literal["call", "decorator", "class", "function", "filename"]
    callee: str | None = None  # dotted or regex (prefix 're:')
    decorator: str | None = None  # dotted or regex (prefix 're:')
    object_method: str | None = None  # 'obj.method' or regex
    filename_glob: str | None = None  # minimatch glob for file routing frameworks
    node_type: str | None = None  # UCG semantic node type if needed
    arg_count_min: int | None = None
    arg_count_max: int | None = None


@dataclass(frozen=True)
class EffectRule:
    """One rule yields one Effect with specific provider/family and field extraction."""

    id: str
    effect_kind: Literal[
        "http.route",
        "db.sql",
        "db.orm",
        "graphql",
        "rpc",
        "messaging",
        "io.file",
        "io.blob",
        "subprocess",
        "cache",
        "feature_flag",
        "auth",
        "scheduler",
    ]
    provider: str  # 'fastapi','flask','express','sequelize','prisma','redis','launchdarkly', etc.
    family: str  # subfamily e.g. 'router','view','model','topic','bucket','queue'
    patterns: list[Pattern]
    fields: list[FieldSpec]  # how to populate normalized_values
    confidence: float = 0.95
    notes: str | None = None


@dataclass(frozen=True)
class RulePack:
    """A versioned bundle of rules for a given provider or a mixed pack."""

    name: str  # 'fastapi@0.115','express@4','sequelize@6','core@1'
    version: RuleVersion  # '1.0'
    language: Literal["python", "javascript", "typescript", "any"]
    rules: list[EffectRule]
    requires: list[str] = field(default_factory=list)  # e.g., ["core@1"]
    telemetry_tag: str | None = None  # for metrics bucketing


# --------------------------- Validation utilities -----------------------------


def validate_pack(pack: RulePack) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if pack.version not in ("1.0",):
        errors.append(f"Unsupported rule schema version: {pack.version}")
    if not pack.rules:
        errors.append("RulePack has no rules")
    seen_ids = set()
    for r in pack.rules:
        if r.id in seen_ids:
            errors.append(f"Duplicate rule id: {r.id}")
        seen_ids.add(r.id)
        if not (0.0 < r.confidence <= 1.0):
            errors.append(f"Rule {r.id} invalid confidence: {r.confidence}")
        if not r.patterns:
            errors.append(f"Rule {r.id} has no patterns")
        for p in r.patterns:
            if p.kind not in ("call", "decorator", "class", "function", "filename"):
                errors.append(f"Rule {r.id} bad pattern kind: {p.kind}")
            if p.language not in ("python", "javascript", "typescript", "any"):
                errors.append(f"Rule {r.id} bad pattern language: {p.language}")
        for f in r.fields:
            if f.source not in ("arg", "kw", "literal", "decorator", "filename"):
                errors.append(f"Rule {r.id} field {f.name} bad source: {f.source}")
    return (len(errors) == 0, errors)
