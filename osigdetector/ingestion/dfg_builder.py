# osigdetector/ingestion/dfg_builder.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .parser_registry import GenericNode
from .ast_to_ucg import UCGBatch
from .provenance import Provenance, from_node, from_regex

# =============================================================================
# Data model
# =============================================================================

@dataclass
class DFGBinding:
    binding_id: int
    func_qname: str
    var_name: str
    value_kind: str         # "literal"|"concat"|"template"|"dict"|"unknown"
    value_norm: str         # normalized representation (e.g., "/users/:id")
    prov: Provenance
    anomalies: List[str] = field(default_factory=list)


@dataclass
class DFGBundle:
    bindings: List[DFGBinding]
    anomalies: List[Dict[str, str]] = field(default_factory=list)


# =============================================================================
# Builder
# =============================================================================

class DFGBuilder:
    """
    Builds lightweight local data flow bindings for functions.

    Captures:
      - Simple constant assignments (x = "foo")
      - String concatenations, f-strings, template literals
      - Dict/object literals near callsites
    """

    def __init__(self):
        self._next_binding_id = 1

    # -------------------------
    # Public API
    # -------------------------

    def build_for_functions(self, fn_nodes: Dict[str, GenericNode]) -> Dict[str, DFGBundle]:
        out: Dict[str, DFGBundle] = {}
        for qname, node in fn_nodes.items():
            bundle = self._build_single(qname, node)
            out[qname] = bundle
        return out

    # -------------------------
    # Internal
    # -------------------------

    def _build_single(self, qname: str, fn_node: GenericNode) -> DFGBundle:
        bindings: List[DFGBinding] = []
        anomalies: List[Dict[str, str]] = []

        # Traverse nodes to find assignment-like or literal-carrying constructs
        stack = [fn_node]
        while stack:
            node = stack.pop()

            # Python assignment
            if node.kind in ("Assign", "assignment_expression"):
                var = self._extract_var(node)
                val, kind, issues = self._extract_value(node)
                prov = self._prov(qname, node, "dfg:assign")
                bindings.append(self._binding(qname, var, kind, val, prov, issues))

            # Dict/object literal
            if node.kind in ("Dict", "object", "dictionary"):
                norm, issues = self._normalize_dict(node)
                prov = self._prov(qname, node, "dfg:dict")
                bindings.append(self._binding(qname, "<dict>", "dict", norm, prov, issues))

            # F-strings / template literals
            if node.kind in ("JoinedStr", "template_string", "template_literal"):
                norm, issues = self._normalize_template(node)
                prov = self._prov(qname, node, "dfg:template")
                bindings.append(self._binding(qname, "<template>", "template", norm, prov, issues))

            stack.extend(node.children)

        return DFGBundle(bindings=bindings, anomalies=anomalies)

    # -------------------------
    # Extractors / normalizers
    # -------------------------

    def _extract_var(self, node: GenericNode) -> str:
        # Heuristic: find a child with kind 'Name' or 'identifier'
        for ch in node.children:
            if ch.kind in ("Name", "identifier"):
                return f"var@L{ch.start_line}:{ch.start_col}"
        return f"var@L{node.start_line}:{node.start_col}"

    def _extract_value(self, node: GenericNode) -> tuple[str, str, List[str]]:
        """
        Try to normalize the RHS of an assignment.
        """
        issues: List[str] = []
        for ch in node.children:
            # Python constant string
            if ch.kind in ("Constant", "string", "string_literal"):
                return ch.kind, "literal", []
            # Concatenation
            if ch.kind in ("BinOp", "binary_expression"):
                norm = "<concat>"
                issues.append("CONCAT_PLACEHOLDER")
                return norm, "concat", issues
        return "<unknown>", "unknown", ["UNRESOLVED_VALUE"]

    def _normalize_dict(self, node: GenericNode) -> tuple[str, List[str]]:
        # We can’t see keys/values text without token strings
        return "{...}", ["DICT_PLACEHOLDER"]

    def _normalize_template(self, node: GenericNode) -> tuple[str, List[str]]:
        return "<template:/.../>", ["TEMPLATE_PLACEHOLDER"]

    # -------------------------
    # Helpers
    # -------------------------

    def _binding(self, qname: str, var: str, kind: str, norm: str, prov: Provenance, issues: List[str]) -> DFGBinding:
        bid = self._next_binding_id
        self._next_binding_id += 1
        return DFGBinding(
            binding_id=bid,
            func_qname=qname,
            var_name=var,
            value_kind=kind,
            value_norm=norm,
            prov=prov,
            anomalies=issues,
        )

    def _prov(self, qname: str, node: GenericNode, note: str) -> Provenance:
        return from_node(file_rel=qname.split(":")[0], node=node, note=note)
