# osigdetector/ingestion/cfg_builder.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .parser_registry import GenericAST, GenericNode
from .ast_to_ucg import UCGBatch
from .provenance import Provenance, from_node, from_regex

# =============================================================================
# Data model
# =============================================================================

@dataclass
class CFGBlock:
    block_id: int
    func_qname: str
    start_line: int
    end_line: int
    exit_kind: str  # "return"|"raise"|"fallthrough"|"unknown"
    prov: Provenance
    anomalies: List[str] = field(default_factory=list)


@dataclass
class CFGEdge:
    edge_id: int
    func_qname: str
    from_block: int
    to_block: int
    kind: str  # "normal"|"exception"


@dataclass
class CFGBundle:
    blocks: List[CFGBlock]
    edges: List[CFGEdge]
    anomalies: List[Dict[str, str]] = field(default_factory=list)


# =============================================================================
# CFG Builder
# =============================================================================

class CFGBuilder:
    """
    Builds block-level CFGs for functions from GenericAST trees.

    What we capture:
      - Sequential blocks (fallthrough)
      - Branching constructs: if/elif/else, try/except/finally
      - Exit points: return, raise
    What we skip:
      - SSA, phi-nodes, detailed expression flow
    """

    def __init__(self):
        self._next_block_id = 1
        self._next_edge_id = 1

    # -------------------------
    # Public API
    # -------------------------

    def build_for_functions(self, batch: UCGBatch, fn_nodes: Dict[str, GenericNode]) -> Dict[str, CFGBundle]:
        """
        Args:
            batch: UCGBatch from AST lift
            fn_nodes: map func_qname -> GenericNode (from ast_to_ucg traversal)

        Returns:
            Dict mapping func_qname -> CFGBundle
        """
        out: Dict[str, CFGBundle] = {}
        for qname, node in fn_nodes.items():
            bundle = self._build_single(qname, node)
            out[qname] = bundle
        return out

    # -------------------------
    # Internal
    # -------------------------

    def _build_single(self, qname: str, fn_node: GenericNode) -> CFGBundle:
        blocks: List[CFGBlock] = []
        edges: List[CFGEdge] = []
        anomalies: List[Dict[str, str]] = []

        entry_block = self._new_block(qname, fn_node.start_line, fn_node.end_line, "fallthrough")
        blocks.append(entry_block)

        # Simple traversal: look for exit nodes in children
        exits = self._collect_exits(fn_node)

        if not exits:
            # Whole function is a linear block
            return CFGBundle(blocks=blocks, edges=edges)

        # Break function into blocks based on exits
        for (kind, line, col) in exits:
            blk = self._new_block(qname, line, line, kind)
            blocks.append(blk)
            edges.append(self._new_edge(qname, entry_block.block_id, blk.block_id,
                                        "exception" if kind == "raise" else "normal"))

        return CFGBundle(blocks=blocks, edges=edges, anomalies=anomalies)

    def _collect_exits(self, fn_node: GenericNode) -> List[Tuple[str, int, int]]:
        """
        Collect return/raise constructs inside a function node.
        Returns list of (exit_kind, line, col).
        """
        out: List[Tuple[str, int, int]] = []
        stack = [fn_node]
        while stack:
            node = stack.pop()
            if node.kind in ("Return", "return_statement"):
                out.append(("return", node.start_line, node.start_col))
            elif node.kind in ("Raise", "throw_statement"):
                out.append(("raise", node.start_line, node.start_col))
            stack.extend(node.children)
        return out

    # -------------------------
    # ID allocators
    # -------------------------

    def _new_block(self, qname: str, sl: int, el: int, exit_kind: str) -> CFGBlock:
        bid = self._next_block_id
        self._next_block_id += 1
        return CFGBlock(
            block_id=bid,
            func_qname=qname,
            start_line=sl,
            end_line=el,
            exit_kind=exit_kind,
            prov=Provenance(file_rel=qname.split(":")[0], start_line=sl, end_line=el, note="cfg:block"),
        )

    def _new_edge(self, qname: str, from_b: int, to_b: int, kind: str) -> CFGEdge:
        eid = self._next_edge_id
        self._next_edge_id += 1
        return CFGEdge(edge_id=eid, func_qname=qname, from_block=from_b, to_block=to_b, kind=kind)
