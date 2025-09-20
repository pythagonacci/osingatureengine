# provis_ucg/flow/model.py
from __future__ import annotations
# -----------------------------------------------------------------------------
# Shared flow IR + config
# -----------------------------------------------------------------------------
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from ..models import Anomaly, Severity, AnomalyType, Language
from ..normalize.lift import Span

# ---------------------------- CFG / DFG data types ----------------------------

class CFGBlockKind(str, Enum):
    ENTRY = "entry"
    NORMAL = "normal"
    EXIT = "exit"
    EXCEPTION = "exception"

@dataclass(frozen=True)
class CFGBlock:
    block_id: str
    fn_node_id: str
    kind: CFGBlockKind
    spans: List[Span]  # representative span(s)

@dataclass(frozen=True)
class CFGEdge:
    edge_id: str
    fn_node_id: str
    src_block_id: str
    dst_block_id: str
    cond_label: Optional[str]  # e.g., "case:200", "else", "except:ValueError"
    spans: List[Span]
    reason_label: str

class DFGOpKind(str, Enum):
    ASSIGN = "assign"
    CONCAT = "concat"
    CALL_NORM = "call_norm"     # e.g., path.join, URL(), os.path.join
    PHI = "phi"
    USE = "use"                 # reaching use at effect site

@dataclass(frozen=True)
class DFGFact:
    fact_id: str
    fn_node_id: str
    src: str       # symbol|literal|tmp id
    dst: str       # symbol|arg|return|tmp id
    op_kind: DFGOpKind
    spans: List[Span]
    flags: List[str]            # e.g., ["FOLDED", "NON_LITERAL_PATH"]
    reason_label: str

# ---------------------------- Flow build result -------------------------------

@dataclass
class FlowResult:
    blocks: List[CFGBlock]
    edges: List[CFGEdge]
    facts: List[DFGFact]
    anomalies: List[Anomaly]
    metrics: Dict[str, int]

# ---------------------------- Bounds / cutoffs --------------------------------

@dataclass(frozen=True)
class FlowBounds:
    max_blocks: int = 2000
    max_edges: int = 6000
    max_facts: int = 512          # per function (design target)
    fold_depth: int = 6
    preview_char_cap: int = 200

DEFAULT_BOUNDS = FlowBounds()
