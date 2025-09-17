# osigdetector/mining/anchor.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from ..ingestion.provenance import Provenance

@dataclass
class Anchor:
    anchor_id: int
    effect_id: Optional[int]
    file_rel: str
    func_qname: Optional[str]
    kind: str                        # http_response, db_write, etc
    raw_fields: Dict[str, str]
    anomalies: List[str] = field(default_factory=list)
    static_confidence: float = 0.0
    prov: Optional[Provenance] = None
    note: str = ""
