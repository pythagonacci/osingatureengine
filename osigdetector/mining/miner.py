# osigdetector/mining/miner.py
from __future__ import annotations
import sqlite3
from typing import List
from ..ingestion.ucg_store import UCGStore
from .anchor import Anchor

class StaticMiner:
    """
    Step 2 Orchestrator: turn raw effects into anchors (proto-OSigs).
    """

    def __init__(self, db_path: str):
        self.store = UCGStore(db_path)
        self._next_anchor_id = 1

    def run(self):
        """
        Entry point: load effects from Step 1 store,
        dispatch to detectors, and persist anchors.
        """
        effects = self.store.list_effects()
        anchors: List[Anchor] = []

        for eff in effects:
            # TODO: dynamic dispatch based on eff["effect_type"], eff["framework_hint"]
            # For now, just a placeholder
            anchors.append(
                Anchor(
                    anchor_id=self._alloc_id(),
                    effect_id=eff["effect_id"],
                    file_rel=eff["file_rel"],
                    func_qname=eff["func_qname"],
                    kind="proto_dummy",
                    raw_fields={"callee": eff.get("framework_hint", "")},
                    anomalies=["NO_DETECTOR"],
                    static_confidence=0.1,
                    prov=None,
                    note="placeholder anchor",
                )
            )

        # persist
        with sqlite3.connect(self.store.db_path) as con:
            cur = con.cursor()
            for a in anchors:
                self.store.insert_anchor(cur, a)
            con.commit()

    def _alloc_id(self) -> int:
        aid = self._next_anchor_id
        self._next_anchor_id += 1
        return aid
