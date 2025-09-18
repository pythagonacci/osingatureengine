"""
Context Packer - Step 4: LLM Input Preparation

Builds compact, evidence-rich context bundles for each anchor to feed
into LLM enrichment in Step 5.
"""

import json
import sqlite3
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger, log_pipeline_step
from ..ingestion.ucg_store import UCGStore
from .helpers.snippet_utils import extract_snippet, get_file_imports, extract_function_signature
from .helpers.neighbor_utils import get_neighbor_facts, get_related_schemas
from .helpers.dfg_utils import get_dfg_bindings, get_cfg_outcomes, get_framework_hint

logger = get_logger(__name__)


@dataclass
class ContextBundle:
    """A complete context bundle for an anchor."""
    
    anchor_id: int
    bundle: Dict[str, Any]
    size_bytes: int
    
    def to_json(self) -> str:
        """Convert bundle to JSON string."""
        return json.dumps(self.bundle, ensure_ascii=False, separators=(',', ':'))


class ContextPacker:
    """Builds context packs for LLM input preparation."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
        self.max_pack_size = 4096  # 4KB limit
        self.snippet_window = 10   # ±10 lines around anchor
    
    def build_context_packs(self, ucg_store_path: str) -> Dict[str, Any]:
        """
        Build context packs for all anchors.
        
        Args:
            ucg_store_path: Path to UCG SQLite database
            
        Returns:
            Dictionary with processing statistics
        """
        log_pipeline_step("context_packing", "started", {"db_path": ucg_store_path})
        
        try:
            store = UCGStore(ucg_store_path)
            
            with store._conn() as conn:
                # Get all anchors that need context packing
                anchors = self._get_anchors_for_packing(conn)
                logger.info(f"Building context packs for {len(anchors)} anchors")
                
                # Clear existing context packs
                self._clear_existing_packs(conn)
                
                # Build context packs
                packs = []
                stats = {
                    "total_anchors": len(anchors),
                    "successful_packs": 0,
                    "failed_packs": 0,
                    "oversized_packs": 0,
                    "total_size_bytes": 0
                }
                
                for anchor_data in anchors:
                    try:
                        context_bundle = self._build_single_context_pack(conn, anchor_data)
                        
                        if context_bundle.size_bytes > self.max_pack_size:
                            stats["oversized_packs"] += 1
                            logger.warning(
                                f"Context pack {context_bundle.anchor_id} is oversized: "
                                f"{context_bundle.size_bytes} bytes"
                            )
                        
                        packs.append((
                            context_bundle.anchor_id,
                            context_bundle.to_json(),
                            context_bundle.size_bytes
                        ))
                        
                        stats["successful_packs"] += 1
                        stats["total_size_bytes"] += context_bundle.size_bytes
                        
                    except Exception as e:
                        logger.error(f"Failed to build context pack for anchor {anchor_data['anchor_id']}: {e}")
                        stats["failed_packs"] += 1
                        continue
                
                # Insert context packs into database
                self._insert_context_packs(conn, packs)
                conn.commit()
                
                stats["average_size_bytes"] = (
                    stats["total_size_bytes"] / max(stats["successful_packs"], 1)
                )
                
                log_pipeline_step("context_packing", "completed", stats)
                return stats
        
        except Exception as e:
            log_pipeline_step("context_packing", "failed", {"error": str(e)})
            raise
    
    def _get_anchors_for_packing(self, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
        """Get all anchors that need context packing."""
        cur = conn.cursor()
        
        # Get anchors that don't have context packs yet
        cur.execute("""
            SELECT a.anchor_id, a.file_rel, a.func_qname, a.kind,
                   a.raw_fields, a.resolved_fields, a.anomalies,
                   a.prov_file, a.prov_sl, a.prov_el, a.note,
                   f.abs_locator
            FROM anchors a
            JOIN files f ON a.file_rel = f.rel_path
            LEFT JOIN context_packs cp ON a.anchor_id = cp.anchor_id
            WHERE cp.pack_id IS NULL
            ORDER BY a.anchor_id
        """)
        
        anchors = []
        for row in cur.fetchall():
            anchor_data = {
                "anchor_id": row[0],
                "file_rel": row[1],
                "func_qname": row[2],
                "kind": row[3],
                "raw_fields": json.loads(row[4] or "{}"),
                "resolved_fields": json.loads(row[5] or "{}"),
                "anomalies": json.loads(row[6] or "[]"),
                "prov_file": row[7],
                "prov_sl": row[8],
                "prov_el": row[9],
                "note": row[10],
                "abs_locator": row[11]
            }
            anchors.append(anchor_data)
        
        return anchors
    
    def _clear_existing_packs(self, conn: sqlite3.Connection):
        """Clear existing context packs (for rebuilding)."""
        cur = conn.cursor()
        cur.execute("DELETE FROM context_packs")
        logger.debug("Cleared existing context packs")
    
    def _build_single_context_pack(
        self, 
        conn: sqlite3.Connection, 
        anchor_data: Dict[str, Any]
    ) -> ContextBundle:
        """Build a context pack for a single anchor."""
        
        anchor_id = anchor_data["anchor_id"]
        file_locator = anchor_data["abs_locator"]
        
        # Build the context bundle
        bundle = {
            "anchor": self._build_anchor_snapshot(anchor_data),
            "file_header": self._build_file_header(file_locator, anchor_data["file_rel"]),
            "span_snippet": self._build_span_snippet(
                file_locator, anchor_data["prov_sl"], anchor_data["prov_el"]
            ),
            "neighbor_facts": get_neighbor_facts(conn, anchor_id),
            "cfg_outcomes": get_cfg_outcomes(conn, anchor_id),
            "dfg_bindings": get_dfg_bindings(conn, anchor_id),
            "framework_hints": get_framework_hint(conn, anchor_data["file_rel"])
        }
        
        # Calculate size and create bundle
        bundle_json = json.dumps(bundle, ensure_ascii=False, separators=(',', ':'))
        size_bytes = len(bundle_json.encode('utf-8'))
        
        return ContextBundle(
            anchor_id=anchor_id,
            bundle=bundle,
            size_bytes=size_bytes
        )
    
    def _build_anchor_snapshot(self, anchor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build the anchor snapshot portion of the context."""
        return {
            "id": anchor_data["anchor_id"],
            "kind": anchor_data["kind"],
            "raw_fields": anchor_data["raw_fields"],
            "resolved_fields": anchor_data["resolved_fields"],
            "anomalies": anchor_data["anomalies"],
            "provenance": {
                "file": anchor_data["prov_file"],
                "start": anchor_data["prov_sl"],
                "end": anchor_data["prov_el"]
            },
            "note": anchor_data["note"]
        }
    
    def _build_file_header(self, file_locator: str, file_rel: str) -> Dict[str, Any]:
        """Build the file header portion of the context."""
        imports = get_file_imports(file_locator, max_imports=10)
        
        # Extract function/class names from file_rel (simplified)
        # In a full implementation, this would query the UCG for all top-level symbols
        header = {
            "file": file_rel,
            "imports": imports,
            "import_count": len(imports)
        }
        
        return header
    
    def _build_span_snippet(
        self, 
        file_locator: str, 
        start_line: int, 
        end_line: int
    ) -> List[str]:
        """Build the code snippet portion of the context."""
        return extract_snippet(
            file_locator=file_locator,
            start_line=start_line,
            end_line=end_line,
            window=self.snippet_window,
            highlight_anchor=True
        )
    
    def _insert_context_packs(self, conn: sqlite3.Connection, packs: List[tuple]):
        """Insert context packs into the database."""
        cur = conn.cursor()
        
        cur.executemany("""
            INSERT INTO context_packs (anchor_id, bundle, size_bytes)
            VALUES (?, ?, ?)
        """, packs)
        
        logger.info(f"Inserted {len(packs)} context packs into database")


# Convenience function for external use
def build_context_packs(ucg_store_path: str, config: Optional[Config] = None) -> Dict[str, Any]:
    """
    Build context packs for all anchors in the UCG store.
    
    Args:
        ucg_store_path: Path to UCG SQLite database
        config: Optional configuration
        
    Returns:
        Processing statistics dictionary
    """
    if config is None:
        config = Config()
    
    packer = ContextPacker(config)
    return packer.build_context_packs(ucg_store_path)
