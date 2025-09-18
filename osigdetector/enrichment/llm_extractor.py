"""
LLM Extractor - Step 5: LLM Enrichment Orchestrator

Main orchestrator that processes context packs through LLM to produce
fully enriched OSigs with semantic understanding and citations.
"""

import json
import sqlite3
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger, log_pipeline_step
from ..ingestion.ucg_store import UCGStore
from .llm_client import LLMClient, LLMResponse
from .json_validator import OSigValidator
from .osig_model import OSig, Citation

logger = get_logger(__name__)


@dataclass
class EnrichmentStats:
    """Statistics for LLM enrichment process."""
    
    total_packs: int = 0
    successful_extractions: int = 0
    failed_extractions: int = 0
    fallback_osigs: int = 0
    hypothesis_osigs: int = 0
    total_tokens_used: int = 0
    total_cost_estimate: float = 0.0
    average_confidence: float = 0.0
    anomaly_counts: Dict[str, int] = None
    
    def __post_init__(self):
        if self.anomaly_counts is None:
            self.anomaly_counts = {}


class LLMExtractor:
    """Main orchestrator for LLM-based OSig enrichment."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
        self.llm_client = LLMClient(config)
        self.validator = OSigValidator(config)
    
    def enrich_osigs(self, ucg_store_path: str) -> EnrichmentStats:
        """
        Main enrichment pipeline that processes all context packs.
        
        Args:
            ucg_store_path: Path to UCG SQLite database
            
        Returns:
            EnrichmentStats with processing results
        """
        log_pipeline_step("llm_enrichment", "started", {"db_path": ucg_store_path})
        
        stats = EnrichmentStats()
        
        try:
            store = UCGStore(ucg_store_path)
            
            with store._conn() as conn:
                # Get all context packs that need processing
                context_packs = self._get_context_packs_for_processing(conn)
                stats.total_packs = len(context_packs)
                
                logger.info(f"Processing {len(context_packs)} context packs for LLM enrichment")
                
                # Clear existing OSigs for reprocessing
                self._clear_existing_osigs(conn)
                
                # Process each context pack
                osigs_to_insert = []
                
                for pack_data in context_packs:
                    try:
                        osig, pack_stats = self._process_single_context_pack(pack_data)
                        
                        if osig:
                            osigs_to_insert.append((pack_data["anchor_id"], osig))
                            
                            # Update stats
                            if osig.hypothesis:
                                stats.hypothesis_osigs += 1
                            else:
                                stats.successful_extractions += 1
                            
                            stats.total_tokens_used += pack_stats.get("tokens_used", 0)
                            stats.total_cost_estimate += pack_stats.get("cost_estimate", 0.0)
                            
                            # Count anomalies
                            for anomaly in osig.anomalies:
                                stats.anomaly_counts[anomaly] = stats.anomaly_counts.get(anomaly, 0) + 1
                        
                        else:
                            stats.failed_extractions += 1
                    
                    except Exception as e:
                        self.logger.error(f"Failed to process context pack {pack_data['pack_id']}: {e}")
                        stats.failed_extractions += 1
                        continue
                
                # Insert all OSigs into database
                self._insert_osigs(conn, osigs_to_insert)
                conn.commit()
                
                # Calculate final stats
                if stats.successful_extractions + stats.hypothesis_osigs > 0:
                    total_osigs = stats.successful_extractions + stats.hypothesis_osigs
                    confidence_sum = sum(
                        osig.llm_confidence for _, osig in osigs_to_insert
                    )
                    stats.average_confidence = confidence_sum / total_osigs
                
                log_pipeline_step("llm_enrichment", "completed", {
                    "total_packs": stats.total_packs,
                    "successful": stats.successful_extractions,
                    "failed": stats.failed_extractions,
                    "hypothesis": stats.hypothesis_osigs,
                    "avg_confidence": stats.average_confidence,
                    "total_cost": stats.total_cost_estimate
                })
                
                return stats
        
        except Exception as e:
            log_pipeline_step("llm_enrichment", "failed", {"error": str(e)})
            raise
    
    def _get_context_packs_for_processing(self, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
        """Get all context packs that need LLM processing."""
        cur = conn.cursor()
        
        # Get context packs that don't have corresponding OSigs yet
        cur.execute("""
            SELECT cp.pack_id, cp.anchor_id, cp.bundle, cp.size_bytes
            FROM context_packs cp
            LEFT JOIN osigs o ON cp.anchor_id = o.anchor_id
            WHERE o.osig_id IS NULL
            ORDER BY cp.pack_id
        """)
        
        packs = []
        for row in cur.fetchall():
            pack_id, anchor_id, bundle_json, size_bytes = row
            
            try:
                bundle = json.loads(bundle_json)
                packs.append({
                    "pack_id": pack_id,
                    "anchor_id": anchor_id,
                    "bundle": bundle,
                    "size_bytes": size_bytes
                })
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid bundle JSON for pack {pack_id}: {e}")
                continue
        
        return packs
    
    def _clear_existing_osigs(self, conn: sqlite3.Connection):
        """Clear existing OSigs for reprocessing."""
        cur = conn.cursor()
        cur.execute("DELETE FROM osigs")
        logger.debug("Cleared existing OSigs for reprocessing")
    
    def _process_single_context_pack(
        self, 
        pack_data: Dict[str, Any]
    ) -> tuple[Optional[OSig], Dict[str, Any]]:
        """
        Process a single context pack through LLM.
        
        Args:
            pack_data: Context pack data with bundle
            
        Returns:
            Tuple of (OSig or None, processing stats)
        """
        pack_id = pack_data["pack_id"]
        bundle = pack_data["bundle"]
        
        self.logger.debug(f"Processing context pack {pack_id}")
        
        # Call LLM
        llm_response = self.llm_client.extract_osig(bundle)
        
        pack_stats = {
            "tokens_used": llm_response.tokens_used,
            "cost_estimate": llm_response.cost_estimate,
            "latency_ms": llm_response.latency_ms
        }
        
        if not llm_response.success:
            self.logger.error(f"LLM call failed for pack {pack_id}: {llm_response.error}")
            
            # Create fallback OSig
            fallback_osig = self.validator.create_fallback_osig(bundle, llm_response.error or "LLM_CALL_FAILED")
            return fallback_osig, pack_stats
        
        # Validate and parse LLM response
        osig, anomalies = self.validator.validate_and_parse(llm_response.content, bundle)
        
        if osig is None:
            self.logger.error(f"Failed to validate LLM response for pack {pack_id}")
            
            # Create fallback OSig
            fallback_osig = self.validator.create_fallback_osig(bundle, "VALIDATION_FAILED")
            return fallback_osig, pack_stats
        
        # Log extraction success
        self.logger.debug(
            f"Successfully extracted OSig for pack {pack_id}: "
            f"kind={osig.kind}, confidence={osig.llm_confidence:.2f}"
        )
        
        return osig, pack_stats
    
    def _insert_osigs(self, conn: sqlite3.Connection, osigs_data: List[tuple]):
        """Insert OSigs into the database."""
        cur = conn.cursor()
        
        insert_data = []
        for anchor_id, osig in osigs_data:
            insert_data.append((
                anchor_id,
                osig.kind,
                json.dumps(osig.fields),
                json.dumps(osig.data_atoms),
                json.dumps(osig.joins),
                osig.summary,
                json.dumps([citation.dict() for citation in osig.citations]),
                osig.llm_confidence,
                json.dumps(osig.anomalies),
                int(osig.hypothesis)
            ))
        
        cur.executemany("""
            INSERT INTO osigs 
            (anchor_id, kind, fields, data_atoms, joins, summary, 
             citations, llm_confidence, anomalies, hypothesis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, insert_data)
        
        logger.info(f"Inserted {len(insert_data)} OSigs into database")


# Convenience function for external use
def enrich_osigs(ucg_store_path: str, config: Optional[Config] = None) -> EnrichmentStats:
    """
    Enrich all context packs into OSigs using LLM.
    
    Args:
        ucg_store_path: Path to UCG SQLite database
        config: Optional configuration
        
    Returns:
        EnrichmentStats with processing results
    """
    if config is None:
        config = Config()
    
    extractor = LLMExtractor(config)
    return extractor.enrich_osigs(ucg_store_path)


# Utility functions for testing and debugging
def get_osig_by_anchor_id(ucg_store_path: str, anchor_id: int) -> Optional[OSig]:
    """Get OSig for a specific anchor ID."""
    try:
        store = UCGStore(ucg_store_path)
        
        with store._conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT kind, fields, data_atoms, joins, summary, 
                       citations, llm_confidence, anomalies, hypothesis
                FROM osigs WHERE anchor_id = ?
            """, (anchor_id,))
            
            row = cur.fetchone()
            if not row:
                return None
            
            kind, fields_json, data_atoms_json, joins_json, summary, citations_json, confidence, anomalies_json, hypothesis = row
            
            return OSig(
                kind=kind,
                fields=json.loads(fields_json),
                data_atoms=json.loads(data_atoms_json or "[]"),
                joins=json.loads(joins_json or "{}"),
                summary=summary,
                citations=[Citation(**c) for c in json.loads(citations_json)],
                llm_confidence=confidence,
                anomalies=json.loads(anomalies_json or "[]"),
                hypothesis=bool(hypothesis)
            )
    
    except Exception as e:
        logger.error(f"Failed to get OSig for anchor {anchor_id}: {e}")
        return None


def list_osigs_by_kind(ucg_store_path: str, kind: str) -> List[OSig]:
    """List all OSigs of a specific kind."""
    osigs = []
    
    try:
        store = UCGStore(ucg_store_path)
        
        with store._conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT anchor_id, kind, fields, data_atoms, joins, summary,
                       citations, llm_confidence, anomalies, hypothesis
                FROM osigs WHERE kind = ?
                ORDER BY llm_confidence DESC
            """, (kind,))
            
            for row in cur.fetchall():
                anchor_id, kind, fields_json, data_atoms_json, joins_json, summary, citations_json, confidence, anomalies_json, hypothesis = row
                
                osig = OSig(
                    kind=kind,
                    fields=json.loads(fields_json),
                    data_atoms=json.loads(data_atoms_json or "[]"),
                    joins=json.loads(joins_json or "{}"),
                    summary=summary,
                    citations=[Citation(**c) for c in json.loads(citations_json)],
                    llm_confidence=confidence,
                    anomalies=json.loads(anomalies_json or "[]"),
                    hypothesis=bool(hypothesis)
                )
                osigs.append(osig)
    
    except Exception as e:
        logger.error(f"Failed to list OSigs by kind {kind}: {e}")
    
    return osigs
