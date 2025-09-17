"""
Resolution pipeline entrypoint - Step 3: String & Constant Resolution

Main pipeline that processes anchors from Step 2 and resolves/normalizes their fields.
"""

from typing import Dict, List, Optional
import json

from ..ingestion.ucg_store import UCGStore
from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger, log_pipeline_step

from .constant_prop import ConstantPropagator
from .string_resolver import StringResolver
from .sql_resolver import SQLResolver
from .env_resolver import EnvironmentResolver
from .normalizer import Normalizer

logger = get_logger(__name__)


def run_resolution(ucg_store_path: str, config: Optional[Config] = None) -> None:
    """
    Main resolution pipeline that processes anchors from Step 2.
    
    Args:
        ucg_store_path: Path to SQLite database with UCG data
        config: Optional configuration object
    """
    if config is None:
        config = Config()
    
    log_pipeline_step("resolution", "started", {"db_path": ucg_store_path})
    
    try:
        store = UCGStore(ucg_store_path)
        
        # Initialize resolvers
        const_prop = ConstantPropagator(config)
        string_resolver = StringResolver(config)
        sql_resolver = SQLResolver(config)
        env_resolver = EnvironmentResolver(config)
        normalizer = Normalizer(config)
        
        # Get all anchors from Step 2
        anchors = _get_anchors_for_resolution(store)
        logger.info(f"Processing {len(anchors)} anchors for resolution")
        
        resolved_count = 0
        
        with store._conn() as conn:
            cur = conn.cursor()
            
            for anchor in anchors:
                try:
                    # Run resolution pipeline on this anchor
                    resolved_anchor = _resolve_anchor(
                        anchor, store, const_prop, string_resolver, 
                        sql_resolver, env_resolver, normalizer
                    )
                    
                    # Update the anchor in database
                    _update_resolved_anchor(cur, resolved_anchor)
                    resolved_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to resolve anchor {anchor.get('anchor_id')}: {e}")
                    continue
            
            conn.commit()
        
        log_pipeline_step("resolution", "completed", {
            "total_anchors": len(anchors),
            "resolved_anchors": resolved_count
        })
        
    except Exception as e:
        log_pipeline_step("resolution", "failed", {"error": str(e)})
        raise


def _get_anchors_for_resolution(store: UCGStore) -> List[Dict]:
    """Get all anchors that need resolution."""
    with store._conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT anchor_id, effect_id, file_rel, func_qname, kind,
                   raw_fields, resolved_fields, anomalies, static_confidence,
                   prov_file, prov_sl, prov_el, note
            FROM anchors
            WHERE resolved_fields IS NULL OR resolved_fields = '{}'
        """)
        
        anchors = []
        for row in cur.fetchall():
            anchor = {
                "anchor_id": row[0],
                "effect_id": row[1], 
                "file_rel": row[2],
                "func_qname": row[3],
                "kind": row[4],
                "raw_fields": json.loads(row[5] or "{}"),
                "resolved_fields": json.loads(row[6] or "{}"),
                "anomalies": json.loads(row[7] or "[]"),
                "static_confidence": row[8],
                "prov_file": row[9],
                "prov_sl": row[10],
                "prov_el": row[11],
                "note": row[12],
            }
            anchors.append(anchor)
        
        return anchors


def _resolve_anchor(
    anchor: Dict,
    store: UCGStore,
    const_prop: ConstantPropagator,
    string_resolver: StringResolver,
    sql_resolver: SQLResolver,
    env_resolver: EnvironmentResolver,
    normalizer: Normalizer
) -> Dict:
    """
    Run the full resolution pipeline on a single anchor.
    
    Returns updated anchor with resolved_fields and confidence_static.
    """
    logger.debug(f"Resolving anchor {anchor['anchor_id']} of kind {anchor['kind']}")
    
    # Start with raw fields
    resolved_fields = anchor["raw_fields"].copy()
    anomalies = anchor["anomalies"].copy()
    confidence = 0.9  # Start optimistic, reduce as we encounter issues
    
    # Phase 1: Constant propagation
    try:
        resolved_fields, const_anomalies = const_prop.resolve_constants(
            resolved_fields, anchor["file_rel"], anchor["func_qname"], store
        )
        anomalies.extend(const_anomalies)
        if const_anomalies:
            confidence = min(confidence, 0.8)
    except Exception as e:
        logger.warning(f"Constant propagation failed for anchor {anchor['anchor_id']}: {e}")
        anomalies.append("CONST_PROP_FAILED")
        confidence = min(confidence, 0.7)
    
    # Phase 2: String resolution (concat, f-strings, templates)
    try:
        resolved_fields, string_anomalies = string_resolver.resolve_strings(
            resolved_fields, anchor["file_rel"], anchor["func_qname"], store
        )
        anomalies.extend(string_anomalies)
        if string_anomalies:
            confidence = min(confidence, 0.7)
    except Exception as e:
        logger.warning(f"String resolution failed for anchor {anchor['anchor_id']}: {e}")
        anomalies.append("STRING_RESOLVE_FAILED")
        confidence = min(confidence, 0.6)
    
    # Phase 3: SQL resolution (if applicable)
    if anchor["kind"].startswith("db_"):
        try:
            resolved_fields, sql_anomalies = sql_resolver.resolve_sql(resolved_fields)
            anomalies.extend(sql_anomalies)
            if sql_anomalies:
                confidence = min(confidence, 0.7)
        except Exception as e:
            logger.warning(f"SQL resolution failed for anchor {anchor['anchor_id']}: {e}")
            anomalies.append("SQL_RESOLVE_FAILED")
            confidence = min(confidence, 0.6)
    
    # Phase 4: Environment variable resolution
    try:
        resolved_fields, env_anomalies = env_resolver.resolve_env_vars(
            resolved_fields, anchor["file_rel"], store
        )
        anomalies.extend(env_anomalies)
        if env_anomalies:
            confidence = min(confidence, 0.7)
    except Exception as e:
        logger.warning(f"Environment resolution failed for anchor {anchor['anchor_id']}: {e}")
        anomalies.append("ENV_RESOLVE_FAILED")
        confidence = min(confidence, 0.6)
    
    # Phase 5: Normalization
    try:
        resolved_fields = normalizer.normalize_fields(resolved_fields, anchor["kind"])
    except Exception as e:
        logger.warning(f"Normalization failed for anchor {anchor['anchor_id']}: {e}")
        anomalies.append("NORMALIZATION_FAILED")
        confidence = min(confidence, 0.8)
    
    # Update anchor with resolved data
    anchor["resolved_fields"] = resolved_fields
    anchor["anomalies"] = anomalies
    anchor["confidence_static"] = confidence
    
    return anchor


def _update_resolved_anchor(cur, anchor: Dict) -> None:
    """Update anchor in database with resolved fields."""
    cur.execute(
        """
        UPDATE anchors 
        SET resolved_fields = ?, anomalies = ?, confidence_static = ?
        WHERE anchor_id = ?
        """,
        (
            json.dumps(anchor["resolved_fields"]),
            json.dumps(anchor["anomalies"]),
            anchor["confidence_static"],
            anchor["anchor_id"]
        )
    )
