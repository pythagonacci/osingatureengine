"""
Neighbor facts extraction for context packing.

Extracts information about related symbols (schemas, models, classes)
that are referenced by or related to anchors.
"""

import json
import sqlite3
from typing import Dict, List, Optional, Set

from ...config import Config
from ...logging_utils import get_logger

logger = get_logger(__name__)


def get_neighbor_facts(conn: sqlite3.Connection, anchor_id: int) -> List[Dict]:
    """
    Get facts about symbols/schemas related to an anchor.
    
    Args:
        conn: Database connection
        anchor_id: Anchor ID to find neighbors for
        
    Returns:
        List of neighbor fact dictionaries
    """
    try:
        cur = conn.cursor()
        
        # Get anchor info
        cur.execute("""
            SELECT file_rel, func_qname, resolved_fields, prov_file, prov_sl, prov_el
            FROM anchors WHERE anchor_id = ?
        """, (anchor_id,))
        
        anchor_row = cur.fetchone()
        if not anchor_row:
            return []
        
        file_rel, func_qname, resolved_fields_json, prov_file, prov_sl, prov_el = anchor_row
        resolved_fields = json.loads(resolved_fields_json or "{}")
        
        neighbor_facts = []
        
        # 1. Schema/model references from resolved fields
        schema_facts = _extract_schema_references(conn, resolved_fields, file_rel)
        neighbor_facts.extend(schema_facts)
        
        # 2. Function parameter types and return types
        if func_qname:
            type_facts = _extract_type_information(conn, func_qname, file_rel)
            neighbor_facts.extend(type_facts)
        
        # 3. Related symbols from same file
        file_facts = _extract_file_symbols(conn, file_rel, prov_sl, prov_el)
        neighbor_facts.extend(file_facts)
        
        # 4. Import-based relationships
        import_facts = _extract_import_relationships(conn, file_rel)
        neighbor_facts.extend(import_facts)
        
        # Deduplicate and limit
        return _deduplicate_facts(neighbor_facts)[:10]  # Max 10 facts
        
    except Exception as e:
        logger.warning(f"Failed to get neighbor facts for anchor {anchor_id}: {e}")
        return []


def _extract_schema_references(
    conn: sqlite3.Connection, 
    resolved_fields: Dict, 
    file_rel: str
) -> List[Dict]:
    """Extract schema/model information referenced in fields."""
    facts = []
    cur = conn.cursor()
    
    # Look for schema names in various fields
    schema_candidates = set()
    
    for field_name, field_value in resolved_fields.items():
        if isinstance(field_value, str):
            # Common schema/model naming patterns
            if any(keyword in field_name.lower() for keyword in ['schema', 'model', 'type']):
                schema_candidates.add(field_value)
            
            # Look for CamelCase names (likely models/schemas)
            if field_value and field_value[0].isupper() and any(c.islower() for c in field_value):
                schema_candidates.add(field_value)
    
    # Query for class definitions that might be schemas
    for schema_name in schema_candidates:
        cur.execute("""
            SELECT name, file_rel, prov_sl, prov_el
            FROM classes 
            WHERE name = ? OR name LIKE ?
            ORDER BY CASE WHEN file_rel = ? THEN 0 ELSE 1 END
            LIMIT 3
        """, (schema_name, f"%{schema_name}%", file_rel))
        
        for row in cur.fetchall():
            name, class_file, start_line, end_line = row
            facts.append({
                "type": "schema",
                "name": name,
                "file": class_file,
                "location": f"{class_file}:{start_line}-{end_line}",
                "confidence": 0.8 if class_file == file_rel else 0.6
            })
    
    return facts


def _extract_type_information(
    conn: sqlite3.Connection, 
    func_qname: str, 
    file_rel: str
) -> List[Dict]:
    """Extract type information from function signatures and annotations."""
    facts = []
    cur = conn.cursor()
    
    try:
        # Get function info
        cur.execute("""
            SELECT name, prov_file, prov_sl, prov_el
            FROM functions WHERE qname = ?
        """, (func_qname,))
        
        func_row = cur.fetchone()
        if not func_row:
            return facts
        
        func_name, func_file, func_start, func_end = func_row
        
        # Look for symbols defined near this function that might be types
        cur.execute("""
            SELECT name, kind, prov_sl, prov_el
            FROM symbols 
            WHERE file_rel = ? 
            AND prov_sl BETWEEN ? AND ?
            AND kind IN ('class', 'type', 'interface')
            ORDER BY prov_sl
        """, (file_rel, max(1, func_start - 10), func_end + 10))
        
        for row in cur.fetchall():
            symbol_name, symbol_kind, sym_start, sym_end = row
            facts.append({
                "type": "type_definition",
                "name": symbol_name,
                "kind": symbol_kind,
                "file": file_rel,
                "location": f"{file_rel}:{sym_start}-{sym_end}",
                "confidence": 0.7
            })
    
    except Exception as e:
        logger.debug(f"Failed to extract type info for {func_qname}: {e}")
    
    return facts


def _extract_file_symbols(
    conn: sqlite3.Connection, 
    file_rel: str, 
    anchor_start: int, 
    anchor_end: int
) -> List[Dict]:
    """Extract relevant symbols from the same file."""
    facts = []
    cur = conn.cursor()
    
    try:
        # Get classes and functions in the same file
        cur.execute("""
            SELECT name, 'class' as type, prov_sl, prov_el
            FROM classes WHERE file_rel = ?
            UNION ALL
            SELECT name, 'function' as type, prov_sl, prov_el  
            FROM functions WHERE file_rel = ?
            ORDER BY prov_sl
        """, (file_rel, file_rel))
        
        for row in cur.fetchall():
            name, symbol_type, start_line, end_line = row
            
            # Skip if it's the anchor itself
            if start_line <= anchor_start <= end_line:
                continue
            
            # Prioritize symbols close to the anchor
            distance = min(
                abs(start_line - anchor_start),
                abs(end_line - anchor_end)
            )
            
            confidence = max(0.3, 0.9 - (distance / 50.0))  # Closer = higher confidence
            
            facts.append({
                "type": "file_symbol",
                "name": name,
                "kind": symbol_type,
                "file": file_rel,
                "location": f"{file_rel}:{start_line}-{end_line}",
                "distance": distance,
                "confidence": confidence
            })
    
    except Exception as e:
        logger.debug(f"Failed to extract file symbols: {e}")
    
    return facts


def _extract_import_relationships(conn: sqlite3.Connection, file_rel: str) -> List[Dict]:
    """Extract information about imported modules and their exports."""
    facts = []
    cur = conn.cursor()
    
    try:
        # Get import edges from this file
        cur.execute("""
            SELECT dst_qname, note
            FROM edges 
            WHERE file_rel = ? AND kind = 'imports'
            LIMIT 20
        """, (file_rel,))
        
        for row in cur.fetchall():
            dst_qname, note = row
            
            # Try to find what this import provides
            if dst_qname and dst_qname.startswith('ident:'):
                imported_name = dst_qname[6:]  # Remove 'ident:' prefix
                
                facts.append({
                    "type": "import",
                    "name": imported_name,
                    "file": file_rel,
                    "note": note or "",
                    "confidence": 0.5
                })
    
    except Exception as e:
        logger.debug(f"Failed to extract import relationships: {e}")
    
    return facts


def _deduplicate_facts(facts: List[Dict]) -> List[Dict]:
    """Remove duplicate facts and sort by confidence."""
    seen = set()
    unique_facts = []
    
    # Sort by confidence (highest first)
    sorted_facts = sorted(facts, key=lambda x: x.get('confidence', 0), reverse=True)
    
    for fact in sorted_facts:
        # Create a key for deduplication
        key = (fact.get('type'), fact.get('name'), fact.get('file'))
        
        if key not in seen:
            seen.add(key)
            unique_facts.append(fact)
    
    return unique_facts


def get_related_schemas(conn: sqlite3.Connection, anchor_fields: Dict) -> List[Dict]:
    """
    Get schema definitions that might be related to anchor fields.
    
    This is a more targeted version for specific schema extraction.
    """
    schemas = []
    cur = conn.cursor()
    
    # Extract potential schema names from fields
    potential_schemas = set()
    
    for field_name, field_value in anchor_fields.items():
        if isinstance(field_value, str) and field_value:
            # Look for CamelCase names
            if field_value[0].isupper():
                potential_schemas.add(field_value)
            
            # Look for schema-related field names
            if 'schema' in field_name.lower() or 'model' in field_name.lower():
                potential_schemas.add(field_value)
    
    # Query for matching classes
    for schema_name in potential_schemas:
        cur.execute("""
            SELECT name, file_rel, prov_sl, prov_el
            FROM classes
            WHERE name = ?
            LIMIT 1
        """, (schema_name,))
        
        row = cur.fetchone()
        if row:
            name, file_rel, start_line, end_line = row
            
            # Try to get field information from symbols in the class
            cur.execute("""
                SELECT name
                FROM symbols
                WHERE file_rel = ? 
                AND prov_sl BETWEEN ? AND ?
                AND kind = 'var'
                ORDER BY prov_sl
                LIMIT 10
            """, (file_rel, start_line, end_line))
            
            fields = [field_row[0] for field_row in cur.fetchall()]
            
            schemas.append({
                "schema": name,
                "fields": fields,
                "file": file_rel,
                "location": f"{file_rel}:{start_line}-{end_line}"
            })
    
    return schemas
