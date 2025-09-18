"""
Data Flow Graph utilities for context packing.

Extracts resolved constants and variable bindings from DFG analysis.
"""

import json
import sqlite3
from typing import Dict, List, Optional

from ...config import Config
from ...logging_utils import get_logger

logger = get_logger(__name__)


def get_dfg_bindings(conn: sqlite3.Connection, anchor_id: int) -> Dict[str, str]:
    """
    Get DFG constant bindings relevant to an anchor.
    
    Args:
        conn: Database connection
        anchor_id: Anchor ID to get bindings for
        
    Returns:
        Dictionary of variable -> resolved value mappings
    """
    try:
        cur = conn.cursor()
        
        # Get anchor context
        cur.execute("""
            SELECT file_rel, func_qname, prov_file, prov_sl, prov_el
            FROM anchors WHERE anchor_id = ?
        """, (anchor_id,))
        
        anchor_row = cur.fetchone()
        if not anchor_row:
            return {}
        
        file_rel, func_qname, prov_file, prov_sl, prov_el = anchor_row
        
        bindings = {}
        
        # 1. Function-scoped bindings
        if func_qname:
            func_bindings = _get_function_bindings(conn, func_qname)
            bindings.update(func_bindings)
        
        # 2. File-scoped bindings (module level)
        file_bindings = _get_file_bindings(conn, file_rel)
        bindings.update(file_bindings)
        
        # 3. Local bindings near the anchor
        local_bindings = _get_local_bindings(conn, file_rel, prov_sl, prov_el)
        bindings.update(local_bindings)
        
        return bindings
        
    except Exception as e:
        logger.warning(f"Failed to get DFG bindings for anchor {anchor_id}: {e}")
        return {}


def _get_function_bindings(conn: sqlite3.Connection, func_qname: str) -> Dict[str, str]:
    """Get DFG bindings scoped to a specific function."""
    bindings = {}
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT var_name, value_norm, value_kind
            FROM dfg_bindings
            WHERE func_qname = ? 
            AND value_kind IN ('literal', 'concat', 'template')
            AND value_norm IS NOT NULL
            ORDER BY binding_id
        """, (func_qname,))
        
        for row in cur.fetchall():
            var_name, value_norm, value_kind = row
            
            # Prioritize literal values
            if var_name not in bindings or value_kind == 'literal':
                bindings[var_name] = value_norm
                logger.debug(f"Function binding: {var_name} = {value_norm} ({value_kind})")
    
    except Exception as e:
        logger.debug(f"Failed to get function bindings for {func_qname}: {e}")
    
    return bindings


def _get_file_bindings(conn: sqlite3.Connection, file_rel: str) -> Dict[str, str]:
    """Get DFG bindings at file/module scope."""
    bindings = {}
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT var_name, value_norm, value_kind
            FROM dfg_bindings
            WHERE prov_file = ?
            AND func_qname IS NULL  -- Module-level bindings
            AND value_kind IN ('literal', 'concat', 'template')
            AND value_norm IS NOT NULL
            ORDER BY binding_id
        """, (file_rel,))
        
        for row in cur.fetchall():
            var_name, value_norm, value_kind = row
            
            if var_name not in bindings or value_kind == 'literal':
                bindings[var_name] = value_norm
                logger.debug(f"File binding: {var_name} = {value_norm} ({value_kind})")
    
    except Exception as e:
        logger.debug(f"Failed to get file bindings for {file_rel}: {e}")
    
    return bindings


def _get_local_bindings(
    conn: sqlite3.Connection, 
    file_rel: str, 
    anchor_start: int, 
    anchor_end: int,
    window: int = 20
) -> Dict[str, str]:
    """Get DFG bindings from lines near the anchor."""
    bindings = {}
    cur = conn.cursor()
    
    try:
        # Look for bindings in a window around the anchor
        search_start = max(1, anchor_start - window)
        search_end = anchor_end + window
        
        cur.execute("""
            SELECT var_name, value_norm, value_kind, prov_sl
            FROM dfg_bindings
            WHERE prov_file = ?
            AND prov_sl BETWEEN ? AND ?
            AND value_kind IN ('literal', 'concat', 'template')
            AND value_norm IS NOT NULL
            ORDER BY ABS(prov_sl - ?) ASC  -- Closest to anchor first
        """, (file_rel, search_start, search_end, anchor_start))
        
        for row in cur.fetchall():
            var_name, value_norm, value_kind, binding_line = row
            
            # Prefer bindings closer to the anchor
            if var_name not in bindings:
                bindings[var_name] = value_norm
                logger.debug(f"Local binding: {var_name} = {value_norm} (line {binding_line})")
    
    except Exception as e:
        logger.debug(f"Failed to get local bindings: {e}")
    
    return bindings


def get_cfg_outcomes(conn: sqlite3.Connection, anchor_id: int) -> List[int]:
    """
    Get CFG outcomes (status codes, return values) for an anchor.
    
    Args:
        conn: Database connection
        anchor_id: Anchor ID
        
    Returns:
        List of status codes or return values
    """
    try:
        cur = conn.cursor()
        
        # Get anchor function context
        cur.execute("""
            SELECT func_qname, file_rel, prov_sl, prov_el
            FROM anchors WHERE anchor_id = ?
        """, (anchor_id,))
        
        anchor_row = cur.fetchone()
        if not anchor_row:
            return []
        
        func_qname, file_rel, prov_sl, prov_el = anchor_row
        
        outcomes = []
        
        # 1. Look for CFG blocks in the same function
        if func_qname:
            outcomes.extend(_extract_function_outcomes(conn, func_qname))
        
        # 2. Look for status codes in resolved fields (from Step 3)
        cur.execute("""
            SELECT resolved_fields FROM anchors WHERE anchor_id = ?
        """, (anchor_id,))
        
        resolved_row = cur.fetchone()
        if resolved_row and resolved_row[0]:
            resolved_fields = json.loads(resolved_row[0])
            
            # Extract status codes from resolved fields
            if 'status' in resolved_fields:
                try:
                    outcomes.append(int(resolved_fields['status']))
                except (ValueError, TypeError):
                    pass
            
            if 'statuses' in resolved_fields and isinstance(resolved_fields['statuses'], list):
                for status in resolved_fields['statuses']:
                    try:
                        outcomes.append(int(status))
                    except (ValueError, TypeError):
                        pass
        
        # Remove duplicates and sort
        return sorted(list(set(outcomes)))
        
    except Exception as e:
        logger.warning(f"Failed to get CFG outcomes for anchor {anchor_id}: {e}")
        return []


def _extract_function_outcomes(conn: sqlite3.Connection, func_qname: str) -> List[int]:
    """Extract outcomes (return values, status codes) from CFG blocks."""
    outcomes = []
    cur = conn.cursor()
    
    try:
        # Look for CFG blocks that might contain status codes
        cur.execute("""
            SELECT exit_kind, prov_file, prov_sl, prov_el
            FROM cfg_blocks
            WHERE func_qname = ?
            AND exit_kind IN ('return', 'raise')
        """, (func_qname,))
        
        for row in cur.fetchall():
            exit_kind, prov_file, start_line, end_line = row
            
            # This is a simplified approach - in a full implementation,
            # we'd parse the actual return/raise statements to extract status codes
            
            # For now, we'll look for common HTTP status code patterns
            # This could be enhanced by parsing the actual CFG block content
            if exit_kind == 'raise':
                # Common exception status codes
                outcomes.extend([400, 404, 500])
            elif exit_kind == 'return':
                # Common success status codes  
                outcomes.extend([200, 201])
    
    except Exception as e:
        logger.debug(f"Failed to extract function outcomes for {func_qname}: {e}")
    
    return outcomes


def get_framework_hint(conn: sqlite3.Connection, file_rel: str) -> Dict[str, str]:
    """
    Get framework hints for a file based on imports and patterns.
    
    Args:
        conn: Database connection
        file_rel: File relative path
        
    Returns:
        Dictionary with language and framework information
    """
    try:
        cur = conn.cursor()
        
        # Get file language
        cur.execute("SELECT language FROM files WHERE rel_path = ?", (file_rel,))
        lang_row = cur.fetchone()
        language = lang_row[0] if lang_row else "unknown"
        
        # Get import information
        cur.execute("""
            SELECT dst_qname, note
            FROM edges
            WHERE file_rel = ? AND kind = 'imports'
        """, (file_rel,))
        
        imports = []
        for row in cur.fetchall():
            dst_qname, note = row
            if dst_qname:
                imports.append(dst_qname.lower())
        
        # Detect framework based on imports
        framework = _detect_framework_from_imports(imports, language)
        
        return {
            "lang": language,
            "framework": framework,
            "imports_count": len(imports)
        }
        
    except Exception as e:
        logger.debug(f"Failed to get framework hint for {file_rel}: {e}")
        return {"lang": "unknown", "framework": "unknown"}


def _detect_framework_from_imports(imports: List[str], language: str) -> str:
    """Detect framework based on import patterns."""
    
    # Framework detection patterns
    patterns = {
        "fastapi": ["fastapi", "ident:fastapi"],
        "flask": ["flask", "ident:flask"],
        "django": ["django", "ident:django"],
        "express": ["express", "ident:express"],
        "react": ["react", "ident:react"],
        "vue": ["vue", "ident:vue"],
        "angular": ["@angular", "ident:@angular"],
        "spring": ["springframework", "ident:springframework"],
        "gin": ["gin-gonic", "ident:gin"],
    }
    
    # Count matches for each framework
    framework_scores = {}
    
    for framework, framework_patterns in patterns.items():
        score = 0
        for pattern in framework_patterns:
            for import_str in imports:
                if pattern in import_str:
                    score += 1
        
        if score > 0:
            framework_scores[framework] = score
    
    # Return the framework with the highest score
    if framework_scores:
        return max(framework_scores.items(), key=lambda x: x[1])[0]
    
    return "unknown"
