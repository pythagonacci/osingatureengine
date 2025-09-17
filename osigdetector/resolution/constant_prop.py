"""
Constant propagation resolver.

Tracks variable assignments within the same function/file to resolve constants
in anchor fields.
"""

from typing import Dict, List, Tuple, Optional, Any
import json

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger
from ..ingestion.ucg_store import UCGStore

logger = get_logger(__name__)


class ConstantPropagator:
    """Resolves constants through variable assignment chains."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
    
    def resolve_constants(
        self, 
        fields: Dict[str, Any], 
        file_rel: str, 
        func_qname: Optional[str],
        store: UCGStore
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Resolve constants in fields using DFG bindings.
        
        Args:
            fields: Raw fields from anchor
            file_rel: File path
            func_qname: Function qualified name
            store: UCG store for accessing DFG data
            
        Returns:
            Tuple of (resolved_fields, anomalies)
        """
        resolved_fields = fields.copy()
        anomalies = []
        
        # Get DFG bindings for this function/file
        bindings = self._get_dfg_bindings(store, file_rel, func_qname)
        
        # Try to resolve each field that might be a variable
        for field_name, field_value in fields.items():
            if isinstance(field_value, str):
                resolved_value, field_anomalies = self._resolve_field_value(
                    field_value, bindings
                )
                
                if resolved_value != field_value:
                    resolved_fields[field_name] = resolved_value
                    self.logger.debug(
                        f"Resolved {field_name}: '{field_value}' -> '{resolved_value}'"
                    )
                
                anomalies.extend(field_anomalies)
        
        return resolved_fields, anomalies
    
    def _get_dfg_bindings(
        self, 
        store: UCGStore, 
        file_rel: str, 
        func_qname: Optional[str]
    ) -> Dict[str, str]:
        """Get DFG bindings for variable assignments."""
        bindings = {}
        
        try:
            with store._conn() as conn:
                cur = conn.cursor()
                
                # Query DFG bindings for this function or file
                if func_qname:
                    # Function-scoped bindings
                    cur.execute("""
                        SELECT var_name, value_norm, value_kind
                        FROM dfg_bindings
                        WHERE func_qname = ? AND value_kind IN ('literal', 'concat')
                    """, (func_qname,))
                else:
                    # File-scoped bindings (module level)
                    cur.execute("""
                        SELECT var_name, value_norm, value_kind
                        FROM dfg_bindings
                        WHERE prov_file = ? AND value_kind IN ('literal', 'concat')
                    """, (file_rel,))
                
                for row in cur.fetchall():
                    var_name, value_norm, value_kind = row
                    if value_norm and value_kind == 'literal':
                        bindings[var_name] = value_norm
                        self.logger.debug(f"Found binding: {var_name} = {value_norm}")
        
        except Exception as e:
            self.logger.warning(f"Failed to get DFG bindings: {e}")
        
        return bindings
    
    def _resolve_field_value(
        self, 
        value: str, 
        bindings: Dict[str, str]
    ) -> Tuple[str, List[str]]:
        """
        Resolve a field value using available bindings.
        
        Args:
            value: Original field value (might be a variable name)
            bindings: Available variable bindings
            
        Returns:
            Tuple of (resolved_value, anomalies)
        """
        anomalies = []
        
        # Simple case: direct variable lookup
        if value in bindings:
            return bindings[value], anomalies
        
        # Check for simple concatenation patterns
        # Example: "PATH" + "/suffix" where PATH is a known variable
        resolved_value = self._resolve_simple_concat(value, bindings)
        if resolved_value != value:
            return resolved_value, anomalies
        
        # Check for template-like patterns
        # Example: "{BASE_URL}/api" where BASE_URL is known
        resolved_value = self._resolve_template_pattern(value, bindings)
        if resolved_value != value:
            return resolved_value, anomalies
        
        # If we can't resolve and it looks like a variable, add anomaly
        if self._looks_like_variable(value):
            anomalies.append("UNRESOLVED_VARIABLE")
            self.logger.debug(f"Could not resolve variable-like value: {value}")
        
        return value, anomalies
    
    def _resolve_simple_concat(self, value: str, bindings: Dict[str, str]) -> str:
        """
        Resolve simple concatenation patterns.
        
        This is a simplified approach - in practice, you'd parse the actual
        concatenation expressions from the AST/DFG.
        """
        # Look for variables at the start of common path patterns
        for var_name, var_value in bindings.items():
            if value.startswith(var_name + "/") or value.startswith(var_name + "_"):
                # Replace variable prefix
                return value.replace(var_name, var_value, 1)
        
        return value
    
    def _resolve_template_pattern(self, value: str, bindings: Dict[str, str]) -> str:
        """
        Resolve template-like patterns with {variable} syntax.
        """
        resolved = value
        
        for var_name, var_value in bindings.items():
            # Look for {VAR_NAME} patterns
            template_var = f"{{{var_name}}}"
            if template_var in resolved:
                resolved = resolved.replace(template_var, var_value)
        
        return resolved
    
    def _looks_like_variable(self, value: str) -> bool:
        """
        Check if a value looks like it might be a variable name.
        
        Simple heuristics:
        - All uppercase (constant style)
        - Contains underscores
        - No spaces or special chars that suggest it's a literal
        """
        if not value:
            return False
        
        # Skip obvious literals
        if value.startswith(("/", "http", "https", ".")):
            return False
        
        if any(char in value for char in [" ", ".", ":", "?", "="]):
            return False
        
        # Looks like a constant if all uppercase with underscores
        if value.isupper() and ("_" in value or len(value) > 2):
            return True
        
        # Or if it's a typical variable name pattern
        if value.replace("_", "").replace("-", "").isalnum() and "_" in value:
            return True
        
        return False
