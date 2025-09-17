"""
String resolver for concatenation, f-strings, and template literals.

Handles string building patterns to resolve dynamic string values in anchor fields.
"""

import re
from typing import Dict, List, Tuple, Optional, Any

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger
from ..ingestion.ucg_store import UCGStore

logger = get_logger(__name__)


class StringResolver:
    """Resolves string concatenation, f-strings, and template patterns."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
        self.max_resolution_depth = config.max_resolution_depth
    
    def resolve_strings(
        self, 
        fields: Dict[str, Any], 
        file_rel: str, 
        func_qname: Optional[str],
        store: UCGStore
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Resolve string patterns in fields.
        
        Args:
            fields: Fields to resolve
            file_rel: File path
            func_qname: Function qualified name
            store: UCG store for context
            
        Returns:
            Tuple of (resolved_fields, anomalies)
        """
        resolved_fields = fields.copy()
        anomalies = []
        
        # Get available string bindings from DFG
        string_bindings = self._get_string_bindings(store, file_rel, func_qname)
        
        for field_name, field_value in fields.items():
            if isinstance(field_value, str):
                resolved_value, field_anomalies = self._resolve_string_field(
                    field_value, string_bindings
                )
                
                if resolved_value != field_value:
                    resolved_fields[field_name] = resolved_value
                    self.logger.debug(
                        f"String resolved {field_name}: '{field_value}' -> '{resolved_value}'"
                    )
                
                anomalies.extend(field_anomalies)
        
        return resolved_fields, anomalies
    
    def _get_string_bindings(
        self, 
        store: UCGStore, 
        file_rel: str, 
        func_qname: Optional[str]
    ) -> Dict[str, str]:
        """Get string concatenation and template bindings from DFG."""
        bindings = {}
        
        try:
            with store._conn() as conn:
                cur = conn.cursor()
                
                # Query for concat and template bindings
                if func_qname:
                    cur.execute("""
                        SELECT var_name, value_norm, value_kind
                        FROM dfg_bindings
                        WHERE func_qname = ? AND value_kind IN ('concat', 'template', 'literal')
                    """, (func_qname,))
                else:
                    cur.execute("""
                        SELECT var_name, value_norm, value_kind
                        FROM dfg_bindings
                        WHERE prov_file = ? AND value_kind IN ('concat', 'template', 'literal')
                    """, (file_rel,))
                
                for row in cur.fetchall():
                    var_name, value_norm, value_kind = row
                    if value_norm:
                        bindings[var_name] = value_norm
                        self.logger.debug(f"Found string binding: {var_name} = {value_norm} ({value_kind})")
        
        except Exception as e:
            self.logger.warning(f"Failed to get string bindings: {e}")
        
        return bindings
    
    def _resolve_string_field(
        self, 
        value: str, 
        bindings: Dict[str, str]
    ) -> Tuple[str, List[str]]:
        """
        Resolve a string field using various string patterns.
        
        Args:
            value: Original string value
            bindings: Available string bindings
            
        Returns:
            Tuple of (resolved_value, anomalies)
        """
        anomalies = []
        
        # Try direct binding lookup first
        if value in bindings:
            return bindings[value], anomalies
        
        # Try f-string pattern resolution
        resolved_value, f_anomalies = self._resolve_f_string_pattern(value, bindings)
        anomalies.extend(f_anomalies)
        if resolved_value != value:
            return resolved_value, anomalies
        
        # Try template literal pattern (JS-style)
        resolved_value, template_anomalies = self._resolve_template_literal(value, bindings)
        anomalies.extend(template_anomalies)
        if resolved_value != value:
            return resolved_value, anomalies
        
        # Try simple concatenation patterns
        resolved_value, concat_anomalies = self._resolve_concat_pattern(value, bindings)
        anomalies.extend(concat_anomalies)
        if resolved_value != value:
            return resolved_value, anomalies
        
        # Check if this looks like an unresolved string pattern
        if self._looks_like_dynamic_string(value):
            anomalies.append("NON_LITERAL_STRING")
            self.logger.debug(f"Could not resolve dynamic string: {value}")
        
        return value, anomalies
    
    def _resolve_f_string_pattern(
        self, 
        value: str, 
        bindings: Dict[str, str]
    ) -> Tuple[str, List[str]]:
        """
        Resolve f-string patterns like f"/users/{user_id}/posts".
        
        This is simplified - real implementation would parse from AST.
        """
        anomalies = []
        
        # Look for {variable} patterns in the string
        pattern = r'\{([^}]+)\}'
        matches = re.findall(pattern, value)
        
        if not matches:
            return value, anomalies
        
        resolved_value = value
        unresolved_vars = []
        
        for var_name in matches:
            # Clean up the variable name (remove formatting, etc.)
            clean_var = var_name.split(':')[0].strip()  # Handle {var:format}
            
            if clean_var in bindings:
                # Replace the {var} with the bound value
                var_pattern = f"{{{var_name}}}"
                resolved_value = resolved_value.replace(var_pattern, bindings[clean_var])
            else:
                unresolved_vars.append(clean_var)
        
        if unresolved_vars:
            anomalies.append("UNRESOLVED_F_STRING_VARS")
            self.logger.debug(f"Unresolved f-string variables: {unresolved_vars}")
        
        return resolved_value, anomalies
    
    def _resolve_template_literal(
        self, 
        value: str, 
        bindings: Dict[str, str]
    ) -> Tuple[str, List[str]]:
        """
        Resolve template literal patterns like `${baseUrl}/api/${version}`.
        """
        anomalies = []
        
        # Look for ${variable} patterns
        pattern = r'\$\{([^}]+)\}'
        matches = re.findall(pattern, value)
        
        if not matches:
            return value, anomalies
        
        resolved_value = value
        unresolved_vars = []
        
        for var_name in matches:
            clean_var = var_name.strip()
            
            if clean_var in bindings:
                var_pattern = f"${{{var_name}}}"
                resolved_value = resolved_value.replace(var_pattern, bindings[clean_var])
            else:
                unresolved_vars.append(clean_var)
        
        if unresolved_vars:
            anomalies.append("UNRESOLVED_TEMPLATE_VARS")
            self.logger.debug(f"Unresolved template variables: {unresolved_vars}")
        
        return resolved_value, anomalies
    
    def _resolve_concat_pattern(
        self, 
        value: str, 
        bindings: Dict[str, str]
    ) -> Tuple[str, List[str]]:
        """
        Resolve simple concatenation patterns.
        
        This would ideally parse actual concat expressions from DFG,
        but for now we use heuristics.
        """
        anomalies = []
        
        # Look for variables that might be concatenated
        for var_name, var_value in bindings.items():
            # Check if the value contains the variable name as a prefix/suffix
            if value.startswith(var_name):
                # Variable at start: VAR + "/suffix"
                suffix = value[len(var_name):]
                if suffix.startswith(("/", "_", "-")):
                    return var_value + suffix, anomalies
            
            elif value.endswith(var_name):
                # Variable at end: "/prefix/" + VAR
                prefix = value[:-len(var_name)]
                if prefix.endswith(("/", "_", "-")):
                    return prefix + var_value, anomalies
        
        return value, anomalies
    
    def _looks_like_dynamic_string(self, value: str) -> bool:
        """
        Check if a string looks like it contains dynamic/unresolved patterns.
        """
        # Contains template patterns
        if re.search(r'\{[^}]+\}', value) or re.search(r'\$\{[^}]+\}', value):
            return True
        
        # Contains concatenation hints
        if " + " in value or value.count('"') > 2:
            return True
        
        # Contains variable-like segments
        segments = value.split('/')
        for segment in segments:
            if segment and segment.isupper() and '_' in segment:
                return True
        
        return False
