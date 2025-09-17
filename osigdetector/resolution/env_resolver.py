"""
Environment variable resolver.

Handles environment variable lookups and resolves them to default values
when available, or flags anomalies when unresolved.
"""

import re
from typing import Dict, List, Tuple, Any, Optional

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger
from ..ingestion.ucg_store import UCGStore

logger = get_logger(__name__)


class EnvironmentResolver:
    """Resolves environment variable references in anchor fields."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
        
        # Compile environment variable patterns
        self._compile_env_patterns()
    
    def resolve_env_vars(
        self, 
        fields: Dict[str, Any], 
        file_rel: str, 
        store: UCGStore
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Resolve environment variable references in fields.
        
        Args:
            fields: Fields to resolve
            file_rel: File path for context
            store: UCG store for additional context
            
        Returns:
            Tuple of (resolved_fields, anomalies)
        """
        resolved_fields = fields.copy()
        anomalies = []
        
        # Get environment variable bindings from source analysis
        env_bindings = self._get_env_bindings(store, file_rel)
        
        for field_name, field_value in fields.items():
            if isinstance(field_value, str):
                resolved_value, field_anomalies = self._resolve_env_field(
                    field_value, env_bindings
                )
                
                if resolved_value != field_value:
                    resolved_fields[field_name] = resolved_value
                    self.logger.debug(
                        f"Env resolved {field_name}: '{field_value}' -> '{resolved_value}'"
                    )
                
                anomalies.extend(field_anomalies)
        
        return resolved_fields, anomalies
    
    def _compile_env_patterns(self):
        """Compile regex patterns for environment variable detection."""
        
        # Python: os.getenv("VAR", "default") or os.environ.get("VAR", "default")
        self.python_getenv_pattern = re.compile(
            r'os\.(?:getenv|environ\.get)\s*\(\s*["\']([^"\']+)["\']\s*(?:,\s*["\']([^"\']*)["\'])?\s*\)',
            re.IGNORECASE
        )
        
        # Python: os.environ["VAR"]
        self.python_environ_pattern = re.compile(
            r'os\.environ\s*\[\s*["\']([^"\']+)["\']\s*\]',
            re.IGNORECASE
        )
        
        # JavaScript: process.env.VAR or process.env["VAR"]
        self.js_env_pattern = re.compile(
            r'process\.env\.(\w+)|process\.env\s*\[\s*["\']([^"\']+)["\']\s*\]',
            re.IGNORECASE
        )
        
        # JavaScript: process.env.VAR || "default" or process.env["VAR"] || "default"
        self.js_env_default_pattern = re.compile(
            r'(?:process\.env\.(\w+)|process\.env\s*\[\s*["\']([^"\']+)["\']\s*\])\s*\|\|\s*["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        
        # Generic ${VAR} or $VAR patterns
        self.generic_env_pattern = re.compile(r'\$\{(\w+)\}|\$(\w+)')
    
    def _get_env_bindings(self, store: UCGStore, file_rel: str) -> Dict[str, Optional[str]]:
        """
        Get environment variable bindings from source analysis.
        
        This would ideally parse the actual environment variable calls
        from the AST/UCG, but for now we use heuristics.
        """
        env_bindings = {}
        
        try:
            # Get the source file content to scan for env patterns
            with store._conn() as conn:
                cur = conn.cursor()
                cur.execute("SELECT abs_locator FROM files WHERE rel_path = ?", (file_rel,))
                row = cur.fetchone()
                
                if row:
                    abs_locator = row[0]
                    source_content = self._read_source_file(abs_locator)
                    
                    if source_content:
                        env_bindings.update(self._extract_env_patterns(source_content))
        
        except Exception as e:
            self.logger.warning(f"Failed to get environment bindings: {e}")
        
        return env_bindings
    
    def _read_source_file(self, abs_locator: str) -> Optional[str]:
        """Read source file content from locator."""
        try:
            if abs_locator.startswith("file://"):
                file_path = abs_locator[7:]  # Remove file:// prefix
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            # Add support for zip:// locators if needed
        except Exception as e:
            self.logger.debug(f"Could not read source file {abs_locator}: {e}")
        
        return None
    
    def _extract_env_patterns(self, source_content: str) -> Dict[str, Optional[str]]:
        """Extract environment variable patterns from source code."""
        env_bindings = {}
        
        # Python os.getenv patterns with defaults
        for match in self.python_getenv_pattern.finditer(source_content):
            var_name = match.group(1)
            default_value = match.group(2) if match.group(2) else None
            env_bindings[var_name] = default_value
        
        # Python os.environ patterns (no default)
        for match in self.python_environ_pattern.finditer(source_content):
            var_name = match.group(1)
            if var_name not in env_bindings:  # Don't override if we have a default
                env_bindings[var_name] = None
        
        # JavaScript process.env with defaults
        for match in self.js_env_default_pattern.finditer(source_content):
            var_name = match.group(1) or match.group(2)  # Either dot notation or bracket notation
            default_value = match.group(3)
            if var_name:
                env_bindings[var_name] = default_value
        
        # JavaScript process.env patterns (no default)
        for match in self.js_env_pattern.finditer(source_content):
            var_name = match.group(1) or match.group(2)
            if var_name and var_name not in env_bindings:
                env_bindings[var_name] = None
        
        # Generic ${VAR} patterns
        for match in self.generic_env_pattern.finditer(source_content):
            var_name = match.group(1) or match.group(2)
            if var_name and var_name not in env_bindings:
                env_bindings[var_name] = None
        
        return env_bindings
    
    def _resolve_env_field(
        self, 
        value: str, 
        env_bindings: Dict[str, Optional[str]]
    ) -> Tuple[str, List[str]]:
        """
        Resolve environment variables in a field value.
        
        Args:
            value: Field value that may contain env vars
            env_bindings: Known environment variable bindings
            
        Returns:
            Tuple of (resolved_value, anomalies)
        """
        anomalies = []
        resolved_value = value
        
        # Check if the entire value is an environment variable
        if value in env_bindings:
            default_value = env_bindings[value]
            if default_value is not None:
                return default_value, anomalies
            else:
                anomalies.append("VAR_HOST")  # Or VAR_PATH, VAR_DB, etc.
                return value, anomalies
        
        # Check for environment variable patterns within the value
        resolved_value, pattern_anomalies = self._resolve_env_patterns_in_string(
            value, env_bindings
        )
        anomalies.extend(pattern_anomalies)
        
        return resolved_value, anomalies
    
    def _resolve_env_patterns_in_string(
        self, 
        value: str, 
        env_bindings: Dict[str, Optional[str]]
    ) -> Tuple[str, List[str]]:
        """Resolve environment variable patterns within a string."""
        anomalies = []
        resolved_value = value
        
        # Resolve ${VAR} patterns
        def replace_env_var(match):
            var_name = match.group(1) or match.group(2)
            
            if var_name in env_bindings:
                default_value = env_bindings[var_name]
                if default_value is not None:
                    return default_value
                else:
                    # Variable found but no default - flag as unresolved
                    anomalies.append(f"UNRESOLVED_ENV_VAR_{var_name}")
                    return match.group(0)  # Keep original pattern
            else:
                # Unknown environment variable
                anomalies.append(f"UNKNOWN_ENV_VAR_{var_name}")
                return match.group(0)
        
        resolved_value = self.generic_env_pattern.sub(replace_env_var, resolved_value)
        
        # Check for other common environment variable indicators
        if self._looks_like_env_var(value) and not anomalies:
            anomalies.append("POTENTIAL_ENV_VAR")
        
        return resolved_value, anomalies
    
    def _looks_like_env_var(self, value: str) -> bool:
        """Check if a value looks like it might reference environment variables."""
        if not value:
            return False
        
        # Common environment variable naming patterns
        env_indicators = [
            'HOST', 'PORT', 'URL', 'URI', 'API_KEY', 'SECRET', 'TOKEN',
            'DATABASE_', 'DB_', 'REDIS_', 'MONGO_', 'POSTGRES_',
            'AWS_', 'AZURE_', 'GCP_', 'NODE_ENV', 'ENV', 'ENVIRONMENT'
        ]
        
        value_upper = value.upper()
        
        # Check if the value matches common env var patterns
        if any(indicator in value_upper for indicator in env_indicators):
            return True
        
        # Check if it's all uppercase with underscores (typical env var format)
        if value.isupper() and '_' in value and value.replace('_', '').isalnum():
            return True
        
        return False
