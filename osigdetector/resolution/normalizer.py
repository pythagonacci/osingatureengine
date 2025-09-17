"""
Field normalizer for canonicalizing resolved values.

Standardizes paths, tables, hosts, schema names, and other values to
consistent formats for better matching and analysis.
"""

import re
from typing import Dict, Any
from urllib.parse import urlparse

from ..config import Config
from ..logging_utils import get_logger

logger = get_logger(__name__)


class Normalizer:
    """Normalizes and canonicalizes field values."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
        
        # Compile normalization patterns
        self._compile_patterns()
    
    def normalize_fields(self, fields: Dict[str, Any], anchor_kind: str) -> Dict[str, Any]:
        """
        Normalize all fields based on anchor kind and field types.
        
        Args:
            fields: Fields to normalize
            anchor_kind: Type of anchor (http_response, db_write, etc.)
            
        Returns:
            Normalized fields dictionary
        """
        normalized_fields = fields.copy()
        
        # Apply kind-specific normalizations
        if anchor_kind.startswith("http_") or anchor_kind == "route":
            normalized_fields = self._normalize_http_fields(normalized_fields)
        
        elif anchor_kind.startswith("db_"):
            normalized_fields = self._normalize_db_fields(normalized_fields)
        
        elif anchor_kind == "external":
            normalized_fields = self._normalize_external_fields(normalized_fields)
        
        # Apply general field normalizations
        normalized_fields = self._normalize_general_fields(normalized_fields)
        
        return normalized_fields
    
    def _compile_patterns(self):
        """Compile regex patterns for normalization."""
        
        # Path parameter patterns
        self.path_param_patterns = [
            (re.compile(r'\{([^}]+)\}'), r':\1'),  # {id} -> :id
            (re.compile(r'<([^>]+)>'), r':\1'),    # <id> -> :id (Flask style)
            (re.compile(r':([^/]+)'), r':\1'),     # Already parameterized
        ]
        
        # Variable segment patterns (for paths that weren't templated)
        self.variable_segment_pattern = re.compile(r'/[A-Z_][A-Z0-9_]*(?=/|$)')
        
        # Host cleaning patterns
        self.protocol_pattern = re.compile(r'^https?://')
        self.port_pattern = re.compile(r':\d+$')
        self.trailing_slash_pattern = re.compile(r'/$')
        
        # Table name patterns
        self.table_quote_pattern = re.compile(r'[`"\[\]]')
        self.plural_pattern = re.compile(r's$', re.IGNORECASE)
    
    def _normalize_http_fields(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize HTTP/route-specific fields."""
        normalized = fields.copy()
        
        # Normalize paths
        if 'path' in fields:
            normalized['path_norm'] = self._normalize_path(fields['path'])
        
        # Normalize methods
        if 'method' in fields:
            normalized['method'] = str(fields['method']).upper()
        
        # Normalize status codes
        if 'status' in fields:
            normalized['status'] = self._normalize_status_code(fields['status'])
        
        if 'statuses' in fields:
            normalized['statuses'] = self._normalize_status_codes(fields['statuses'])
        
        # Normalize hosts
        if 'host' in fields:
            normalized['host_norm'] = self._normalize_host(fields['host'])
        
        return normalized
    
    def _normalize_db_fields(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize database-specific fields."""
        normalized = fields.copy()
        
        # Normalize table names
        if 'table' in fields:
            normalized['table_norm'] = self._normalize_table_name(fields['table'])
        
        if 'sql_tables' in fields and isinstance(fields['sql_tables'], list):
            normalized['sql_tables_norm'] = [
                self._normalize_table_name(table) for table in fields['sql_tables']
            ]
        
        # Normalize column names
        if 'column' in fields:
            normalized['column_norm'] = self._normalize_column_name(fields['column'])
        
        if 'sql_columns' in fields and isinstance(fields['sql_columns'], list):
            normalized['sql_columns_norm'] = [
                self._normalize_column_name(col) for col in fields['sql_columns']
            ]
        
        # Normalize SQL operations
        if 'sql_operation' in fields:
            normalized['sql_operation'] = str(fields['sql_operation']).upper()
        
        return normalized
    
    def _normalize_external_fields(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize external service fields."""
        normalized = fields.copy()
        
        # Normalize URLs
        if 'url' in fields:
            normalized['url_norm'] = self._normalize_url(fields['url'])
        
        # Normalize service names
        if 'service' in fields:
            normalized['service_norm'] = self._normalize_service_name(fields['service'])
        
        return normalized
    
    def _normalize_general_fields(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Apply general normalizations to all field types."""
        normalized = fields.copy()
        
        # Normalize schema names
        if 'schema' in fields:
            normalized['schema_norm'] = self._normalize_schema_name(fields['schema'])
        
        # Normalize action names
        if 'action' in fields:
            normalized['action_norm'] = self._normalize_action_name(fields['action'])
        
        return normalized
    
    def _normalize_path(self, path: str) -> str:
        """
        Normalize URL paths to canonical form.
        
        Examples:
        - /users/{id} -> /users/:id
        - /users/123 -> /users/:id (if 123 looks like a parameter)
        - /api/v1/users -> /api/v1/users (unchanged)
        """
        if not path or not isinstance(path, str):
            return ""
        
        normalized = path.strip()
        
        # Ensure it starts with /
        if not normalized.startswith('/'):
            normalized = '/' + normalized
        
        # Apply parameter patterns
        for pattern, replacement in self.path_param_patterns:
            normalized = pattern.sub(replacement, normalized)
        
        # Convert variable-looking segments to parameters
        # Example: /users/USER_ID -> /users/:user_id
        def replace_variable_segment(match):
            segment = match.group(0)[1:]  # Remove leading /
            param_name = segment.lower()
            return f'/:{param_name}'
        
        normalized = self.variable_segment_pattern.sub(replace_variable_segment, normalized)
        
        # Convert numeric segments that look like IDs to parameters
        normalized = re.sub(r'/\d+(?=/|$)', '/:id', normalized)
        
        # Convert UUID-like segments to parameters
        uuid_pattern = r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)'
        normalized = re.sub(uuid_pattern, '/:uuid', normalized, flags=re.IGNORECASE)
        
        # Remove trailing slash unless it's the root
        if len(normalized) > 1:
            normalized = self.trailing_slash_pattern.sub('', normalized)
        
        return normalized
    
    def _normalize_host(self, host: str) -> str:
        """
        Normalize host names.
        
        Examples:
        - https://api.example.com:443/ -> api.example.com
        - HTTP://API.EXAMPLE.COM -> api.example.com
        """
        if not host or not isinstance(host, str):
            return ""
        
        normalized = host.strip().lower()
        
        # Remove protocol
        normalized = self.protocol_pattern.sub('', normalized)
        
        # Remove trailing slash first
        normalized = self.trailing_slash_pattern.sub('', normalized)
        
        # Remove standard ports
        if normalized.endswith(':443') or normalized.endswith(':80'):
            normalized = re.sub(r':(?:80|443)$', '', normalized)
        
        # Remove www prefix
        if normalized.startswith('www.'):
            normalized = normalized[4:]
        
        return normalized
    
    def _normalize_table_name(self, table: str) -> str:
        """
        Normalize database table names.
        
        Examples:
        - "Users" -> users
        - `user_profiles` -> user_profiles
        - [Orders] -> orders
        """
        if not table or not isinstance(table, str):
            return ""
        
        normalized = table.strip()
        
        # Remove quotes and brackets
        normalized = self.table_quote_pattern.sub('', normalized)
        
        # Convert to lowercase
        normalized = normalized.lower()
        
        # Singularize simple plurals (basic approach)
        if len(normalized) > 3 and normalized.endswith('s') and not normalized.endswith('ss'):
            singular = normalized[:-1]
            # Check if it's likely a plural (not a word that naturally ends in 's')
            if not any(normalized.endswith(suffix) for suffix in ['ous', 'ics', 'ness', 'less']):
                normalized = singular
        
        return normalized
    
    def _normalize_column_name(self, column: str) -> str:
        """Normalize database column names."""
        if not column or not isinstance(column, str):
            return ""
        
        # Remove quotes and convert to lowercase
        normalized = self.table_quote_pattern.sub('', column.strip()).lower()
        
        return normalized
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URLs for external services."""
        if not url or not isinstance(url, str):
            return ""
        
        try:
            parsed = urlparse(url)
            
            # Reconstruct with normalized components
            scheme = parsed.scheme.lower() if parsed.scheme else 'https'
            netloc = parsed.netloc.lower() if parsed.netloc else ''
            path = self._normalize_path(parsed.path) if parsed.path else '/'
            
            # Remove standard ports
            if ':80' in netloc and scheme == 'http':
                netloc = netloc.replace(':80', '')
            elif ':443' in netloc and scheme == 'https':
                netloc = netloc.replace(':443', '')
            
            normalized = f"{scheme}://{netloc}{path}"
            
            return normalized
        
        except Exception:
            # If URL parsing fails, do basic normalization
            return url.strip().lower()
    
    def _normalize_service_name(self, service: str) -> str:
        """Normalize service names."""
        if not service or not isinstance(service, str):
            return ""
        
        # Convert to lowercase and replace separators with underscores
        normalized = service.strip().lower()
        normalized = re.sub(r'[-\s\.]+', '_', normalized)
        
        return normalized
    
    def _normalize_schema_name(self, schema: str) -> str:
        """Normalize schema names to alphanumeric underscore format."""
        if not schema or not isinstance(schema, str):
            return ""
        
        # Convert to lowercase, replace non-alphanumeric with underscores
        normalized = re.sub(r'[^a-zA-Z0-9_]', '_', schema.strip().lower())
        
        # Remove multiple consecutive underscores
        normalized = re.sub(r'_+', '_', normalized)
        
        # Remove leading/trailing underscores
        normalized = normalized.strip('_')
        
        return normalized
    
    def _normalize_action_name(self, action: str) -> str:
        """Normalize action names."""
        if not action or not isinstance(action, str):
            return ""
        
        # Convert to lowercase
        normalized = action.strip().lower()
        
        # Map common action aliases to standard names
        action_mapping = {
            'create': 'create',
            'insert': 'create',
            'add': 'create',
            'read': 'read',
            'get': 'read',
            'find': 'read',
            'select': 'read',
            'update': 'update',
            'modify': 'update',
            'edit': 'update',
            'delete': 'delete',
            'remove': 'delete',
            'destroy': 'delete',
        }
        
        return action_mapping.get(normalized, normalized)
    
    def _normalize_status_code(self, status: Any) -> int:
        """Normalize a single status code."""
        try:
            return int(status)
        except (ValueError, TypeError):
            return 0
    
    def _normalize_status_codes(self, statuses: Any) -> list:
        """Normalize a list of status codes."""
        if not isinstance(statuses, (list, tuple)):
            return []
        
        normalized = []
        for status in statuses:
            norm_status = self._normalize_status_code(status)
            if norm_status > 0:
                normalized.append(norm_status)
        
        return sorted(list(set(normalized)))  # Remove duplicates and sort
