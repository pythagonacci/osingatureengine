"""
SQL resolver for parsing SQL strings and extracting table/column information.

Handles SQL queries when they are literal strings to extract database metadata.
"""

import re
from typing import Dict, List, Tuple, Set, Any

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger

logger = get_logger(__name__)


class SQLResolver:
    """Resolves SQL strings to extract table and column information."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
        
        # Compile SQL parsing patterns
        self._compile_sql_patterns()
    
    def resolve_sql(self, fields: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """
        Resolve SQL strings in fields to extract database metadata.
        
        Args:
            fields: Fields that may contain SQL strings
            
        Returns:
            Tuple of (resolved_fields, anomalies)
        """
        resolved_fields = fields.copy()
        anomalies = []
        
        # Look for SQL-related fields
        sql_fields = self._identify_sql_fields(fields)
        
        for field_name in sql_fields:
            field_value = fields.get(field_name, "")
            if isinstance(field_value, str) and field_value:
                
                sql_info, field_anomalies = self._parse_sql_string(field_value)
                anomalies.extend(field_anomalies)
                
                if sql_info:
                    # Add extracted SQL metadata to resolved fields
                    resolved_fields.update(sql_info)
                    self.logger.debug(f"Extracted SQL info from {field_name}: {sql_info}")
        
        return resolved_fields, anomalies
    
    def _identify_sql_fields(self, fields: Dict[str, Any]) -> List[str]:
        """Identify fields that likely contain SQL strings."""
        sql_fields = []
        
        # Direct SQL field names
        direct_sql_fields = ['sql', 'query', 'statement', 'command']
        for field_name in direct_sql_fields:
            if field_name in fields:
                sql_fields.append(field_name)
        
        # Fields with SQL-like content
        for field_name, field_value in fields.items():
            if isinstance(field_value, str) and self._looks_like_sql(field_value):
                sql_fields.append(field_name)
        
        return sql_fields
    
    def _looks_like_sql(self, value: str) -> bool:
        """Check if a string looks like SQL."""
        if not value or len(value) < 6:
            return False
        
        value_upper = value.upper().strip()
        
        # Common SQL keywords at the start
        sql_starters = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
        
        return any(value_upper.startswith(starter) for starter in sql_starters)
    
    def _compile_sql_patterns(self):
        """Compile regex patterns for SQL parsing."""
        
        # SELECT patterns
        self.select_pattern = re.compile(
            r'SELECT\s+(.+?)\s+FROM\s+([^\s;]+)',
            re.IGNORECASE | re.DOTALL
        )
        
        # INSERT patterns  
        self.insert_pattern = re.compile(
            r'INSERT\s+INTO\s+([^\s(;]+)(?:\s*\(([^)]+)\))?',
            re.IGNORECASE
        )
        
        # UPDATE patterns
        self.update_pattern = re.compile(
            r'UPDATE\s+([^\s;]+)\s+SET',
            re.IGNORECASE
        )
        
        # DELETE patterns
        self.delete_pattern = re.compile(
            r'DELETE\s+FROM\s+([^\s;]+)',
            re.IGNORECASE
        )
        
        # Table name pattern (for cleaning)
        self.table_name_pattern = re.compile(r'[`"\[\]]', re.IGNORECASE)
    
    def _parse_sql_string(self, sql: str) -> Tuple[Dict[str, Any], List[str]]:
        """
        Parse a SQL string to extract metadata.
        
        Args:
            sql: SQL string to parse
            
        Returns:
            Tuple of (sql_info_dict, anomalies)
        """
        sql_info = {}
        anomalies = []
        
        try:
            sql_clean = sql.strip()
            
            # Determine SQL operation type
            operation = self._get_sql_operation(sql_clean)
            if operation:
                sql_info['sql_operation'] = operation
            
            # Extract tables and columns based on operation
            if operation == 'SELECT':
                tables, columns = self._parse_select(sql_clean)
            elif operation == 'INSERT':
                tables, columns = self._parse_insert(sql_clean)
            elif operation == 'UPDATE':
                tables, columns = self._parse_update(sql_clean)
            elif operation == 'DELETE':
                tables, columns = self._parse_delete(sql_clean)
            else:
                tables, columns = set(), set()
                anomalies.append("UNKNOWN_SQL_OPERATION")
            
            if tables:
                sql_info['sql_tables'] = list(tables)
            
            if columns:
                sql_info['sql_columns'] = list(columns)
            
            # If we couldn't extract anything useful, mark as dynamic
            if not tables and not columns:
                anomalies.append("DYNAMIC_SQL")
                self.logger.debug(f"Could not parse SQL: {sql_clean[:100]}...")
        
        except Exception as e:
            self.logger.warning(f"SQL parsing failed: {e}")
            anomalies.append("SQL_PARSE_ERROR")
        
        return sql_info, anomalies
    
    def _get_sql_operation(self, sql: str) -> str:
        """Determine the primary SQL operation."""
        sql_upper = sql.upper().strip()
        
        operations = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
        
        for op in operations:
            if sql_upper.startswith(op):
                return op
        
        return ""
    
    def _parse_select(self, sql: str) -> Tuple[Set[str], Set[str]]:
        """Parse SELECT statement."""
        tables = set()
        columns = set()
        
        match = self.select_pattern.search(sql)
        if match:
            columns_part, table_part = match.groups()
            
            # Extract table names
            table_names = self._extract_table_names(table_part)
            tables.update(table_names)
            
            # Extract column names (simplified)
            column_names = self._extract_column_names(columns_part)
            columns.update(column_names)
        
        return tables, columns
    
    def _parse_insert(self, sql: str) -> Tuple[Set[str], Set[str]]:
        """Parse INSERT statement."""
        tables = set()
        columns = set()
        
        match = self.insert_pattern.search(sql)
        if match:
            table_name, columns_part = match.groups()
            
            # Clean and add table name
            clean_table = self._clean_table_name(table_name)
            if clean_table:
                tables.add(clean_table)
            
            # Extract column names if specified
            if columns_part:
                column_names = self._extract_column_names(columns_part)
                columns.update(column_names)
        
        return tables, columns
    
    def _parse_update(self, sql: str) -> Tuple[Set[str], Set[str]]:
        """Parse UPDATE statement."""
        tables = set()
        columns = set()
        
        match = self.update_pattern.search(sql)
        if match:
            table_name = match.group(1)
            
            clean_table = self._clean_table_name(table_name)
            if clean_table:
                tables.add(clean_table)
            
            # Extract SET columns (simplified)
            set_pattern = re.search(r'SET\s+(.+?)(?:\s+WHERE|$)', sql, re.IGNORECASE | re.DOTALL)
            if set_pattern:
                set_part = set_pattern.group(1)
                # Extract column names from SET clause
                set_columns = re.findall(r'(\w+)\s*=', set_part)
                columns.update(set_columns)
        
        return tables, columns
    
    def _parse_delete(self, sql: str) -> Tuple[Set[str], Set[str]]:
        """Parse DELETE statement."""
        tables = set()
        columns = set()
        
        match = self.delete_pattern.search(sql)
        if match:
            table_name = match.group(1)
            
            clean_table = self._clean_table_name(table_name)
            if clean_table:
                tables.add(clean_table)
        
        return tables, columns
    
    def _extract_table_names(self, table_part: str) -> Set[str]:
        """Extract table names from FROM/JOIN clauses."""
        tables = set()
        
        # Split by common separators and keywords
        parts = re.split(r'\s+(?:JOIN|,)\s+', table_part, flags=re.IGNORECASE)
        
        for part in parts:
            # Remove JOIN keywords and aliases
            part = re.sub(r'\s+(?:INNER|LEFT|RIGHT|OUTER|FULL)\s+JOIN\s+', ' ', part, flags=re.IGNORECASE)
            part = re.sub(r'\s+(?:AS\s+)?\w+$', '', part, flags=re.IGNORECASE)  # Remove alias
            
            table_name = self._clean_table_name(part.strip())
            if table_name:
                tables.add(table_name)
        
        return tables
    
    def _extract_column_names(self, columns_part: str) -> Set[str]:
        """Extract column names from SELECT or column lists."""
        columns = set()
        
        # Skip * selections
        if columns_part.strip() == '*':
            return columns
        
        # Split by commas
        column_parts = columns_part.split(',')
        
        for part in column_parts:
            part = part.strip()
            
            # Remove functions and aliases
            part = re.sub(r'\w+\([^)]*\)', '', part)  # Remove functions
            part = re.sub(r'\s+AS\s+\w+', '', part, flags=re.IGNORECASE)  # Remove aliases
            
            # Extract simple column names
            column_match = re.search(r'(\w+)(?:\.\w+)?', part)
            if column_match:
                column_name = column_match.group(1)
                if column_name and not column_name.upper() in ['SELECT', 'FROM', 'WHERE', 'AND', 'OR']:
                    columns.add(column_name)
        
        return columns
    
    def _clean_table_name(self, table_name: str) -> str:
        """Clean and normalize table name."""
        if not table_name:
            return ""
        
        # Remove quotes, brackets, backticks
        clean_name = self.table_name_pattern.sub('', table_name)
        
        # Remove schema prefixes (e.g., schema.table -> table)
        if '.' in clean_name:
            clean_name = clean_name.split('.')[-1]
        
        # Basic validation
        clean_name = clean_name.strip()
        if clean_name and clean_name.replace('_', '').isalnum():
            return clean_name.lower()
        
        return ""
