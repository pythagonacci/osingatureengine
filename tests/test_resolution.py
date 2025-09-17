"""
Tests for Step 3 resolution pipeline.
"""

import tempfile
import pytest
from pathlib import Path

from osigdetector.resolution.constant_prop import ConstantPropagator
from osigdetector.resolution.string_resolver import StringResolver
from osigdetector.resolution.sql_resolver import SQLResolver
from osigdetector.resolution.env_resolver import EnvironmentResolver
from osigdetector.resolution.normalizer import Normalizer
from osigdetector.config import Config


class TestConstantPropagator:
    """Test constant propagation resolver."""
    
    def test_resolve_constants_basic(self):
        """Test basic constant resolution."""
        config = Config()
        propagator = ConstantPropagator(config)
        
        # Mock bindings
        bindings = {"API_PATH": "/api/v1", "VERSION": "v2"}
        
        # Test direct variable lookup
        resolved, anomalies = propagator._resolve_field_value("API_PATH", bindings)
        assert resolved == "/api/v1"
        assert len(anomalies) == 0
        
        # Test unresolved variable
        resolved, anomalies = propagator._resolve_field_value("UNKNOWN_VAR", bindings)
        assert resolved == "UNKNOWN_VAR"
        assert "UNRESOLVED_VARIABLE" in anomalies


class TestStringResolver:
    """Test string resolution for f-strings and templates."""
    
    def test_resolve_f_string_pattern(self):
        """Test f-string pattern resolution."""
        config = Config()
        resolver = StringResolver(config)
        
        bindings = {"user_id": "123", "action": "update"}
        
        # Test f-string resolution
        resolved, anomalies = resolver._resolve_f_string_pattern(
            "/users/{user_id}/actions/{action}", bindings
        )
        assert resolved == "/users/123/actions/update"
        assert len(anomalies) == 0
        
        # Test unresolved f-string
        resolved, anomalies = resolver._resolve_f_string_pattern(
            "/users/{unknown_var}", bindings
        )
        assert resolved == "/users/{unknown_var}"
        assert "UNRESOLVED_F_STRING_VARS" in anomalies
    
    def test_resolve_template_literal(self):
        """Test template literal resolution."""
        config = Config()
        resolver = StringResolver(config)
        
        bindings = {"baseUrl": "https://api.example.com", "version": "v1"}
        
        # Test template literal resolution
        resolved, anomalies = resolver._resolve_template_literal(
            "${baseUrl}/api/${version}", bindings
        )
        assert resolved == "https://api.example.com/api/v1"
        assert len(anomalies) == 0


class TestSQLResolver:
    """Test SQL parsing and resolution."""
    
    def test_parse_select_statement(self):
        """Test SELECT statement parsing."""
        config = Config()
        resolver = SQLResolver(config)
        
        sql = "SELECT id, name FROM users WHERE active = 1"
        sql_info, anomalies = resolver._parse_sql_string(sql)
        
        assert sql_info["sql_operation"] == "SELECT"
        assert "users" in sql_info["sql_tables"]
        assert "id" in sql_info["sql_columns"]
        assert "name" in sql_info["sql_columns"]
        assert len(anomalies) == 0
    
    def test_parse_insert_statement(self):
        """Test INSERT statement parsing."""
        config = Config()
        resolver = SQLResolver(config)
        
        sql = "INSERT INTO orders (customer_id, total) VALUES (?, ?)"
        sql_info, anomalies = resolver._parse_sql_string(sql)
        
        assert sql_info["sql_operation"] == "INSERT"
        assert "orders" in sql_info["sql_tables"]
        assert "customer_id" in sql_info["sql_columns"]
        assert "total" in sql_info["sql_columns"]
    
    def test_dynamic_sql_detection(self):
        """Test detection of dynamic SQL."""
        config = Config()
        resolver = SQLResolver(config)
        
        # Non-SQL string should not be parsed
        sql_info, anomalies = resolver._parse_sql_string("some random string")
        assert "UNKNOWN_SQL_OPERATION" in anomalies


class TestEnvironmentResolver:
    """Test environment variable resolution."""
    
    def test_looks_like_env_var(self):
        """Test environment variable detection."""
        config = Config()
        resolver = EnvironmentResolver(config)
        
        # Should detect as env vars
        assert resolver._looks_like_env_var("DATABASE_URL")
        assert resolver._looks_like_env_var("API_KEY")
        assert resolver._looks_like_env_var("NODE_ENV")
        
        # Should not detect as env vars
        assert not resolver._looks_like_env_var("/api/users")
        assert not resolver._looks_like_env_var("hello world")
        assert not resolver._looks_like_env_var("user_id")
    
    def test_extract_env_patterns(self):
        """Test extraction of environment patterns from source."""
        config = Config()
        resolver = EnvironmentResolver(config)
        
        # Python source with env vars
        python_source = '''
import os
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///default.db")
API_KEY = os.environ["API_KEY"]
HOST = os.getenv("HOST")
'''
        
        env_bindings = resolver._extract_env_patterns(python_source)
        
        assert env_bindings["DATABASE_URL"] == "sqlite:///default.db"
        assert env_bindings["API_KEY"] is None  # No default
        assert env_bindings["HOST"] is None  # No default
        
        # JavaScript source with env vars
        js_source = '''
const host = process.env.HOST || "localhost";
const port = process.env.PORT;
const apiUrl = process.env["API_URL"] || "http://localhost:3000";
'''
        
        env_bindings = resolver._extract_env_patterns(js_source)
        
        assert env_bindings["HOST"] == "localhost"
        assert env_bindings["PORT"] is None
        assert env_bindings["API_URL"] == "http://localhost:3000"


class TestNormalizer:
    """Test field normalization."""
    
    def test_normalize_path(self):
        """Test path normalization."""
        config = Config()
        normalizer = Normalizer(config)
        
        # Test parameter normalization
        assert normalizer._normalize_path("/users/{id}") == "/users/:id"
        assert normalizer._normalize_path("/users/<int:id>") == "/users/:int:id"
        
        # Test numeric ID normalization
        assert normalizer._normalize_path("/users/123") == "/users/:id"
        assert normalizer._normalize_path("/users/123/posts/456") == "/users/:id/posts/:id"
        
        # Test UUID normalization
        uuid_path = "/users/550e8400-e29b-41d4-a716-446655440000/profile"
        assert normalizer._normalize_path(uuid_path) == "/users/:uuid/profile"
        
        # Test trailing slash removal
        assert normalizer._normalize_path("/api/users/") == "/api/users"
        assert normalizer._normalize_path("/") == "/"  # Root should keep slash
    
    def test_normalize_host(self):
        """Test host normalization."""
        config = Config()
        normalizer = Normalizer(config)
        
        # Test protocol removal
        assert normalizer._normalize_host("https://api.example.com") == "api.example.com"
        assert normalizer._normalize_host("HTTP://API.EXAMPLE.COM") == "api.example.com"
        
        # Test port removal
        assert normalizer._normalize_host("api.example.com:443") == "api.example.com"
        assert normalizer._normalize_host("api.example.com:80") == "api.example.com"
        
        # Test www removal
        assert normalizer._normalize_host("www.example.com") == "example.com"
        
        # Test complex case
        assert normalizer._normalize_host("https://www.api.example.com:443/") == "api.example.com"
    
    def test_normalize_table_name(self):
        """Test table name normalization."""
        config = Config()
        normalizer = Normalizer(config)
        
        # Test quote removal and case conversion
        assert normalizer._normalize_table_name('"Users"') == "user"  # Singularized
        assert normalizer._normalize_table_name("`user_profiles`") == "user_profile"  # Singularized
        assert normalizer._normalize_table_name("[Orders]") == "order"  # Singularized
        
        # Test pluralization handling
        assert normalizer._normalize_table_name("users") == "user"
        assert normalizer._normalize_table_name("categories") == "categorie"  # Simple rule
        assert normalizer._normalize_table_name("address") == "address"  # Not plural
    
    def test_normalize_http_fields(self):
        """Test HTTP field normalization."""
        config = Config()
        normalizer = Normalizer(config)
        
        fields = {
            "method": "get",
            "path": "/users/{id}/posts",
            "host": "https://api.example.com:443",
            "status": "200"
        }
        
        normalized = normalizer._normalize_http_fields(fields)
        
        assert normalized["method"] == "GET"
        assert normalized["path_norm"] == "/users/:id/posts"
        assert normalized["host_norm"] == "api.example.com"
        assert normalized["status"] == 200
    
    def test_normalize_db_fields(self):
        """Test database field normalization."""
        config = Config()
        normalizer = Normalizer(config)
        
        fields = {
            "table": '"Users"',
            "sql_operation": "select",
            "sql_tables": ["Orders", "order_items"],
            "sql_columns": ["ID", "user_name"]
        }
        
        normalized = normalizer._normalize_db_fields(fields)
        
        assert normalized["table_norm"] == "user"
        assert normalized["sql_operation"] == "SELECT"
        assert normalized["sql_tables_norm"] == ["order", "order_item"]
        assert normalized["sql_columns_norm"] == ["id", "user_name"]


def test_resolution_pipeline_integration():
    """Test the resolution pipeline with a simple case."""
    # This would be a more complex integration test
    # For now, just verify the pipeline can be imported and instantiated
    from osigdetector.resolution.run_resolution import run_resolution
    
    # The function exists and can be called (would need real DB for full test)
    assert callable(run_resolution)
