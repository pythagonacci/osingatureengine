"""
Tests for Step 4 context packing system.
"""

import json
import tempfile
import sqlite3
from pathlib import Path
import pytest

from osigdetector.enrichment.context_packer import ContextPacker, build_context_packs
from osigdetector.enrichment.helpers.snippet_utils import extract_snippet, get_file_imports
from osigdetector.enrichment.helpers.neighbor_utils import get_neighbor_facts
from osigdetector.enrichment.helpers.dfg_utils import get_dfg_bindings, get_framework_hint
from osigdetector.config import Config
from osigdetector.ingestion.ucg_store import UCGStore


class TestSnippetUtils:
    """Test code snippet extraction utilities."""
    
    def test_extract_snippet_basic(self, tmp_path):
        """Test basic snippet extraction."""
        # Create a test file
        test_file = tmp_path / "test.py"
        test_content = """# Line 1
def hello():  # Line 2
    print("world")  # Line 3
    return True  # Line 4
# Line 5
def goodbye():  # Line 6
    pass  # Line 7
"""
        test_file.write_text(test_content)
        
        # Extract snippet around line 3-4
        snippet = extract_snippet(str(test_file), 3, 4, window=2)
        
        # Should include lines 1-6 (3-4 ±2 window)
        assert len(snippet) == 6
        assert ">>   3| " in snippet[2]  # Highlighted anchor line
        assert ">>   4| " in snippet[3]  # Highlighted anchor line
        assert "   1| # Line 1" in snippet[0]  # Context line
    
    def test_extract_snippet_edge_cases(self, tmp_path):
        """Test snippet extraction edge cases."""
        test_file = tmp_path / "small.py"
        test_file.write_text("line1\nline2\nline3")
        
        # Window larger than file
        snippet = extract_snippet(str(test_file), 2, 2, window=10)
        assert len(snippet) == 3  # Should not exceed file bounds
        
        # Start at beginning
        snippet = extract_snippet(str(test_file), 1, 1, window=1)
        assert len(snippet) == 2  # Lines 1-2
    
    def test_get_file_imports(self, tmp_path):
        """Test import extraction."""
        test_file = tmp_path / "imports.py"
        test_content = """import os
from fastapi import APIRouter
import json
from typing import Dict, List

def function():
    pass
"""
        test_file.write_text(test_content)
        
        imports = get_file_imports(str(test_file))
        
        assert "import os" in imports
        assert "from fastapi import APIRouter" in imports
        assert "import json" in imports
        assert "from typing import Dict, List" in imports
        assert len(imports) == 4


class TestNeighborUtils:
    """Test neighbor facts extraction."""
    
    def test_get_neighbor_facts_empty_db(self):
        """Test neighbor facts with empty database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            conn = sqlite3.connect(tmp.name)
            
            # Create minimal schema
            conn.execute("""
                CREATE TABLE anchors (
                    anchor_id INTEGER PRIMARY KEY,
                    file_rel TEXT,
                    func_qname TEXT,
                    resolved_fields TEXT,
                    prov_file TEXT,
                    prov_sl INTEGER,
                    prov_el INTEGER
                )
            """)
            
            # Should return empty list for non-existent anchor
            facts = get_neighbor_facts(conn, 999)
            assert facts == []
            
            conn.close()


class TestDFGUtils:
    """Test DFG utilities."""
    
    def test_get_dfg_bindings_empty_db(self):
        """Test DFG bindings with empty database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            conn = sqlite3.connect(tmp.name)
            
            # Create minimal schema
            conn.execute("""
                CREATE TABLE anchors (
                    anchor_id INTEGER PRIMARY KEY,
                    file_rel TEXT,
                    func_qname TEXT,
                    prov_file TEXT,
                    prov_sl INTEGER,
                    prov_el INTEGER
                )
            """)
            
            conn.execute("""
                CREATE TABLE dfg_bindings (
                    binding_id INTEGER PRIMARY KEY,
                    func_qname TEXT,
                    var_name TEXT,
                    value_norm TEXT,
                    value_kind TEXT,
                    prov_file TEXT,
                    prov_sl INTEGER
                )
            """)
            
            # Should return empty dict for non-existent anchor
            bindings = get_dfg_bindings(conn, 999)
            assert bindings == {}
            
            conn.close()
    
    def test_get_framework_hint_unknown(self):
        """Test framework detection with unknown file."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            conn = sqlite3.connect(tmp.name)
            
            # Create minimal schema
            conn.execute("""
                CREATE TABLE files (
                    rel_path TEXT PRIMARY KEY,
                    language TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE edges (
                    edge_id INTEGER PRIMARY KEY,
                    file_rel TEXT,
                    kind TEXT,
                    dst_qname TEXT,
                    note TEXT
                )
            """)
            
            hint = get_framework_hint(conn, "unknown.py")
            assert hint["lang"] == "unknown"
            assert hint["framework"] == "unknown"
            
            conn.close()


class TestContextPacker:
    """Test the main context packer."""
    
    def test_context_packer_init(self):
        """Test context packer initialization."""
        config = Config()
        packer = ContextPacker(config)
        
        assert packer.config == config
        assert packer.max_pack_size == 4096
        assert packer.snippet_window == 10
    
    def test_build_anchor_snapshot(self):
        """Test anchor snapshot building."""
        config = Config()
        packer = ContextPacker(config)
        
        anchor_data = {
            "anchor_id": 1,
            "kind": "http_response",
            "raw_fields": {"method": "GET", "path": "/users"},
            "resolved_fields": {"method": "GET", "path_norm": "/users"},
            "anomalies": [],
            "prov_file": "test.py",
            "prov_sl": 10,
            "prov_el": 12,
            "note": "test anchor"
        }
        
        snapshot = packer._build_anchor_snapshot(anchor_data)
        
        assert snapshot["id"] == 1
        assert snapshot["kind"] == "http_response"
        assert snapshot["raw_fields"]["method"] == "GET"
        assert snapshot["resolved_fields"]["path_norm"] == "/users"
        assert snapshot["provenance"]["file"] == "test.py"
        assert snapshot["provenance"]["start"] == 10
        assert snapshot["provenance"]["end"] == 12
    
    def test_build_file_header(self, tmp_path):
        """Test file header building."""
        config = Config()
        packer = ContextPacker(config)
        
        # Create test file with imports
        test_file = tmp_path / "test.py"
        test_content = """import os
from fastapi import APIRouter
import json

def test_function():
    pass
"""
        test_file.write_text(test_content)
        
        header = packer._build_file_header(str(test_file), "test.py")
        
        assert header["file"] == "test.py"
        assert len(header["imports"]) >= 2
        assert "import os" in header["imports"]
        assert "from fastapi import APIRouter" in header["imports"]
        assert header["import_count"] >= 2
    
    def test_build_span_snippet(self, tmp_path):
        """Test span snippet building."""
        config = Config()
        packer = ContextPacker(config)
        
        test_file = tmp_path / "test.py"
        test_content = """line1
line2
line3
line4
line5
"""
        test_file.write_text(test_content)
        
        snippet = packer._build_span_snippet(str(test_file), 2, 3)
        
        assert len(snippet) > 0
        assert any(">>   2|" in line for line in snippet)  # Highlighted line
        assert any(">>   3|" in line for line in snippet)  # Highlighted line


class TestContextPacksIntegration:
    """Integration tests for context packing."""
    
    def test_build_context_packs_empty_db(self, tmp_path):
        """Test context packing with minimal database."""
        db_path = tmp_path / "test.db"
        
        # Create minimal UCG store
        store = UCGStore(str(db_path))
        
        # Should complete without errors even with no anchors
        stats = build_context_packs(str(db_path))
        
        assert stats["total_anchors"] == 0
        assert stats["successful_packs"] == 0
        assert stats["failed_packs"] == 0
    
    def test_context_bundle_json_serialization(self):
        """Test context bundle JSON serialization."""
        from osigdetector.enrichment.context_packer import ContextBundle
        
        bundle_data = {
            "anchor": {"id": 1, "kind": "test"},
            "file_header": {"imports": ["import os"]},
            "span_snippet": ["1| test line"],
            "neighbor_facts": [],
            "cfg_outcomes": [200],
            "dfg_bindings": {"VAR": "value"},
            "framework_hints": {"lang": "python", "framework": "test"}
        }
        
        bundle = ContextBundle(
            anchor_id=1,
            bundle=bundle_data,
            size_bytes=100
        )
        
        json_str = bundle.to_json()
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["anchor"]["id"] == 1
        assert parsed["dfg_bindings"]["VAR"] == "value"
        assert parsed["cfg_outcomes"] == [200]


def test_context_packing_pipeline_integration():
    """Test that the context packing pipeline can be imported and called."""
    # This is a basic smoke test
    config = Config()
    packer = ContextPacker(config)
    
    # Should be able to instantiate without errors
    assert packer is not None
    assert callable(packer.build_context_packs)
    
    # build_context_packs function should be importable
    assert callable(build_context_packs)
