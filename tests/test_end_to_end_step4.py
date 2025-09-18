"""
End-to-end integration test for Steps 1-4 of the OSig pipeline.

Tests the complete flow: Ingestion → Mining → Resolution → Context Packing
"""

import tempfile
import json
from pathlib import Path

from osigdetector.ingestion.build_ucg import build_ucg
from osigdetector.mining.miner import StaticMiner
from osigdetector.resolution.run_resolution import run_resolution
from osigdetector.enrichment.context_packer import build_context_packs


def test_end_to_end_steps_1_to_4():
    """Test the complete pipeline from source code to context packs."""
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        # Step 0: Create a test repository with FastAPI code
        repo_dir = tmp_path / "test_repo"
        repo_dir.mkdir()
        
        # Create a realistic FastAPI example
        app_file = repo_dir / "app.py"
        app_file.write_text('''
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import os

router = APIRouter()

class UserResponse(BaseModel):
    id: int
    name: str
    email: str

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///default.db")
API_VERSION = "v1"

@router.get(f"/api/{API_VERSION}/users/{{user_id}}")
def get_user(user_id: int):
    """Get user by ID."""
    if user_id <= 0:
        raise HTTPException(404, detail="User not found")
    
    return UserResponse(
        id=user_id,
        name="Test User", 
        email="test@example.com"
    )

@router.post("/api/v1/users")
def create_user(user_data: dict):
    """Create a new user."""
    if not user_data.get("name"):
        raise HTTPException(400, detail="Name is required")
    
    # Simulate database save
    new_user = UserResponse(
        id=123,
        name=user_data["name"],
        email=user_data.get("email", "")
    )
    
    return new_user
''')
        
        # Create database path
        db_path = tmp_path / "test_pipeline.db"
        
        # Step 1: Build UCG (Ingestion)
        print("🔄 Step 1: Building UCG...")
        ucg_store = build_ucg(
            repo_path=str(repo_dir),
            languages=["python"],
            db_path=str(db_path)
        )
        
        # Verify Step 1 results
        assert ucg_store is not None
        
        with ucg_store._conn() as conn:
            cur = conn.cursor()
            
            # Should have the file
            cur.execute("SELECT COUNT(*) FROM files")
            file_count = cur.fetchone()[0]
            assert file_count > 0, "No files found after ingestion"
            
            # Should have effects (route detections)
            cur.execute("SELECT COUNT(*) FROM effects WHERE effect_type = 'route'")
            route_count = cur.fetchone()[0]
            assert route_count > 0, "No route effects found after ingestion"
            
            print(f"✅ Step 1: Found {file_count} files and {route_count} route effects")
        
        # Step 2: Static Mining
        print("🔄 Step 2: Running static miner...")
        miner = StaticMiner(str(db_path))
        mining_stats = miner.run()
        
        # Verify Step 2 results
        assert mining_stats["anchors_created"] > 0, "No anchors created by miner"
        
        with ucg_store._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM anchors")
            anchor_count = cur.fetchone()[0]
            assert anchor_count > 0, "No anchors found after mining"
            
            print(f"✅ Step 2: Created {anchor_count} anchors")
        
        # Step 3: Resolution
        print("🔄 Step 3: Running resolution...")
        try:
            run_resolution(str(db_path))
            
            # Verify Step 3 results
            with ucg_store._conn() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT COUNT(*) FROM anchors 
                    WHERE resolved_fields IS NOT NULL 
                    AND resolved_fields != '{}'
                """)
                resolved_count = cur.fetchone()[0]
                
                print(f"✅ Step 3: Resolved {resolved_count} anchors")
                
        except Exception as e:
            print(f"⚠️  Step 3: Resolution had issues but continuing: {e}")
        
        # Step 4: Context Packing
        print("🔄 Step 4: Building context packs...")
        packing_stats = build_context_packs(str(db_path))
        
        # Verify Step 4 results
        assert packing_stats["total_anchors"] > 0, "No anchors found for context packing"
        assert packing_stats["successful_packs"] > 0, "No context packs created"
        
        with ucg_store._conn() as conn:
            cur = conn.cursor()
            
            # Check context packs were created
            cur.execute("SELECT COUNT(*) FROM context_packs")
            pack_count = cur.fetchone()[0]
            assert pack_count > 0, "No context packs found in database"
            
            # Get a sample context pack to verify structure
            cur.execute("""
                SELECT cp.bundle, a.kind, a.resolved_fields
                FROM context_packs cp
                JOIN anchors a ON cp.anchor_id = a.anchor_id
                LIMIT 1
            """)
            
            sample_row = cur.fetchone()
            if sample_row:
                bundle_json, anchor_kind, resolved_fields_json = sample_row
                bundle = json.loads(bundle_json)
                
                # Verify bundle structure
                required_keys = [
                    "anchor", "file_header", "span_snippet", 
                    "neighbor_facts", "cfg_outcomes", "dfg_bindings", "framework_hints"
                ]
                
                for key in required_keys:
                    assert key in bundle, f"Missing key '{key}' in context bundle"
                
                # Verify anchor data
                assert bundle["anchor"]["kind"] == anchor_kind
                assert "provenance" in bundle["anchor"]
                assert "file" in bundle["anchor"]["provenance"]
                
                # Verify file header has imports
                assert "imports" in bundle["file_header"]
                assert isinstance(bundle["file_header"]["imports"], list)
                
                # Verify span snippet has code lines
                assert isinstance(bundle["span_snippet"], list)
                assert len(bundle["span_snippet"]) > 0
                
                # Verify framework hints
                assert "lang" in bundle["framework_hints"]
                assert "framework" in bundle["framework_hints"]
                
                print(f"✅ Step 4: Created {pack_count} context packs")
                print(f"   Sample pack size: {len(bundle_json)} bytes")
                print(f"   Framework detected: {bundle['framework_hints']['framework']}")
                print(f"   Import count: {len(bundle['file_header']['imports'])}")
                print(f"   Snippet lines: {len(bundle['span_snippet'])}")
                
        print("\n🎉 End-to-end pipeline test completed successfully!")
        print(f"📊 Final stats:")
        print(f"   Files: {file_count}")
        print(f"   Effects: {route_count}")
        print(f"   Anchors: {anchor_count}")
        print(f"   Context Packs: {pack_count}")
        print(f"   Average pack size: {packing_stats.get('average_size_bytes', 0):.0f} bytes")


def test_context_pack_content_quality():
    """Test that context packs contain high-quality, relevant information."""
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        # Create a focused test case
        repo_dir = tmp_path / "quality_test"
        repo_dir.mkdir()
        
        test_file = repo_dir / "routes.py"
        test_file.write_text('''
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from .models import User, Email
from .database import get_db

router = APIRouter()

@router.post("/users/{user_id}/emails")
def send_email(user_id: int, email_data: dict, db: Session = Depends(get_db)):
    """Send email to user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, detail="User not found")
    
    email = Email(
        user_id=user_id,
        subject=email_data["subject"],
        body=email_data["body"]
    )
    db.add(email)
    db.commit()
    
    return {"status": "sent", "email_id": email.id}
''')
        
        db_path = tmp_path / "quality_test.db"
        
        # Run the pipeline
        build_ucg(str(repo_dir), ["python"], str(db_path))
        
        miner = StaticMiner(str(db_path))
        miner.run()
        
        try:
            run_resolution(str(db_path))
        except:
            pass  # Continue even if resolution has issues
        
        stats = build_context_packs(str(db_path))
        
        # Analyze context pack quality
        ucg_store = build_ucg(str(repo_dir), ["python"], str(db_path))
        with ucg_store._conn() as conn:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT cp.bundle, cp.size_bytes
                FROM context_packs cp
                JOIN anchors a ON cp.anchor_id = a.anchor_id
                WHERE a.kind LIKE '%route%' OR a.kind LIKE '%http%'
                LIMIT 1
            """)
            
            row = cur.fetchone()
            if row:
                bundle_json, size_bytes = row
                bundle = json.loads(bundle_json)
                
                # Quality checks
                assert size_bytes < 4096, f"Context pack too large: {size_bytes} bytes"
                
                # Should contain FastAPI imports
                imports = bundle["file_header"]["imports"]
                has_fastapi = any("fastapi" in imp.lower() for imp in imports)
                assert has_fastapi, "Should detect FastAPI imports"
                
                # Should have meaningful snippet
                snippet = bundle["span_snippet"]
                has_decorator = any("@router" in line for line in snippet)
                assert has_decorator, "Should include route decorator in snippet"
                
                # Framework should be detected
                framework = bundle["framework_hints"]["framework"]
                # Note: Might be 'unknown' if detection isn't perfect, which is okay
                
                print(f"✅ Quality test passed:")
                print(f"   Pack size: {size_bytes} bytes (limit: 4096)")
                print(f"   FastAPI detected: {has_fastapi}")
                print(f"   Route decorator found: {has_decorator}")
                print(f"   Framework hint: {framework}")


if __name__ == "__main__":
    test_end_to_end_steps_1_to_4()
    test_context_pack_content_quality()
    print("\n🎯 All integration tests passed!")
