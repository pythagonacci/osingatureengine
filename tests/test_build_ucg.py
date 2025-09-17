import os
import tempfile

import pytest

from osigdetector.ingestion.build_ucg import build_ucg


def test_build_ucg_on_small_python_file(tmp_path):
    # Make a tiny Python repo
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    f = repo_dir / "app.py"
    f.write_text(
        """
from fastapi import FastAPI

app = FastAPI()

@app.get("/ping")
def ping():
    return {"pong": True}
"""
    )

    # Run build_ucg
    db_path = tmp_path / "ucg.sqlite"
    store = build_ucg(str(repo_dir), languages=["python"], db_path=str(db_path))

    # Basic assertions
    file_row = store.get_file("app.py")
    assert file_row is not None
    assert file_row["language"] == "python"

    funcs = store.list_functions("app.py")
    assert len(funcs) > 0  # At least one function should be detected

    effects = store.list_effects("route")
    assert any(e["framework_hint"] == "fastapi" for e in effects)
