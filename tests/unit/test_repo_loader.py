import tempfile
from pathlib import Path

from osigdetector.step1_ucg.repo_loader.loader import load_repo


def create_temp_file(ext: str, content: str = "print('hello')") -> Path:
    tmp_dir = tempfile.mkdtemp()
    file_path = Path(tmp_dir) / f"test{ext}"
    with open(file_path, "w") as f:
        f.write(content)
    return file_path


def test_detect_python_file():
    file_path = create_temp_file(".py")
    manifest = load_repo(str(file_path.parent), db_path=":memory:")
    entry = next(f for f in manifest if f["path"] == str(file_path))
    assert entry["language"] == "python"
    assert entry["status"] == "ok"
    assert entry["hash"] != ""


def test_detect_js_file():
    file_path = create_temp_file(".js", "console.log('hi');")
    manifest = load_repo(str(file_path.parent), db_path=":memory:")
    entry = next(f for f in manifest if f["path"] == str(file_path))
    assert entry["language"] == "javascript"


def test_detect_unsupported_file():
    file_path = create_temp_file(".cpp", "#include <iostream>")
    manifest = load_repo(str(file_path.parent), db_path=":memory:")
    entry = next(f for f in manifest if f["path"] == str(file_path))
    assert entry["status"] == "anomaly"
    assert entry["anomaly_type"] == "UNSUPPORTED_LANG"


def test_ignore_node_modules():
    tmp_dir = tempfile.mkdtemp()
    ignore_dir = Path(tmp_dir) / "node_modules"
    ignore_dir.mkdir()
    file_path = ignore_dir / "ignoreme.py"
    file_path.write_text("print('hi')")

    manifest = load_repo(tmp_dir, db_path=":memory:")
    entry = next(f for f in manifest if "node_modules" in f["path"])
    assert entry["status"] == "anomaly"
    assert entry["anomaly_type"] == "IGNORED"
