import hashlib
import uuid
from pathlib import Path
from typing import Dict, List
import datetime

import ray
import duckdb


# --- Supported languages ---
SUPPORTED_LANGS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
}

# --- Default ignore dirs ---
DEFAULT_IGNORES = {"node_modules", "__pycache__", ".git", ".hg", ".svn"}


# --- Anomaly taxonomy ---
ANOMALY_UNSUPPORTED_LANG = "UNSUPPORTED_LANG"
ANOMALY_FILE_READ_ERROR = "FILE_READ_ERROR"
ANOMALY_IGNORED = "IGNORED"
ANOMALY_UNKNOWN = "UNKNOWN"


def sha256sum(file_path: Path) -> str:
    """Compute SHA256 checksum of a file safely in chunks."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""  # leave blank if file unreadable


@ray.remote
def process_file(file_path: str) -> Dict:
    """
    Process a single file into a manifest entry with provenance and anomaly handling.
    """
    path_obj = Path(file_path)
    ext = path_obj.suffix.lower()
    timestamp = datetime.datetime.utcnow().isoformat()

    # Handle ignored dirs
    if any(part in DEFAULT_IGNORES for part in path_obj.parts):
        return {
            "id": str(uuid.uuid4()),
            "path": str(path_obj),
            "language": None,
            "size": 0,
            "hash": "",
            "status": "anomaly",
            "anomaly_type": ANOMALY_IGNORED,
            "reason": f"Ignored directory ({[p for p in path_obj.parts if p in DEFAULT_IGNORES]})",
            "timestamp": timestamp,
        }

    language = SUPPORTED_LANGS.get(ext)

    try:
        size = path_obj.stat().st_size
        file_hash = sha256sum(path_obj)
    except Exception as e:
        return {
            "id": str(uuid.uuid4()),
            "path": str(path_obj),
            "language": None,
            "size": 0,
            "hash": "",
            "status": "anomaly",
            "anomaly_type": ANOMALY_FILE_READ_ERROR,
            "reason": str(e),
            "timestamp": timestamp,
        }

    if not language:
        return {
            "id": str(uuid.uuid4()),
            "path": str(path_obj),
            "language": "unsupported",
            "size": size,
            "hash": file_hash,
            "status": "anomaly",
            "anomaly_type": ANOMALY_UNSUPPORTED_LANG,
            "reason": f"Extension {ext} not supported",
            "timestamp": timestamp,
        }

    return {
        "id": str(uuid.uuid4()),
        "path": str(path_obj),
        "language": language,
        "size": size,
        "hash": file_hash,
        "status": "ok",
        "anomaly_type": None,
        "reason": None,
        "timestamp": timestamp,
    }


def load_repo(repo_path: str, db_path: str = "ucg_repo_manifest.duckdb") -> List[Dict]:
    """
    Walk a repo directory, process files in parallel with Ray,
    return manifest, and persist results to DuckDB.
    """
    repo_root = Path(repo_path).resolve()
    if not repo_root.exists():
        raise FileNotFoundError(f"Repo path {repo_root} does not exist")

    all_files = [str(p) for p in repo_root.rglob("*") if p.is_file()]

    if not ray.is_initialized():
        ray.init(ignore_reinit_error=True)

    futures = [process_file.remote(path) for path in all_files]
    manifest = ray.get(futures)

    # --- Telemetry ---
    total_files = len(manifest)
    ok_files = sum(1 for f in manifest if f["status"] == "ok")
    anomalies = total_files - ok_files
    print(f"[RepoLoader] Processed {total_files} files: {ok_files} ok, {anomalies} anomalies")

    # --- Persist to DuckDB ---
    con = duckdb.connect(db_path)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS repo_manifest (
            id TEXT,
            path TEXT,
            language TEXT,
            size BIGINT,
            hash TEXT,
            status TEXT,
            anomaly_type TEXT,
            reason TEXT,
            timestamp TEXT
        )
        """
    )
    con.execute("INSERT INTO repo_manifest VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", manifest)
    con.close()

    return manifest
