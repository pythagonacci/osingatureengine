from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file_chunked(path: Path, chunk_size: int = 1_048_576) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
