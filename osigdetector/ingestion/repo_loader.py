# osigdetector/ingestion/repo_loader.py
from __future__ import annotations

import dataclasses
import fnmatch
import json
import os
import posixpath
import time
import zipfile
from dataclasses import dataclass
from hashlib import blake2b
from typing import Dict, Iterator, List, Optional, Tuple

# -----------------------------
# Data models
# -----------------------------

@dataclass(frozen=True)
class FileRecord:
    """
    Immutable description of a single source file discovered in a repo snapshot.

    Fields:
        file_id:       Stable id "rel_path:hash8" (used across the pipeline).
        rel_path:      Path relative to repo root or inside a zip (POSIX style).
        abs_locator:   Absolute locator ("file:///.../path" or "zip://archive.zip!/inner/path").
        language:      Coarse language tag: 'python' | 'typescript' | 'javascript' | 'unknown'
        size_bytes:    File size in bytes.
        mtime:         Last modified time (float timestamp). For zip members, uses zip info date.
        content_hash:  BLAKE2b (16-byte) hex digest of full file contents.
    """
    file_id: str
    rel_path: str
    abs_locator: str
    language: str
    size_bytes: int
    mtime: float
    content_hash: str


@dataclass
class RepoSnapshot:
    """
    The complete result of loading a repository snapshot.

    Attributes:
        files:            All accepted FileRecord entries (after filtering).
        changed_files:    Subset of 'files' that are new or content-changed vs the cache.
        unchanged_files:  Subset of 'files' that match the cache (content unchanged).
        anomalies:        Non-fatal issues encountered (skips, size limits, binary, etc.).
        stats:            Basic counters (scanned, skipped, accepted, changed, unchanged).
        root_norm:        Normalized root string (path or "zip://...").
    """
    files: List[FileRecord]
    changed_files: List[FileRecord]
    unchanged_files: List[FileRecord]
    anomalies: List[Dict[str, str]]
    stats: Dict[str, int]
    root_norm: str


# -----------------------------
# Configuration: language map & exclusions
# -----------------------------

_EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
}

_DEFAULT_EXCLUDES = [
    "**/.git/**",
    "**/.hg/**",
    "**/.svn/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.mypy_cache/**",
    "**/__pycache__/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/out/**",
    "**/*.min.js",
    "**/*.map",
    "**/*.lock",
    "**/*.bin",
    "**/*.wasm",
]

# -----------------------------
# Helpers
# -----------------------------

def _posix_rel(base: str, path: str) -> str:
    rel = os.path.relpath(path, base)
    return rel.replace("\\", "/")

def _hash_bytes(data: bytes) -> str:
    h = blake2b(digest_size=16)
    h.update(data)
    return h.hexdigest()

def _hash_file(path: str, chunk_size: int = 1 << 20) -> Tuple[str, int]:
    h = blake2b(digest_size=16)
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size

def _is_probably_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    textish = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return (len(sample) - textish) / max(1, len(sample)) > 0.30

def _lang_from_ext(rel_path: str) -> str:
    _, ext = os.path.splitext(rel_path)
    return _EXT_TO_LANG.get(ext.lower(), "unknown")

def _matches_any(patterns: List[str], rel_path: str) -> bool:
    return any(fnmatch.fnmatch(rel_path, pat) for pat in patterns)

def _make_file_id(rel_path: str, content_hash: str) -> str:
    return f"{rel_path}:{content_hash[:8]}"

def _now_ts() -> float:
    return time.time()

# -----------------------------
# Main entrypoint
# -----------------------------

def load_repo(
    repo_path: str,
    languages: Optional[List[str]] = None,
    incremental: bool = True,
    cache_path: Optional[str] = ".osigcache.json",
    max_file_bytes: int = 1_000_000,
    include_hidden: bool = False,
    excludes: Optional[List[str]] = None,
) -> RepoSnapshot:
    abs_repo = os.path.abspath(repo_path)
    is_zip = zipfile.is_zipfile(abs_repo)
    root_norm = abs_repo if not is_zip else f"zip://{abs_repo}"

    exclusions = list(_DEFAULT_EXCLUDES)
    if excludes:
        exclusions.extend(excludes)

    prior: Dict[str, Dict[str, object]] = {}
    if incremental and cache_path and os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                prior = json.load(f)
        except Exception:
            prior = {}

    files: List[FileRecord] = []
    anomalies: List[Dict[str, str]] = []
    scanned = accepted = skipped = 0

    if is_zip:
        for rec in _iter_zip(abs_repo, exclusions, include_hidden, max_file_bytes, anomalies):
            scanned += 1
            if _accept_language(rec, languages):
                files.append(rec)
                accepted += 1
            else:
                skipped += 1
    else:
        for rec in _iter_dir(abs_repo, exclusions, include_hidden, max_file_bytes, anomalies):
            scanned += 1
            if _accept_language(rec, languages):
                files.append(rec)
                accepted += 1
            else:
                skipped += 1

    changed, unchanged = _split_changed(files, prior)

    if incremental and cache_path:
        _write_cache(cache_path, files)

    stats = dict(scanned=scanned, accepted=accepted, skipped=skipped,
                 changed=len(changed), unchanged=len(unchanged))

    return RepoSnapshot(
        files=files,
        changed_files=changed,
        unchanged_files=unchanged,
        anomalies=anomalies,
        stats=stats,
        root_norm=root_norm,
    )

# -----------------------------
# Iterators
# -----------------------------

def _iter_dir(
    abs_root: str,
    excludes: List[str],
    include_hidden: bool,
    max_file_bytes: int,
    anomalies: List[Dict[str, str]],
) -> Iterator[FileRecord]:
    for dirpath, dirnames, filenames in os.walk(abs_root):
        if not include_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

        for fname in filenames:
            if not include_hidden and fname.startswith("."):
                continue

            abspath = os.path.join(dirpath, fname)
            rel = _posix_rel(abs_root, abspath)

            if _matches_any(excludes, rel):
                continue

            try:
                size = os.path.getsize(abspath)
            except OSError:
                anomalies.append({"rel_path": rel, "reason": "stat_failed"})
                continue

            if size > max_file_bytes:
                anomalies.append({"rel_path": rel, "reason": "too_large", "size": str(size)})
                continue

            try:
                with open(abspath, "rb") as f:
                    prefix = f.read(4096)
            except OSError:
                anomalies.append({"rel_path": rel, "reason": "read_failed"})
                continue

            if _is_probably_binary(prefix):
                anomalies.append({"rel_path": rel, "reason": "binary_like"})
                continue

            try:
                digest, real_size = _hash_file(abspath)
            except Exception:
                anomalies.append({"rel_path": rel, "reason": "hash_failed"})
                continue

            try:
                mtime = os.path.getmtime(abspath)
            except OSError:
                mtime = _now_ts()

            lang = _lang_from_ext(rel)
            file_id = _make_file_id(rel, digest)
            locator = f"file://{abspath}"

            yield FileRecord(
                file_id=file_id,
                rel_path=rel,
                abs_locator=locator,
                language=lang,
                size_bytes=real_size,
                mtime=mtime,
                content_hash=digest,
            )

def _iter_zip(
    zip_path: str,
    excludes: List[str],
    include_hidden: bool,
    max_file_bytes: int,
    anomalies: List[Dict[str, str]],
) -> Iterator[FileRecord]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        for zinfo in zf.infolist():
            if zinfo.is_dir():
                continue

            rel_posix = zinfo.filename.replace("\\", "/")
            base = posixpath.basename(rel_posix)
            if not include_hidden and (base.startswith(".") or any(part.startswith(".") for part in rel_posix.split("/"))):
                continue

            if _matches_any(excludes, rel_posix):
                continue

            size = zinfo.file_size
            if size > max_file_bytes:
                anomalies.append({"rel_path": rel_posix, "reason": "too_large", "size": str(size), "where": "zip"})
                continue

            try:
                with zf.open(zinfo, "r") as f:
                    prefix = f.read(4096)
            except Exception:
                anomalies.append({"rel_path": rel_posix, "reason": "zip_read_failed"})
                continue

            if _is_probably_binary(prefix):
                anomalies.append({"rel_path": rel_posix, "reason": "binary_like"})
                continue

            try:
                with zf.open(zinfo, "r") as f:
                    data = f.read()
            except Exception:
                anomalies.append({"rel_path": rel_posix, "reason": "zip_read_failed_full"})
                continue

            digest = _hash_bytes(data)
            try:
                y, m, d, H, M, S = zinfo.date_time
                mtime = time.mktime((y, m, d, H, M, S, 0, 0, -1))
            except Exception:
                mtime = _now_ts()

            lang = _lang_from_ext(rel_posix)
            file_id = _make_file_id(rel_posix, digest)
            locator = f"zip://{zip_path}!/{rel_posix}"

            yield FileRecord(
                file_id=file_id,
                rel_path=rel_posix,
                abs_locator=locator,
                language=lang,
                size_bytes=size,
                mtime=mtime,
                content_hash=digest,
            )

# -----------------------------
# Incremental utilities
# -----------------------------

def _accept_language(rec: FileRecord, allowlist: Optional[List[str]]) -> bool:
    if not allowlist:
        return True
    return rec.language in set(allowlist)

def _split_changed(
    files: List[FileRecord],
    prior: Dict[str, Dict[str, object]],
) -> Tuple[List[FileRecord], List[FileRecord]]:
    changed, unchanged = [], []
    for rec in files:
        prior_entry = prior.get(rec.rel_path)
        if not prior_entry:
            changed.append(rec)
            continue
        if prior_entry.get("content_hash") != rec.content_hash:
            changed.append(rec)
        else:
            unchanged.append(rec)
    return changed, unchanged

def _write_cache(cache_path: str, files: List[FileRecord]) -> None:
    out = {}
    for rec in files:
        out[rec.rel_path] = {
            "content_hash": rec.content_hash,
            "size_bytes": rec.size_bytes,
            "mtime": rec.mtime,
            "language": rec.language,
            "file_id": rec.file_id,
            "abs_locator": rec.abs_locator,
        }
    tmp = f"{cache_path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    os.replace(tmp, cache_path)
