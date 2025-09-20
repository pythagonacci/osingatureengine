from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

class Severity(Enum):
    INFO = "INFO"; WARN = "WARN"; ERROR = "ERROR"

class AnomalyType(Enum):
    SYMLINK_TRAVERSED = auto()
    SYMLINK_OUT_OF_ROOT = auto()
    GENERATED_CODE = auto()
    MINIFIED_JS = auto()
    VENDORED_CODE = auto()
    FILE_TOO_LARGE = auto()
    PERMISSION_DENIED = auto()

class Language(Enum):
    PYTHON = "python"; JAVASCRIPT = "javascript"; TYPESCRIPT = "typescript"

@dataclass
class Anomaly:
    path: str
    blob_sha256: Optional[str]
    typ: AnomalyType
    severity: Severity
    reason_detail: str

@dataclass
class DiscoveredFile:
    abs_path: str
    rel_path: str
    language: Language
    blob_sha256: str
    size_bytes: int
    is_symlink: bool
