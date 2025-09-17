# osigdetector/ingestion/parser_registry.py
from __future__ import annotations

import ast as py_ast
import io
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .repo_loader import FileRecord

# Optional Tree-sitter import (graceful degradation if missing)
_TS_AVAILABLE = False
try:
    # Two common ways people install TS grammars in Python:
    # 1) tree_sitter_languages (prebuilt grammars)
    # 2) tree_sitter + custom language bundles
    from tree_sitter import Language, Parser  # type: ignore
    try:
        # If tree_sitter_languages is installed, we can load grammars by name
        from tree_sitter_languages import get_language as ts_get_language  # type: ignore
        _TS_AVAILABLE = True
        _TS_BACKEND = "tree_sitter_languages"
    except Exception:
        # Fallback: users can build their own .so Language bundle and set TS_LANGUAGE_BUNDLE path
        _TS_BUNDLE = os.environ.get("TS_LANGUAGE_BUNDLE")  # e.g., ".../languages.so"
        if _TS_BUNDLE and os.path.exists(_TS_BUNDLE):
            _TS_LANG_BUNDLE = Language(_TS_BUNDLE, "javascript")  # probe
            _TS_AVAILABLE = True
            _TS_BACKEND = "bundle"
        else:
            _TS_AVAILABLE = False
            _TS_BACKEND = "none"
except Exception:
    _TS_AVAILABLE = False
    _TS_BACKEND = "none"


# =============================================================================
# Uniform AST surface
# =============================================================================

@dataclass
class GenericNode:
    """
    Language-agnostic AST node used by downstream steps.

    Fields:
        kind:         Short type name ("Module", "FunctionDef", "class_declaration", ...)
        start_line:   1-based (inclusive)
        start_col:    0-based (inclusive)
        end_line:     1-based (inclusive)
        end_col:      0-based (exclusive)
        start_byte:   -1 if unknown
        end_byte:     -1 if unknown
        children:     Child nodes (ordered)
    """
    kind: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    start_byte: int = -1
    end_byte: int = -1
    children: List["GenericNode"] = field(default_factory=list)


@dataclass
class GenericAST:
    """
    Container for a parsed file.
    """
    language: str                 # "python" | "typescript" | "javascript" | "unknown"
    rel_path: str
    root: GenericNode
    anomalies: List[Dict[str, str]] = field(default_factory=list)


# =============================================================================
# File content loading from locator
# =============================================================================

def _read_bytes_from_locator(abs_locator: str) -> bytes:
    """
    Read file content from a 'file://...' or 'zip://...!/inner/path' locator.
    """
    if abs_locator.startswith("file://"):
        path = abs_locator[len("file://") :]
        with open(path, "rb") as f:
            return f.read()

    if abs_locator.startswith("zip://"):
        # Format: zip://<abs_zip_path>!/<inner/posix/path>
        rest = abs_locator[len("zip://") :]
        if "!/" not in rest:
            raise ValueError(f"Invalid zip locator: {abs_locator}")
        zip_path, inner = rest.split("!/", 1)
        with zipfile.ZipFile(zip_path, "r") as zf:
            with zf.open(inner, "r") as f:
                return f.read()

    raise ValueError(f"Unsupported locator scheme: {abs_locator}")


# =============================================================================
# Parser registry
# =============================================================================

class BaseParser:
    """Abstract parser API."""
    def parse(self, fr: FileRecord) -> GenericAST:
        raise NotImplementedError


# -------------------------
# Python parser (CPython ast)
# -------------------------

class PythonParser(BaseParser):
    """
    Uses built-in 'ast' (and node position attrs) to build a GenericAST.
    Provides line/column provenance; byte offsets remain -1 (unknown).
    """

    def parse(self, fr: FileRecord) -> GenericAST:
        anomalies: List[Dict[str, str]] = []
        try:
            src_bytes = _read_bytes_from_locator(fr.abs_locator)
        except Exception as e:
            return GenericAST(
                language=fr.language,
                rel_path=fr.rel_path,
                root=GenericNode("Error", 1, 0, 1, 0),
                anomalies=[{"reason": "IO_ERROR", "detail": str(e)}],
            )

        try:
            src_text = src_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            anomalies.append({"reason": "DECODE_ERROR", "detail": str(e)})
            src_text = src_bytes.decode("utf-8", errors="ignore")

        try:
            tree = py_ast.parse(src_text, filename=fr.rel_path, mode="exec")
        except SyntaxError as e:
            root = GenericNode(
                kind="SyntaxError",
                start_line=getattr(e, "lineno", 1) or 1,
                start_col=getattr(e, "offset", 0) or 0,
                end_line=getattr(e, "lineno", 1) or 1,
                end_col=(getattr(e, "offset", 0) or 0) + 1,
            )
            anomalies.append({"reason": "SYNTAX_ERROR", "detail": str(e)})
            return GenericAST(language=fr.language, rel_path=fr.rel_path, root=root, anomalies=anomalies)

        # Walk CPython AST and wrap into GenericNode
        root = self._wrap_py_node(tree)
        return GenericAST(language=fr.language, rel_path=fr.rel_path, root=root, anomalies=anomalies)

    # --- helpers ---

    def _wrap_py_node(self, node: py_ast.AST) -> GenericNode:
        kind = type(node).__name__
        # Position info (Python 3.8+)
        sl = getattr(node, "lineno", 1) or 1
        sc = getattr(node, "col_offset", 0) or 0
        el = getattr(node, "end_lineno", sl) or sl
        ec = getattr(node, "end_col_offset", sc) or sc

        children: List[GenericNode] = []
        for child in py_ast.iter_child_nodes(node):
            children.append(self._wrap_py_node(child))

        return GenericNode(kind=kind, start_line=sl, start_col=sc, end_line=el, end_col=ec, children=children)


# -------------------------
# Tree-sitter parser for JS/TS (optional)
# -------------------------

class TreeSitterParser(BaseParser):
    """
    Tree-sitter parser used for 'javascript' and 'typescript' when available.
    Provides byte-level and line/column provenance.
    """

    def __init__(self, lang_name: str):
        self.lang_name = lang_name
        self._parser = None
        self._language = None
        self._init_ts()

    def _init_ts(self) -> None:
        if not _TS_AVAILABLE:
            return
        try:
            if _TS_BACKEND == "tree_sitter_languages":
                self._language = ts_get_language(self.lang_name)  # type: ignore
                self._parser = Parser()  # type: ignore
                self._parser.set_language(self._language)
            elif _TS_BACKEND == "bundle":
                # Users must bundle languages themselves; we try to load by name
                # NOTE: Without a mapping, this is illustrative; most users rely on tree_sitter_languages.
                self._parser = Parser()  # type: ignore
                # self._parser.set_language(Language(os.environ["TS_LANGUAGE_BUNDLE"], self.lang_name))
                # For safety, leave unconfigured if we can't set a language.
                pass
        except Exception:
            self._parser = None
            self._language = None

    def parse(self, fr: FileRecord) -> GenericAST:
        anomalies: List[Dict[str, str]] = []
        try:
            src_bytes = _read_bytes_from_locator(fr.abs_locator)
        except Exception as e:
            return GenericAST(
                language=fr.language,
                rel_path=fr.rel_path,
                root=GenericNode("Error", 1, 0, 1, 0),
                anomalies=[{"reason": "IO_ERROR", "detail": str(e)}],
            )

        if not self._parser:
            # Fallback
            anomalies.append({"reason": "PARSER_UNAVAILABLE", "detail": "tree-sitter not available"})
            return _heuristic_fallback(fr, src_bytes, anomalies)

        try:
            tree = self._parser.parse(src_bytes)  # type: ignore
        except Exception as e:
            anomalies.append({"reason": "PARSE_ERROR", "detail": str(e)})
            return _heuristic_fallback(fr, src_bytes, anomalies)

        # Convert TS tree to GenericNode
        root = self._wrap_ts_node(tree.root_node)
        return GenericAST(language=fr.language, rel_path=fr.rel_path, root=root, anomalies=anomalies)

    def _wrap_ts_node(self, node) -> GenericNode:  # node: tree_sitter.Node
        kind = node.type
        sl, sc = node.start_point  # (row, col), 0-based rows
        el, ec = node.end_point
        # Convert to 1-based lines
        g = GenericNode(
            kind=kind,
            start_line=sl + 1,
            start_col=sc,
            end_line=el + 1,
            end_col=ec,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            children=[],
        )
        for i in range(node.child_count):
            child = node.child(i)
            if child is None:
                continue
            g.children.append(self._wrap_ts_node(child))
        return g


# -------------------------
# Heuristic fallback for JS/TS when parsers are missing
# -------------------------

_FUNC_RE = re.compile(r"(?:function\s+([A-Za-z0-9_]+)|([A-Za-z0-9_]+)\s*=\s*\([^)]*\)\s*=>)", re.MULTILINE)
_CLASS_RE = re.compile(r"class\s+([A-Za-z0-9_]+)", re.MULTILINE)

def _heuristic_fallback(fr: FileRecord, src_bytes: bytes, anomalies: List[Dict[str, str]]) -> GenericAST:
    """
    Extremely tolerant parser: finds top-level class/function declarations via regex,
    emits a shallow tree so downstream steps can still proceed (with lower fidelity).
    """
    try:
        text = src_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = src_bytes.decode("latin-1", errors="replace")

    root = GenericNode(kind="Module", start_line=1, start_col=0, end_line=max(1, text.count("\n") + 1), end_col=0)
    lines = text.splitlines()

    def mk_node(kind: str, name: str, line_idx: int) -> GenericNode:
        # 1-based line; no byte info
        ln = line_idx + 1
        col = 0
        return GenericNode(kind=f"{kind}({name})", start_line=ln, start_col=col, end_line=ln, end_col=col)

    for m in _CLASS_RE.finditer(text):
        name = m.group(1) or "Anonymous"
        start = text.rfind("\n", 0, m.start()) + 1
        line_idx = text[:m.start()].count("\n")
        root.children.append(mk_node("ClassDecl", name, line_idx))

    for m in _FUNC_RE.finditer(text):
        name = m.group(1) or m.group(2) or "anonymous"
        line_idx = text[:m.start()].count("\n")
        root.children.append(mk_node("FunctionDecl", name, line_idx))

    anomalies.append({"reason": "HEURISTIC_AST", "detail": "Used regex-based fallback"})
    return GenericAST(language=fr.language, rel_path=fr.rel_path, root=root, anomalies=anomalies)


# =============================================================================
# Public registry API
# =============================================================================

class ParserRegistry:
    """
    Chooses a parser by language and exposes a simple batch API.
    """

    def __init__(self) -> None:
        self._py = PythonParser()
        # Create TS parsers on demand for the two JS-family tags
        self._ts_parsers: Dict[str, TreeSitterParser] = {}

    def _for_language(self, language: str) -> BaseParser:
        if language == "python":
            return self._py
        if language in ("javascript", "typescript"):
            if language not in self._ts_parsers:
                self._ts_parsers[language] = TreeSitterParser(
                    "javascript" if language == "javascript" else "typescript"
                )
            return self._ts_parsers[language]
        # Unknowns will use a permissive JS/TS heuristic as last resort
        return HeuristicAnyParser()

    def parse_file(self, fr: FileRecord) -> GenericAST:
        parser = self._for_language(fr.language)
        try:
            return parser.parse(fr)
        except Exception as e:
            # Last-resort guard: never blow up Step 1
            return GenericAST(
                language=fr.language,
                rel_path=fr.rel_path,
                root=GenericNode("Error", 1, 0, 1, 0),
                anomalies=[{"reason": "UNCAUGHT_PARSE_EXCEPTION", "detail": str(e)}],
            )

    def parse_files(self, files: Iterable[FileRecord]) -> List[GenericAST]:
        return [self.parse_file(fr) for fr in files]


class HeuristicAnyParser(BaseParser):
    """
    Final fallback for unknown languages: tries a minimal structure so downstream
    modules have *something* to work with (e.g., a Module node).
    """

    def parse(self, fr: FileRecord) -> GenericAST:
        anomalies: List[Dict[str, str]] = []
        try:
            src_bytes = _read_bytes_from_locator(fr.abs_locator)
        except Exception as e:
            return GenericAST(
                language=fr.language,
                rel_path=fr.rel_path,
                root=GenericNode("Error", 1, 0, 1, 0),
                anomalies=[{"reason": "IO_ERROR", "detail": str(e)}],
            )
        try:
            text = src_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = src_bytes.decode("latin-1", errors="replace")

        end_line = max(1, text.count("\n") + 1)
        root = GenericNode(kind="Module", start_line=1, start_col=0, end_line=end_line, end_col=0)
        anomalies.append({"reason": "PARSER_UNAVAILABLE", "detail": "unknown language; emitted trivial Module"})
        return GenericAST(language=fr.language, rel_path=fr.rel_path, root=root, anomalies=anomalies)
