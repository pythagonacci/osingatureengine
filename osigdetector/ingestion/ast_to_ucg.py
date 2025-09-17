# osigdetector/ingestion/ast_to_ucg.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .repo_loader import FileRecord
from .parser_registry import GenericAST, GenericNode
from .provenance import Provenance, from_node, from_regex

# =============================================================================
# UCG data model (in-memory batch). Persist later via ucg_store.py
# =============================================================================


@dataclass
class UCGFile:
    file_id_hint: str             # e.g., rel_path:hash8 from FileRecord.file_id (if available)
    rel_path: str
    language: str
    size_bytes: int
    mtime: float
    content_hash: str
    abs_locator: str


@dataclass
class UCGSymbol:
    symbol_id: int
    file_rel: str
    name: str
    kind: str                     # "var"|"import"|"export"|"func"|"class"|"unknown"
    scope_qname: str              # enclosing scope_qname ("" at module)
    prov: Provenance
    anomalies: List[str] = field(default_factory=list)


@dataclass
class UCGFunction:
    func_id: int
    file_rel: str
    qname: str                    # module-qualified name, e.g., "pkg.mod:Class.method" or "pkg.mod:function"
    name: str
    scope_qname: str              # class or module where defined
    prov: Provenance
    anomalies: List[str] = field(default_factory=list)


@dataclass
class UCGClass:
    class_id: int
    file_rel: str
    qname: str                    # e.g., "pkg.mod:Class"
    name: str
    scope_qname: str              # module or enclosing class
    prov: Provenance
    anomalies: List[str] = field(default_factory=list)


@dataclass
class UCGEdge:
    edge_id: int
    file_rel: str
    src_qname: str                # source entity (function/class/module "")
    dst_qname: str                # target symbol qname-ish (best-effort)
    kind: str                     # "defines"|"calls"|"imports"|"exports"
    prov: Provenance
    note: str = ""


@dataclass
class UCGBatch:
    files: List[UCGFile] = field(default_factory=list)
    symbols: List[UCGSymbol] = field(default_factory=list)
    functions: List[UCGFunction] = field(default_factory=list)
    classes: List[UCGClass] = field(default_factory=list)
    edges: List[UCGEdge] = field(default_factory=list)
    anomalies: List[Dict[str, str]] = field(default_factory=list)

    # quick lookup maps (filled by builder)
    _fn_by_qname: Dict[str, UCGFunction] = field(default_factory=dict, repr=False)
    _cls_by_qname: Dict[str, UCGClass] = field(default_factory=dict, repr=False)
    _sym_by_key: Dict[Tuple[str, str, str], UCGSymbol] = field(default_factory=dict, repr=False)  # (file_rel, scope_qname, name)


# =============================================================================
# Builder
# =============================================================================

class ASTtoUCGBuilder:
    """
    Lifts GenericAST trees into a minimal, language-agnostic UCG:
      - files (one per rel_path, using FileRecord metadata)
      - functions / classes (with qualified names)
      - symbols (imports/vars) scoped by enclosing class/function/module
      - edges (defines, imports, calls) with provenance

    Design principles:
      - Be conservative: never invent names; annotate uncertainty in anomalies.
      - Preserve provenance on every record (file:line and optional byte spans).
      - Use simple heuristics to recover call targets for Python and JS/TS.
      - Keep it incremental-friendly: identities are path+qname based.
    """

    def __init__(self):
        self._next_sym_id = 1
        self._next_fn_id = 1
        self._next_cls_id = 1
        self._next_edge_id = 1

    # ---------------------------
    # Public API
    # ---------------------------
    def build(self,
              asts: List[GenericAST],
              file_meta: Dict[str, FileRecord]) -> UCGBatch:
        """
        Build a UCGBatch from parsed ASTs.

        Args:
            asts:      GenericASTs from parser_registry.
            file_meta: Map rel_path -> FileRecord (from repo_loader), to enrich files table.

        Returns:
            UCGBatch
        """
        batch = UCGBatch()

        # 1) Files
        for ast in asts:
            fr = file_meta.get(ast.rel_path)
            if not fr:
                # Allow proceeding; mark anomaly
                batch.anomalies.append({"rel_path": ast.rel_path, "reason": "MISSING_FILE_META"})
                ucg_file = UCGFile(
                    file_id_hint=f"{ast.rel_path}:unknown",
                    rel_path=ast.rel_path,
                    language=ast.language,
                    size_bytes=-1,
                    mtime=-1.0,
                    content_hash="",
                    abs_locator="",
                )
            else:
                ucg_file = UCGFile(
                    file_id_hint=fr.file_id,
                    rel_path=fr.rel_path,
                    language=fr.language,
                    size_bytes=fr.size_bytes,
                    mtime=fr.mtime,
                    content_hash=fr.content_hash,
                    abs_locator=fr.abs_locator,
                )
            batch.files.append(ucg_file)

        # 2) Per-file traversal to build functions/classes/symbols/edges
        for ast in asts:
            scope = ScopeState(module=ast.rel_path)  # module scope key == file rel_path
            self._walk_file(ast, batch, scope)

        return batch

    # ---------------------------
    # Walkers
    # ---------------------------

    def _walk_file(self, ast: GenericAST, batch: UCGBatch, scope: 'ScopeState') -> None:
        """
        Walk a file. The file's root is scope.module (module-level).
        """
        # Defines edges for all top-level defs/classes will be added as we see them
        for child in ast.root.children:
            self._visit_node(ast, child, batch, scope)

    def _visit_node(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        kind = node.kind

        # Normalize by language family
        if ast.language == "python":
            if kind in ("FunctionDef", "AsyncFunctionDef"):
                self._handle_py_function(ast, node, batch, scope)
                return
            if kind == "ClassDef":
                self._handle_py_class(ast, node, batch, scope)
                return
            if kind in ("Import", "ImportFrom"):
                self._handle_py_import(ast, node, batch, scope)
                # keep walking to see inner alias nodes if present
        else:
            # JS/TS common kinds
            if kind in ("function_declaration", "method_definition"):
                self._handle_ts_function(ast, node, batch, scope)
                return
            if kind in ("class_declaration", "class"):
                self._handle_ts_class(ast, node, batch, scope)
                return
            if kind in ("import_statement", "import_clause"):
                self._handle_ts_import(ast, node, batch, scope)

        # Calls appear in both languages; catch common surface forms
        if kind in ("Call", "call_expression"):
            self._handle_call(ast, node, batch, scope)

        # Recurse
        for ch in node.children:
            self._visit_node(ast, ch, batch, scope)

    # ---------------------------
    # Python specifics
    # ---------------------------

    def _py_get_name(self, node: GenericNode) -> Optional[str]:
        """
        GenericNode for CPython AST doesn't expose identifiers directly, but
        'FunctionDef'/'ClassDef' names are not children in our generic tree.
        For uniformity, we attempt to recover from the CPython AST shape:
        we rely on the node kind and sibling structure; if not available, we emit None.
        """
        # NOTE: Our GenericNode doesn't keep the 'name' attribute of CPython nodes.
        # To recover, we look into children to find an ast.Name node near the def line
        # as a heuristic; otherwise return None. Better solution: extend GenericNode
        # or attach metadata during PythonParser wrapping. For now, heuristics:
        for ch in node.children:
            if ch.kind == "name":  # Not present in CPython AST wrapped form
                return "<name>"
        return None  # we will fallback to anon ids and add anomalies

    def _handle_py_function(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        name = self._py_get_name(node) or self._recover_name_from_text(ast, node, fallback_prefix="func")
        qname = scope.child_qname(name)
        prov = self._prov(ast.rel_path, node, note="py:function")

        fn = UCGFunction(
            func_id=self._alloc_fn_id(),
            file_rel=ast.rel_path,
            qname=qname,
            name=name,
            scope_qname=scope.qname(),
            prov=prov,
            anomalies=[] if name else ["PY_NAME_HEURISTIC"],
        )
        batch.functions.append(fn)
        batch._fn_by_qname[qname] = fn

        # defines edge (module/class -> function)
        batch.edges.append(self._edge(ast.rel_path, scope.qname(), qname, "defines", node, "py:def"))

        # Recurse under new scope
        with scope.push(name, kind="func"):
            for ch in node.children:
                self._visit_node(ast, ch, batch, scope)

    def _handle_py_class(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        name = self._recover_name_from_text(ast, node, fallback_prefix="Class")
        qname = scope.child_qname(name)
        prov = self._prov(ast.rel_path, node, note="py:class")

        cls = UCGClass(
            class_id=self._alloc_cls_id(),
            file_rel=ast.rel_path,
            qname=qname,
            name=name,
            scope_qname=scope.qname(),
            prov=prov,
        )
        batch.classes.append(cls)
        batch._cls_by_qname[qname] = cls

        # defines edge (module/class -> class)
        batch.edges.append(self._edge(ast.rel_path, scope.qname(), qname, "defines", node, "py:class"))

        # Recurse under class scope
        with scope.push(name, kind="class"):
            for ch in node.children:
                self._visit_node(ast, ch, batch, scope)

    def _handle_py_import(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        # Imports in CPython AST have child alias nodes; here we only record a shallow symbol
        name = self._recover_name_from_text(ast, node, fallback_prefix="import")
        sym = self._symbol(batch, ast.rel_path, scope.qname(), name, "import", node, anomalies=[])
        batch.edges.append(self._edge(ast.rel_path, scope.qname(), name, "imports", node, "py:import"))

    # ---------------------------
    # TS/JS specifics
    # ---------------------------

    def _ts_extract_identifier(self, node: GenericNode) -> Optional[str]:
        # Walk shallow children to find an identifier-ish node
        for ch in node.children:
            # Tree-sitter JS/TS commonly uses 'identifier' for names
            if ch.kind in ("identifier", "type_identifier", "property_identifier"):
                # NOTE: we don't carry token text; so we can't read exact name.
                # We fallback to a generated placeholder and mark heuristic.
                return None
        return None

    def _handle_ts_function(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        name = self._recover_name_from_text(ast, node, fallback_prefix="fn")
        qname = scope.child_qname(name)
        fn = UCGFunction(
            func_id=self._alloc_fn_id(),
            file_rel=ast.rel_path,
            qname=qname,
            name=name,
            scope_qname=scope.qname(),
            prov=self._prov(ast.rel_path, node, note="ts:function"),
            anomalies=[] if name else ["TS_NAME_HEURISTIC"],
        )
        batch.functions.append(fn)
        batch._fn_by_qname[qname] = fn
        batch.edges.append(self._edge(ast.rel_path, scope.qname(), qname, "defines", node, "ts:def"))

        with scope.push(name, kind="func"):
            for ch in node.children:
                self._visit_node(ast, ch, batch, scope)

    def _handle_ts_class(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        name = self._recover_name_from_text(ast, node, fallback_prefix="Class")
        qname = scope.child_qname(name)
        cls = UCGClass(
            class_id=self._alloc_cls_id(),
            file_rel=ast.rel_path,
            qname=qname,
            name=name,
            scope_qname=scope.qname(),
            prov=self._prov(ast.rel_path, node, note="ts:class"),
        )
        batch.classes.append(cls)
        batch._cls_by_qname[qname] = cls
        batch.edges.append(self._edge(ast.rel_path, scope.qname(), qname, "defines", node, "ts:class"))

        with scope.push(name, kind="class"):
            for ch in node.children:
                self._visit_node(ast, ch, batch, scope)

    def _handle_ts_import(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        name = self._recover_name_from_text(ast, node, fallback_prefix="import")
        sym = self._symbol(batch, ast.rel_path, scope.qname(), name, "import", node, anomalies=[])
        batch.edges.append(self._edge(ast.rel_path, scope.qname(), name, "imports", node, "ts:import"))

    # ---------------------------
    # Calls (shared)
    # ---------------------------

    def _handle_call(self, ast: GenericAST, node: GenericNode, batch: UCGBatch, scope: 'ScopeState') -> None:
        """
        Build a 'calls' edge from the innermost function/class scope to a best-effort target.
        We do NOT resolve full symbols here; resolution happens later in symbol_resolver.py.
        For now we record a textual target placeholder derived from node shape/position.
        """
        caller = scope.qname()
        if not caller:
            # module-level call: attach to module scope ""
            caller = scope.qname()

        # Heuristic target name (we don't have token text in GenericNode)
        target = self._call_target_placeholder(ast, node)
        batch.edges.append(self._edge(ast.rel_path, caller, target, "calls", node, "call"))

    # ---------------------------
    # Utilities
    # ---------------------------

    def _symbol(self, batch: UCGBatch, file_rel: str, scope_qname: str,
                name: str, kind: str, node: GenericNode, anomalies: List[str]) -> UCGSymbol:
        key = (file_rel, scope_qname, name)
        existing = batch._sym_by_key.get(key)
        if existing:
            return existing
        sym = UCGSymbol(
            symbol_id=self._alloc_sym_id(),
            file_rel=file_rel,
            name=name,
            kind=kind,
            scope_qname=scope_qname,
            prov=self._prov(file_rel, node, note=f"sym:{kind}"),
            anomalies=anomalies,
        )
        batch.symbols.append(sym)
        batch._sym_by_key[key] = sym
        return sym

    def _edge(self, file_rel: str, src_qname: str, dst_qname: str, kind: str, node: GenericNode, note: str) -> UCGEdge:
        e = UCGEdge(
            edge_id=self._alloc_edge_id(),
            file_rel=file_rel,
            src_qname=src_qname,
            dst_qname=dst_qname,
            kind=kind,
            prov=self._prov(file_rel, node, note=note),
            note=note,
        )
        return e

    def _prov(self, file_rel: str, node: GenericNode, note: str = "") -> Provenance:
        return from_node(file_rel=file_rel, node=node, note=note)

    def _alloc_sym_id(self) -> int:
        i = self._next_sym_id
        self._next_sym_id += 1
        return i

    def _alloc_fn_id(self) -> int:
        i = self._next_fn_id
        self._next_fn_id += 1
        return i

    def _alloc_cls_id(self) -> int:
        i = self._next_cls_id
        self._next_cls_id += 1
        return i

    def _alloc_edge_id(self) -> int:
        i = self._next_edge_id
        self._next_edge_id += 1
        return i

    def _recover_name_from_text(self, ast: GenericAST, node: GenericNode, fallback_prefix: str) -> str:
        """
        We don't currently store identifier token text in GenericNode. Until we extend the
        parser wrappers to stash exact names, we generate a stable placeholder name
        from position: e.g., "func_L10_15" meaning defined near line 10 col 15.
        """
        return f"{fallback_prefix}_L{node.start_line}_{node.start_col}"

    def _call_target_placeholder(self, ast: GenericAST, node: GenericNode) -> str:
        """
        Without token text, return a stable call target placeholder by site.
        Resolution happens later in symbol_resolver; this preserves call site provenance.
        """
        return f"callsite@L{node.start_line}:{node.start_col}"


# =============================================================================
# Scoping helper
# =============================================================================

class ScopeState:
    """
    Maintains a stack of scope components to compute qualified names.
    For files we use the rel_path as the module key; module qname is "" (empty),
    and children are formed as "rel_path:Name" (class) or "rel_path:Name.method".
    """
    def __init__(self, module: str):
        self._module = module
        self._stack: List[Tuple[str, str]] = []  # (name, kind)

    def qname(self) -> str:
        if not self._stack:
            return ""  # module scope
        parts = [f"{self._module}:{self._stack[0][0]}"]
        for name, kind in self._stack[1:]:
            parts.append(f".{name}")
        return "".join(parts)

    def child_qname(self, name: str) -> str:
        if not self._stack:
            return f"{self._module}:{name}"
        return f"{self.qname()}.{name}"

    def push(self, name: str, kind: str):
        self._stack.append((name, kind))
        return _ScopeGuard(self)

    def pop(self):
        if self._stack:
            self._stack.pop()


class _ScopeGuard:
    def __init__(self, scope: ScopeState):
        self._scope = scope
    def __enter__(self):
        return self._scope
    def __exit__(self, exc_type, exc, tb):
        self._scope.pop()
