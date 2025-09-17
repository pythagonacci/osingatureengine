# osigdetector/ingestion/build_ucg.py
from __future__ import annotations

import os
from typing import Dict

from .repo_loader import load_repo, FileRecord
from .parser_registry import ParserRegistry, GenericAST
from .ast_to_ucg import ASTtoUCGBuilder, UCGBatch
from .symbol_resolver import SymbolResolver
from .cfg_builder import CFGBuilder
from .dfg_builder import DFGBuilder
from .effect_annotator import EffectAnnotator
from .ucg_store import UCGStore


def build_ucg(
    repo_path: str,
    languages: list[str] | None = None,
    db_path: str = "artifacts/ucg.sqlite",
    incremental: bool = True,
    cache_path: str | None = ".osigcache.json",
) -> UCGStore:
    """
    Build the Step-1 Uniform Code Graph (UCG) for a repo.

    Pipeline:
      1. Repo loader → files & FileRecords
      2. ParserRegistry → GenericASTs
      3. AST → UCG (functions, classes, symbols, edges)
      4. SymbolResolver → upgrades call edges with identifiers
      5. CFGBuilder → block-level control flow
      6. DFGBuilder → local literal/data flow bindings
      7. EffectAnnotator → pre-OSig effect carriers
      8. UCGStore → persist all to SQLite

    Args:
        repo_path:     Path to local dir or .zip archive
        languages:     Optional whitelist of language tags
        db_path:       SQLite DB file (created if missing)
        incremental:   Use cache to skip unchanged files
        cache_path:    Path for JSON cache (default .osigcache.json)

    Returns:
        UCGStore handle (ready for queries)
    """
    # Step 1: load repo
    snap = load_repo(repo_path, languages=languages, incremental=incremental, cache_path=cache_path)
    file_meta: Dict[str, FileRecord] = {fr.rel_path: fr for fr in snap.files}

    # Step 2: parse files → ASTs
    registry = ParserRegistry()
    asts: list[GenericAST] = registry.parse_files(snap.changed_files or snap.files)

    # Step 3: lift AST → UCG
    ast_builder = ASTtoUCGBuilder()
    ucg: UCGBatch = ast_builder.build(asts, file_meta)

    # Step 4: resolve symbols (enrich calls)
    resolver = SymbolResolver()
    stats = resolver.resolve(ucg, file_meta)

    # Step 5: build CFGs
    cfg_builder = CFGBuilder()
    # For now we can’t map fn_qname -> GenericNode easily; use empty map
    cfgs = {}  # qname -> CFGBundle (wire when we carry nodes)
    # TODO: Connect ASTtoUCGBuilder to emit qname->node map

    # Step 6: build DFGs
    dfg_builder = DFGBuilder()
    dfgs = {}  # qname -> DFGBundle (same TODO as above)

    # Step 7: annotate effects
    annotator = EffectAnnotator()
    effects_bundle = annotator.annotate(ucg, fn_nodes={}, file_meta=file_meta)

    # Step 8: persist to store
    store = UCGStore(db_path)
    store.write_all(ucg, cfg_by_func=cfgs, dfg_by_func=dfgs, effects=effects_bundle)

    return store
