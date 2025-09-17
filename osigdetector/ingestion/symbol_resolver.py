# osigdetector/ingestion/symbol_resolver.py
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .repo_loader import FileRecord
from .ast_to_ucg import UCGBatch, UCGEdge, UCGFunction, UCGClass

# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

@dataclass
class ResolutionStats:
    files: int = 0
    edges_total: int = 0
    call_edges: int = 0
    calls_with_ident: int = 0
    calls_upgraded_dst: int = 0
    anomalies: List[Dict[str, str]] = field(default_factory=list)


class SymbolResolver:
    """
    Step 1 resolver (lightweight):
      - Builds per-file symbol tables of locally defined functions/classes (qnames).
      - For each 'calls' edge, extracts the textual callee identifier at the callsite
        (using provenance line/column and raw source bytes).
      - Upgrades edge.dst_qname to 'ident:<name>' for readability, and records an anomaly
        if extraction fails.

    Notes:
      * We DO NOT attempt cross-file or framework-aware resolution here.
      * Function/class names produced earlier may be placeholders (e.g., func_L10_4).
        So we do *not* try to bind to qnames yet; that happens in later steps once
        GenericNode carries identifier text.
    """

    _PY_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_\.]*")
    _JS_IDENT = re.compile(r"[A-Za-z_\$][A-Za-z0-9_\$\.]*")

    def resolve(self, batch: UCGBatch, file_meta: Dict[str, FileRecord]) -> ResolutionStats:
        stats = ResolutionStats()
        stats.files = len({f.rel_path for f in batch.files})

        # Build quick index of local definitions by file (qname -> UCGFunction/Class)
        defs_by_file: Dict[str, Dict[str, str]] = self._index_local_defs(batch)

        # Iterate edges and enrich calls
        for e in batch.edges:
            stats.edges_total += 1
            if e.kind != "calls":
                continue
            stats.call_edges += 1

            fr = file_meta.get(e.file_rel)
            if not fr:
                stats.anomalies.append({"rel_path": e.file_rel, "reason": "MISSING_FILE_META_FOR_CALL"})
                continue

            src = self._read_text(fr)
            if src is None:
                stats.anomalies.append({"rel_path": e.file_rel, "reason": "IO_READ_FAILED"})
                continue

            ident = self._extract_ident_at(src, e.prov.start_line, 0, lang_hint=fr.language)
            if ident:
                stats.calls_with_ident += 1
                # For now, we upgrade the destination to 'ident:<name>'
                old = e.dst_qname
                e.dst_qname = f"ident:{ident}"
                # Optional: add a hint into note (non-breaking)
                if "callee=" not in e.note:
                    e.note = f"{e.note}; callee={ident}"
                stats.calls_upgraded_dst += 1
            else:
                stats.anomalies.append({
                    "rel_path": e.file_rel,
                    "reason": "IDENT_EXTRACT_FAILED",
                    "at": f"L{e.prov.start_line}:{e.prov.start_col}",
                })

        return stats

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _index_local_defs(self, batch: UCGBatch) -> Dict[str, Dict[str, str]]:
        """
        Build a per-file dictionary of 'visible names' -> qname for functions/classes.
        NOTE: Our Step 1 names may be placeholders; we keep the map for future binding.
        """
        out: Dict[str, Dict[str, str]] = {}
        for fn in batch.functions:
            out.setdefault(fn.file_rel, {})[fn.name] = fn.qname
        for cls in batch.classes:
            out.setdefault(cls.file_rel, {})[cls.name] = cls.qname
        return out

    def _read_text(self, fr: FileRecord) -> Optional[str]:
        """
        Read full file text from locator (supports file:// and zip://).
        Returns UTF-8 text (errors='replace') or None on hard failure.
        """
        try:
            if fr.abs_locator.startswith("file://"):
                path = fr.abs_locator[len("file://") :]
                with open(path, "rb") as f:
                    data = f.read()
            elif fr.abs_locator.startswith("zip://"):
                rest = fr.abs_locator[len("zip://") :]
                if "!/" not in rest:
                    return None
                zip_path, inner = rest.split("!/", 1)
                with zipfile.ZipFile(zip_path, "r") as zf:
                    with zf.open(inner, "r") as f:
                        data = f.read()
            else:
                return None
        except Exception:
            return None

        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")

    def _extract_ident_at(self, text: str, line: int, col: int, lang_hint: str) -> Optional[str]:
        """
        Extract a best-effort identifier starting at (line, col).
        We scan rightward from the call node's start to catch names like:
           python:  process_payment(...), client.create(...)
           js/ts:   axios.post(...), prisma.user.create(...)
        We allow dot-qualified names (foo.bar.baz); we return the full dotted string.
        """
        lines = text.splitlines()
        if line - 1 < 0 or line - 1 >= len(lines):
            return None
        s = lines[line - 1]
        if col < 0 or col >= len(s):
            # Try a small left shift in case the call node begins at '('
            col = max(0, min(len(s) - 1, col - 1))

        # Slice from col to some reasonable window
        window = s[col : col + 200]

        rx = self._PY_IDENT if lang_hint == "python" else self._JS_IDENT
        m = rx.search(window)
        if not m:
            # Occasionally, call node may start on whitespace/newline; look ahead next line
            if line < len(lines):
                window2 = lines[line][:200]
                m = rx.search(window2)
                if not m:
                    return None
            else:
                return None

        ident = m.group(0)
        # Strip trailing dots if regex caught incomplete segments
        ident = ident.rstrip(".")
        return ident or None
