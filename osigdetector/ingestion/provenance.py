# osigdetector/ingestion/provenance.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Union

from .parser_registry import GenericNode


@dataclass
class Provenance:
    """
    Provenance = citation metadata for any graph node/edge/effect.

    Fields:
      file_rel   -- relative path inside repo
      start_line -- 1-based inclusive
      end_line   -- 1-based inclusive
      start_byte -- byte offset in file (or -1 if unknown)
      end_byte   -- byte offset (or -1 if unknown)
      note       -- short tag: "py:function", "express_route", etc.
      anomalies  -- optional warnings if provenance is incomplete
    """
    file_rel: str
    start_line: int
    end_line: int
    start_byte: int = -1
    end_byte: int = -1
    note: str = ""
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file_rel,
            "sl": self.start_line,
            "el": self.end_line,
            "sbyte": self.start_byte,
            "ebyte": self.end_byte,
            "note": self.note,
            "anomalies": self.anomalies,
        }

    def short(self) -> str:
        """Short human-readable form, like 'main.py:L10-12 (py:function)'."""
        return f"{self.file_rel}:L{self.start_line}-{self.end_line} ({self.note})"


# =============================================================================
# Helper constructors
# =============================================================================

def from_node(file_rel: str, node: GenericNode, note: str = "", anomalies: Optional[List[str]] = None) -> Provenance:
    """
    Construct provenance from a GenericNode.
    """
    return Provenance(
        file_rel=file_rel,
        start_line=node.start_line,
        end_line=node.end_line,
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        note=note,
        anomalies=anomalies or [],
    )


def from_regex(file_rel: str, line: int, note: str = "", anomalies: Optional[List[str]] = None) -> Provenance:
    """
    Construct provenance from a regex match in file text (line number known).
    """
    return Provenance(
        file_rel=file_rel,
        start_line=line,
        end_line=line,
        note=note,
        anomalies=anomalies or [],
    )


def merge(file_rel: str, provs: List[Provenance], note: str = "merged") -> Provenance:
    """
    Merge multiple provenance spans into a single covering span.
    """
    if not provs:
        return Provenance(file_rel=file_rel, start_line=1, end_line=1, note=note, anomalies=["MERGE_EMPTY"])
    sl = min(p.start_line for p in provs)
    el = max(p.end_line for p in provs)
    return Provenance(file_rel=file_rel, start_line=sl, end_line=el, note=note)
