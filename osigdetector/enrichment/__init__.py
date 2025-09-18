"""
Enrichment module - Step 4: Context Packing & Step 5: LLM Enrichment

This module handles context packing for LLM input preparation and
LLM-powered enrichment of proto-OSig anchors.
"""

from .context_packer import ContextPacker, build_context_packs

__all__ = [
    "ContextPacker",
    "build_context_packs",
]
