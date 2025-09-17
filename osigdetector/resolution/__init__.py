"""
Resolution module - Step 3: String & Constant Resolution

This module handles resolving constants, strings, and variables in proto-OSig anchors
to fill in missing fields like paths, SQL tables, hosts, schema names, etc.
"""

from .constant_prop import ConstantPropagator
from .string_resolver import StringResolver
from .sql_resolver import SQLResolver
from .env_resolver import EnvironmentResolver
from .normalizer import Normalizer

__all__ = [
    "ConstantPropagator",
    "StringResolver", 
    "SQLResolver",
    "EnvironmentResolver",
    "Normalizer",
]
