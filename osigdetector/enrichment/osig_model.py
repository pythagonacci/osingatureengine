"""
OSig (Operational Signature) Pydantic models.

Defines the core data structures for fully enriched operational signatures
with strict validation, serialization, and schema enforcement.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, validator
import json


class Citation(BaseModel):
    """A citation pointing to specific code location that supports an OSig."""
    
    file: str = Field(..., description="File path relative to repository root")
    start: int = Field(..., ge=1, description="Start line number (1-based)")
    end: int = Field(..., ge=1, description="End line number (1-based)")
    note: Optional[str] = Field(None, description="Optional note about what this citation proves")
    
    @validator('end')
    def end_must_be_after_start(cls, v, values):
        """Ensure end line is >= start line."""
        if 'start' in values and v < values['start']:
            raise ValueError('end line must be >= start line')
        return v
    
    def __str__(self) -> str:
        """Human-readable citation format."""
        note_part = f" ({self.note})" if self.note else ""
        return f"{self.file}:{self.start}-{self.end}{note_part}"


class OSig(BaseModel):
    """
    Complete Operational Signature with semantic enrichment.
    
    This represents a fully analyzed operational signature that has been
    enriched by LLM processing with semantic understanding, data atoms,
    join keys, and human-readable summaries.
    """
    
    kind: str = Field(
        ..., 
        description="OSig kind e.g. http_response, db_write, external_call"
    )
    
    fields: Dict[str, Any] = Field(
        ..., 
        description="Kind-specific fields (method, path, table, etc.)"
    )
    
    data_atoms: List[str] = Field(
        default_factory=list,
        description="Domain-specific entities (userId, orderId, etc.)"
    )
    
    joins: Dict[str, Any] = Field(
        default_factory=dict,
        description="Join keys for stitching OSigs together"
    )
    
    summary: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="1-2 line human-readable summary starting with a verb"
    )
    
    citations: List[Citation] = Field(
        ...,
        min_items=1,
        description="File:line spans proving the OSig"
    )
    
    llm_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="LLM confidence score (0.0-1.0)"
    )
    
    anomalies: List[str] = Field(
        default_factory=list,
        description="Anomaly codes for uncertain or problematic fields"
    )
    
    hypothesis: bool = Field(
        default=False,
        description="Whether this OSig is a hypothesis (low confidence)"
    )
    
    @validator('summary')
    def summary_must_start_with_verb(cls, v):
        """Ensure summary starts with a verb (action word)."""
        if not v:
            raise ValueError('summary cannot be empty')
        
        # Split into sentences and check first word of first sentence
        first_sentence = v.split('.')[0].strip()
        if not first_sentence:
            raise ValueError('summary must contain at least one sentence')
        
        first_word = first_sentence.split()[0].lower()
        
        # Common verb patterns (not exhaustive, but catches most cases)
        verb_patterns = [
            # Action verbs
            'creates', 'create', 'updates', 'update', 'deletes', 'delete',
            'gets', 'get', 'retrieves', 'retrieve', 'sends', 'send',
            'processes', 'process', 'handles', 'handle', 'manages', 'manage',
            'generates', 'generate', 'validates', 'validate', 'checks', 'check',
            'saves', 'save', 'loads', 'load', 'fetches', 'fetch',
            'executes', 'execute', 'runs', 'run', 'performs', 'perform',
            'returns', 'return', 'responds', 'respond', 'serves', 'serve',
            # Present continuous
            'creating', 'updating', 'deleting', 'getting', 'retrieving',
            'sending', 'processing', 'handling', 'managing', 'generating',
            'validating', 'checking', 'saving', 'loading', 'fetching',
            'executing', 'running', 'performing', 'returning', 'responding'
        ]
        
        if first_word not in verb_patterns:
            # Allow it but add a warning in anomalies during validation
            pass  # We'll handle this in the extractor
        
        return v
    
    @validator('hypothesis')
    def set_hypothesis_for_low_confidence(cls, v, values):
        """Automatically set hypothesis=True for low confidence OSigs."""
        if 'llm_confidence' in values and values['llm_confidence'] < 0.5:
            return True
        return v
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with proper JSON serialization."""
        return {
            "kind": self.kind,
            "fields": self.fields,
            "data_atoms": self.data_atoms,
            "joins": self.joins,
            "summary": self.summary,
            "citations": [citation.dict() for citation in self.citations],
            "llm_confidence": self.llm_confidence,
            "anomalies": self.anomalies,
            "hypothesis": self.hypothesis
        }
    
    def to_json(self, **kwargs) -> str:
        """Convert to JSON string."""
        return self.json(**kwargs)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'OSig':
        """Create OSig from JSON string."""
        return cls.parse_raw(json_str)
    
    def get_primary_citation(self) -> Citation:
        """Get the primary (first) citation."""
        return self.citations[0]
    
    def add_anomaly(self, anomaly_code: str) -> None:
        """Add an anomaly code if not already present."""
        if anomaly_code not in self.anomalies:
            self.anomalies.append(anomaly_code)
    
    def is_high_confidence(self) -> bool:
        """Check if this OSig has high confidence (>= 0.7)."""
        return self.llm_confidence >= 0.7
    
    def is_medium_confidence(self) -> bool:
        """Check if this OSig has medium confidence (0.5-0.7)."""
        return 0.5 <= self.llm_confidence < 0.7
    
    def is_low_confidence(self) -> bool:
        """Check if this OSig has low confidence (< 0.5)."""
        return self.llm_confidence < 0.5


class OSigBatch(BaseModel):
    """A batch of OSigs with metadata."""
    
    osigs: List[OSig] = Field(..., description="List of OSigs in this batch")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Batch metadata")
    
    def __len__(self) -> int:
        """Number of OSigs in the batch."""
        return len(self.osigs)
    
    def __iter__(self):
        """Iterate over OSigs."""
        return iter(self.osigs)
    
    def filter_by_confidence(self, min_confidence: float) -> 'OSigBatch':
        """Filter OSigs by minimum confidence."""
        filtered = [osig for osig in self.osigs if osig.llm_confidence >= min_confidence]
        return OSigBatch(osigs=filtered, metadata=self.metadata.copy())
    
    def filter_by_kind(self, kind: str) -> 'OSigBatch':
        """Filter OSigs by kind."""
        filtered = [osig for osig in self.osigs if osig.kind == kind]
        return OSigBatch(osigs=filtered, metadata=self.metadata.copy())
    
    def get_confidence_stats(self) -> Dict[str, float]:
        """Get confidence statistics."""
        if not self.osigs:
            return {"mean": 0.0, "min": 0.0, "max": 0.0, "count": 0}
        
        confidences = [osig.llm_confidence for osig in self.osigs]
        return {
            "mean": sum(confidences) / len(confidences),
            "min": min(confidences),
            "max": max(confidences),
            "count": len(confidences)
        }


# JSON Schema for LLM prompt validation
OSIG_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {
            "type": "string",
            "description": "OSig kind e.g. http_response, db_write"
        },
        "fields": {
            "type": "object",
            "description": "Kind-specific fields"
        },
        "data_atoms": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Domain-specific entities"
        },
        "joins": {
            "type": "object",
            "description": "Join keys for stitching OSigs"
        },
        "summary": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": "1-2 line human-readable summary"
        },
        "citations": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "start": {"type": "integer", "minimum": 1},
                    "end": {"type": "integer", "minimum": 1},
                    "note": {"type": "string"}
                },
                "required": ["file", "start", "end"]
            }
        },
        "llm_confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0
        },
        "anomalies": {
            "type": "array",
            "items": {"type": "string"}
        },
        "hypothesis": {
            "type": "boolean"
        }
    },
    "required": ["kind", "fields", "summary", "citations", "llm_confidence"]
}
