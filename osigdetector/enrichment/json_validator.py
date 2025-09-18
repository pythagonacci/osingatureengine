"""
JSON validator for OSig extraction with Pydantic integration.

Validates LLM responses against OSig schema and provides detailed error reporting.
"""

import json
import re
from typing import Dict, Any, Optional, List, Tuple
from pydantic import ValidationError

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger
from .osig_model import OSig, Citation, OSIG_JSON_SCHEMA

logger = get_logger(__name__)


class OSigValidator:
    """Validates and cleans LLM responses for OSig extraction."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
    
    def validate_and_parse(self, llm_response: str, context_bundle: Dict[str, Any]) -> Tuple[Optional[OSig], List[str]]:
        """
        Validate LLM response and parse into OSig object.
        
        Args:
            llm_response: Raw LLM response string
            context_bundle: Original context bundle for fallback data
            
        Returns:
            Tuple of (OSig object or None, list of anomalies)
        """
        anomalies = []
        
        # Step 1: Extract JSON from response
        json_str, extract_anomalies = self._extract_json(llm_response)
        anomalies.extend(extract_anomalies)
        
        if not json_str:
            self.logger.error("Could not extract JSON from LLM response")
            return None, anomalies + ["JSON_EXTRACTION_FAILED"]
        
        # Step 2: Parse JSON
        try:
            json_data = json.loads(json_str)
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in LLM response: {e}")
            return None, anomalies + ["INVALID_JSON"]
        
        # Step 3: Validate against schema
        validation_anomalies = self._validate_json_schema(json_data)
        anomalies.extend(validation_anomalies)
        
        # Step 4: Clean and enhance the data
        cleaned_data, clean_anomalies = self._clean_osig_data(json_data, context_bundle)
        anomalies.extend(clean_anomalies)
        
        # Step 5: Create OSig object with Pydantic validation
        try:
            osig = OSig(**cleaned_data)
            
            # Add any validation anomalies to the OSig
            for anomaly in anomalies:
                osig.add_anomaly(anomaly)
            
            return osig, anomalies
            
        except ValidationError as e:
            self.logger.error(f"Pydantic validation failed: {e}")
            return None, anomalies + ["PYDANTIC_VALIDATION_FAILED"]
    
    def _extract_json(self, llm_response: str) -> Tuple[Optional[str], List[str]]:
        """Extract JSON object from LLM response."""
        anomalies = []
        
        # Clean the response
        response = llm_response.strip()
        
        # Look for JSON object boundaries
        json_patterns = [
            # Direct JSON object
            r'\{.*\}',
            # JSON wrapped in code blocks
            r'```(?:json)?\s*(\{.*\})\s*```',
            # JSON after "JSON:" or similar
            r'(?:JSON|json):\s*(\{.*\})',
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                # Extract the JSON part
                json_candidate = match.group(1) if match.groups() else match.group(0)
                
                # Try to parse to verify it's valid JSON
                try:
                    json.loads(json_candidate)
                    return json_candidate, anomalies
                except json.JSONDecodeError:
                    continue
        
        # If no valid JSON found, try to extract anything that looks like JSON
        brace_start = response.find('{')
        brace_end = response.rfind('}')
        
        if brace_start >= 0 and brace_end > brace_start:
            json_candidate = response[brace_start:brace_end + 1]
            try:
                json.loads(json_candidate)
                anomalies.append("JSON_EXTRACTION_HEURISTIC")
                return json_candidate, anomalies
            except json.JSONDecodeError:
                pass
        
        return None, anomalies + ["NO_JSON_FOUND"]
    
    def _validate_json_schema(self, json_data: Dict[str, Any]) -> List[str]:
        """Validate JSON data against OSig schema."""
        anomalies = []
        
        # Check required fields
        required_fields = ["kind", "fields", "summary", "citations", "llm_confidence"]
        for field in required_fields:
            if field not in json_data:
                anomalies.append(f"MISSING_REQUIRED_FIELD_{field.upper()}")
        
        # Validate field types
        if "llm_confidence" in json_data:
            confidence = json_data["llm_confidence"]
            if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 1):
                anomalies.append("INVALID_CONFIDENCE_RANGE")
        
        if "citations" in json_data:
            citations = json_data["citations"]
            if not isinstance(citations, list) or len(citations) == 0:
                anomalies.append("MISSING_CITATIONS")
            else:
                for i, citation in enumerate(citations):
                    if not isinstance(citation, dict):
                        anomalies.append(f"INVALID_CITATION_{i}")
                        continue
                    
                    if "file" not in citation or "start" not in citation or "end" not in citation:
                        anomalies.append(f"INCOMPLETE_CITATION_{i}")
        
        if "summary" in json_data:
            summary = json_data["summary"]
            if not isinstance(summary, str) or len(summary.strip()) == 0:
                anomalies.append("EMPTY_SUMMARY")
            elif len(summary) > 200:
                anomalies.append("SUMMARY_TOO_LONG")
        
        return anomalies
    
    def _clean_osig_data(
        self, 
        json_data: Dict[str, Any], 
        context_bundle: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Clean and enhance OSig data with fallbacks."""
        cleaned = json_data.copy()
        anomalies = []
        
        # Ensure required fields have defaults
        if "data_atoms" not in cleaned:
            cleaned["data_atoms"] = []
        
        if "joins" not in cleaned:
            cleaned["joins"] = {}
        
        if "anomalies" not in cleaned:
            cleaned["anomalies"] = []
        
        if "hypothesis" not in cleaned:
            cleaned["hypothesis"] = False
        
        # Clean and validate citations
        if "citations" in cleaned:
            cleaned_citations = []
            for citation_data in cleaned["citations"]:
                if isinstance(citation_data, dict):
                    # Ensure citation has required fields
                    if "file" in citation_data and "start" in citation_data and "end" in citation_data:
                        # Clean the citation data
                        clean_citation = {
                            "file": str(citation_data["file"]),
                            "start": int(citation_data["start"]),
                            "end": int(citation_data["end"]),
                            "note": citation_data.get("note", "")
                        }
                        cleaned_citations.append(clean_citation)
                    else:
                        anomalies.append("INCOMPLETE_CITATION_DATA")
            
            # If no valid citations, create one from context
            if not cleaned_citations:
                anchor = context_bundle.get("anchor", {})
                provenance = anchor.get("provenance", {})
                
                if provenance.get("file") and provenance.get("start"):
                    fallback_citation = {
                        "file": provenance["file"],
                        "start": provenance["start"],
                        "end": provenance.get("end", provenance["start"]),
                        "note": "fallback from anchor provenance"
                    }
                    cleaned_citations.append(fallback_citation)
                    anomalies.append("FALLBACK_CITATION_USED")
            
            cleaned["citations"] = cleaned_citations
        
        # Validate confidence and set hypothesis
        confidence = cleaned.get("llm_confidence", 0.0)
        if confidence < 0.5:
            cleaned["hypothesis"] = True
            if "LOW_CONFIDENCE" not in cleaned["anomalies"]:
                cleaned["anomalies"].append("LOW_CONFIDENCE")
        
        # Clean summary
        if "summary" in cleaned:
            summary = cleaned["summary"].strip()
            
            # Check if summary starts with a verb
            if summary and not self._starts_with_verb(summary):
                anomalies.append("SUMMARY_NO_VERB")
            
            cleaned["summary"] = summary
        
        return cleaned, anomalies
    
    def _starts_with_verb(self, summary: str) -> bool:
        """Check if summary starts with an action verb."""
        if not summary:
            return False
        
        first_word = summary.split()[0].lower()
        
        # Common action verbs for API operations
        action_verbs = {
            'creates', 'create', 'updates', 'update', 'deletes', 'delete',
            'gets', 'get', 'retrieves', 'retrieve', 'sends', 'send',
            'processes', 'process', 'handles', 'handle', 'manages', 'manage',
            'generates', 'generate', 'validates', 'validate', 'checks', 'check',
            'saves', 'save', 'loads', 'load', 'fetches', 'fetch',
            'executes', 'execute', 'runs', 'run', 'performs', 'perform',
            'returns', 'return', 'responds', 'respond', 'serves', 'serve',
            'creates', 'creating', 'updates', 'updating', 'deletes', 'deleting',
            'processes', 'processing', 'handles', 'handling', 'manages', 'managing'
        }
        
        return first_word in action_verbs
    
    def create_fallback_osig(
        self, 
        context_bundle: Dict[str, Any], 
        error_reason: str
    ) -> OSig:
        """
        Create a fallback OSig when LLM extraction fails.
        
        Args:
            context_bundle: Original context bundle
            error_reason: Reason for fallback
            
        Returns:
            Fallback OSig with low confidence
        """
        anchor = context_bundle.get("anchor", {})
        
        # Extract basic information from anchor
        kind = anchor.get("kind", "unknown")
        resolved_fields = anchor.get("resolved_fields", {})
        provenance = anchor.get("provenance", {})
        
        # Create fallback citation
        fallback_citation = Citation(
            file=provenance.get("file", "unknown"),
            start=provenance.get("start", 1),
            end=provenance.get("end", 1),
            note="fallback citation due to LLM failure"
        )
        
        # Create basic summary
        summary = f"Performs {kind} operation (LLM extraction failed)"
        
        return OSig(
            kind=kind,
            fields=resolved_fields,
            data_atoms=[],
            joins={},
            summary=summary,
            citations=[fallback_citation],
            llm_confidence=0.1,  # Very low confidence
            anomalies=["LLM_EXTRACTION_FAILED", error_reason],
            hypothesis=True
        )
