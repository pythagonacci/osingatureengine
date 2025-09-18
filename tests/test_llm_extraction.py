"""
Tests for Step 5 LLM extraction and enrichment.
"""

import json
import pytest
from unittest.mock import Mock, patch

from osigdetector.enrichment.osig_model import OSig, Citation, OSigBatch
from osigdetector.enrichment.json_validator import OSigValidator
from osigdetector.enrichment.llm_client import LLMClient, LLMResponse
from osigdetector.enrichment.llm_extractor import LLMExtractor, EnrichmentStats
from osigdetector.config import Config


class TestOSigModel:
    """Test OSig Pydantic model validation."""
    
    def test_valid_osig_creation(self):
        """Test creating a valid OSig."""
        citation = Citation(
            file="test.py",
            start=10,
            end=15,
            note="test citation"
        )
        
        osig = OSig(
            kind="http_response",
            fields={"method": "GET", "path": "/users"},
            data_atoms=["userId"],
            joins={"resource": "user"},
            summary="Gets user information from database",
            citations=[citation],
            llm_confidence=0.85,
            anomalies=[],
            hypothesis=False
        )
        
        assert osig.kind == "http_response"
        assert osig.fields["method"] == "GET"
        assert osig.data_atoms == ["userId"]
        assert osig.llm_confidence == 0.85
        assert not osig.hypothesis
        assert len(osig.citations) == 1
    
    def test_citation_validation(self):
        """Test citation validation rules."""
        # Valid citation
        citation = Citation(file="test.py", start=5, end=10)
        assert citation.start == 5
        assert citation.end == 10
        
        # Invalid citation (end < start)
        with pytest.raises(ValueError):
            Citation(file="test.py", start=10, end=5)
    
    def test_osig_confidence_hypothesis_auto_set(self):
        """Test that hypothesis is automatically set for low confidence."""
        citation = Citation(file="test.py", start=1, end=1)
        
        # Low confidence should auto-set hypothesis=True
        osig = OSig(
            kind="test",
            fields={},
            summary="Test operation",
            citations=[citation],
            llm_confidence=0.3,  # Low confidence
            hypothesis=False  # Should be overridden
        )
        
        assert osig.hypothesis is True  # Should be auto-set
    
    def test_osig_serialization(self):
        """Test OSig JSON serialization."""
        citation = Citation(file="test.py", start=1, end=1)
        osig = OSig(
            kind="test",
            fields={"key": "value"},
            summary="Test operation",
            citations=[citation],
            llm_confidence=0.8
        )
        
        # Test to_dict
        osig_dict = osig.to_dict()
        assert osig_dict["kind"] == "test"
        assert osig_dict["fields"]["key"] == "value"
        assert len(osig_dict["citations"]) == 1
        
        # Test JSON serialization
        json_str = osig.to_json()
        parsed = json.loads(json_str)
        assert parsed["kind"] == "test"
        
        # Test from_json
        recreated = OSig.from_json(json_str)
        assert recreated.kind == osig.kind
        assert recreated.llm_confidence == osig.llm_confidence


class TestOSigBatch:
    """Test OSigBatch functionality."""
    
    def test_osig_batch_operations(self):
        """Test OSigBatch filtering and statistics."""
        citation = Citation(file="test.py", start=1, end=1)
        
        osigs = [
            OSig(kind="http_response", fields={}, summary="Test 1", citations=[citation], llm_confidence=0.9),
            OSig(kind="db_write", fields={}, summary="Test 2", citations=[citation], llm_confidence=0.6),
            OSig(kind="http_response", fields={}, summary="Test 3", citations=[citation], llm_confidence=0.3),
        ]
        
        batch = OSigBatch(osigs=osigs)
        
        # Test length and iteration
        assert len(batch) == 3
        assert len(list(batch)) == 3
        
        # Test filtering by confidence
        high_conf = batch.filter_by_confidence(0.8)
        assert len(high_conf) == 1
        assert high_conf.osigs[0].llm_confidence == 0.9
        
        # Test filtering by kind
        http_osigs = batch.filter_by_kind("http_response")
        assert len(http_osigs) == 2
        
        # Test confidence stats
        stats = batch.get_confidence_stats()
        assert stats["count"] == 3
        assert stats["mean"] == (0.9 + 0.6 + 0.3) / 3
        assert stats["min"] == 0.3
        assert stats["max"] == 0.9


class TestJSONValidator:
    """Test JSON validation for OSig extraction."""
    
    def test_valid_json_validation(self):
        """Test validation of valid OSig JSON."""
        config = Config()
        validator = OSigValidator(config)
        
        valid_json = {
            "kind": "http_response",
            "fields": {"method": "GET", "path": "/test"},
            "data_atoms": ["testId"],
            "joins": {},
            "summary": "Gets test data from API",
            "citations": [{"file": "test.py", "start": 1, "end": 1}],
            "llm_confidence": 0.8,
            "anomalies": [],
            "hypothesis": False
        }
        
        context_bundle = {
            "anchor": {"provenance": {"file": "test.py", "start": 1, "end": 1}}
        }
        
        osig, anomalies = validator.validate_and_parse(
            json.dumps(valid_json), context_bundle
        )
        
        assert osig is not None
        assert osig.kind == "http_response"
        assert osig.llm_confidence == 0.8
    
    def test_invalid_json_handling(self):
        """Test handling of invalid JSON responses."""
        config = Config()
        validator = OSigValidator(config)
        
        context_bundle = {
            "anchor": {"provenance": {"file": "test.py", "start": 1, "end": 1}}
        }
        
        # Test malformed JSON
        osig, anomalies = validator.validate_and_parse(
            "This is not JSON at all", context_bundle
        )
        
        assert osig is None
        assert "JSON_EXTRACTION_FAILED" in anomalies
    
    def test_fallback_osig_creation(self):
        """Test creation of fallback OSigs."""
        config = Config()
        validator = OSigValidator(config)
        
        context_bundle = {
            "anchor": {
                "kind": "http_response",
                "resolved_fields": {"method": "GET", "path": "/test"},
                "provenance": {"file": "test.py", "start": 10, "end": 15}
            }
        }
        
        fallback_osig = validator.create_fallback_osig(context_bundle, "TEST_ERROR")
        
        assert fallback_osig.kind == "http_response"
        assert fallback_osig.llm_confidence == 0.1  # Very low
        assert fallback_osig.hypothesis is True
        assert "LLM_EXTRACTION_FAILED" in fallback_osig.anomalies
        assert "TEST_ERROR" in fallback_osig.anomalies
        assert len(fallback_osig.citations) == 1
        assert fallback_osig.citations[0].file == "test.py"


class TestLLMClient:
    """Test LLM client functionality."""
    
    def test_llm_client_initialization(self):
        """Test LLM client initialization."""
        config = Config()
        config.llm_api_key = "test_key"
        
        # Should initialize without errors if OpenAI is available
        try:
            client = LLMClient(config)
            assert client.model == config.llm_model
            assert client.temperature == config.llm_temperature
        except ImportError:
            # Skip if OpenAI not available
            pytest.skip("OpenAI package not available")
    
    @patch('osigdetector.enrichment.llm_client.openai.OpenAI')
    def test_llm_response_processing(self, mock_openai):
        """Test LLM response processing with mocked API."""
        config = Config()
        config.llm_api_key = "test_key"
        
        # Mock successful API response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"kind": "test", "summary": "Test", "citations": [], "llm_confidence": 0.8}'
        mock_response.usage.total_tokens = 100
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        client = LLMClient(config)
        
        test_bundle = {
            "anchor": {"kind": "test"},
            "file_header": {},
            "span_snippet": [],
            "neighbor_facts": [],
            "cfg_outcomes": [],
            "dfg_bindings": {},
            "framework_hints": {}
        }
        
        response = client.extract_osig(test_bundle)
        
        assert response.success
        assert response.tokens_used == 100
        assert response.cost_estimate > 0
    
    def test_cache_functionality(self):
        """Test LLM response caching."""
        config = Config()
        config.llm_api_key = "test_key"
        
        try:
            client = LLMClient(config)
            
            # Test cache stats
            stats = client.get_cache_stats()
            assert "cache_size" in stats
            assert "cache_enabled" in stats
            
            # Test cache clearing
            client.clear_cache()
            assert len(client.cache) == 0
            
        except ImportError:
            pytest.skip("OpenAI package not available")


class TestLLMExtractor:
    """Test the main LLM extractor orchestrator."""
    
    def test_extractor_initialization(self):
        """Test LLM extractor initialization."""
        config = Config()
        config.llm_api_key = "test_key"
        
        try:
            extractor = LLMExtractor(config)
            assert extractor.config == config
            assert extractor.llm_client is not None
            assert extractor.validator is not None
        except ImportError:
            pytest.skip("OpenAI package not available")
    
    def test_enrichment_stats(self):
        """Test enrichment statistics tracking."""
        stats = EnrichmentStats()
        
        assert stats.total_packs == 0
        assert stats.successful_extractions == 0
        assert stats.anomaly_counts == {}
        
        # Test stats updates
        stats.total_packs = 10
        stats.successful_extractions = 8
        stats.failed_extractions = 2
        
        assert stats.total_packs == 10
        assert stats.successful_extractions == 8


def test_prompt_templates_exist():
    """Test that prompt templates are properly formatted."""
    from pathlib import Path
    
    prompts_dir = Path(__file__).parent.parent / "osigdetector" / "enrichment" / "prompts"
    
    # Check that prompt files exist
    http_prompt = prompts_dir / "http_response.json"
    db_prompt = prompts_dir / "db_write.json"
    external_prompt = prompts_dir / "external_call.json"
    
    assert http_prompt.exists(), "HTTP response prompt template missing"
    assert db_prompt.exists(), "DB write prompt template missing"
    assert external_prompt.exists(), "External call prompt template missing"
    
    # Validate prompt template structure
    for prompt_file in [http_prompt, db_prompt, external_prompt]:
        with open(prompt_file) as f:
            prompt_data = json.load(f)
        
        assert "system_prompt" in prompt_data
        assert "user_prompt_template" in prompt_data
        assert "example_output" in prompt_data
        
        # Validate example output structure
        example = prompt_data["example_output"]
        required_fields = ["kind", "fields", "summary", "citations", "llm_confidence"]
        
        for field in required_fields:
            assert field in example, f"Missing {field} in {prompt_file.name} example"


def test_osig_model_integration():
    """Test integration between OSig model and JSON validation."""
    # Test that the example outputs in prompts are valid OSigs
    from pathlib import Path
    
    prompts_dir = Path(__file__).parent.parent / "osigdetector" / "enrichment" / "prompts"
    
    for prompt_file in prompts_dir.glob("*.json"):
        with open(prompt_file) as f:
            prompt_data = json.load(f)
        
        example_output = prompt_data["example_output"]
        
        # Should be able to create OSig from example
        try:
            osig = OSig(**example_output)
            assert osig.kind == example_output["kind"]
            assert osig.llm_confidence == example_output["llm_confidence"]
        except Exception as e:
            pytest.fail(f"Invalid example output in {prompt_file.name}: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
