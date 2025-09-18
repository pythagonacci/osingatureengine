"""
LLM Client for OSig extraction.

Handles API calls to various LLM providers (OpenAI, Anthropic, etc.)
with retry logic, rate limiting, and caching.
"""

import json
import time
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import os

from ..config import Config, AnomalyCodes
from ..logging_utils import get_logger

logger = get_logger(__name__)

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI package not available. Install with: pip install openai")


@dataclass
class LLMResponse:
    """Response from LLM API call."""
    
    content: str
    model: str
    tokens_used: int
    cost_estimate: float
    latency_ms: int
    success: bool
    error: Optional[str] = None


class LLMClient:
    """Client for calling LLM APIs with retry logic and caching."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logger
        
        # API configuration
        self.api_key = config.llm_api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = config.llm_base_url
        self.model = config.llm_model
        self.temperature = config.llm_temperature
        self.max_tokens = config.llm_max_tokens
        self.timeout = config.llm_timeout
        self.max_retries = config.llm_max_retries
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms between requests
        
        # Simple in-memory cache
        self.cache: Dict[str, LLMResponse] = {}
        self.cache_enabled = getattr(config, 'llm_cache_enabled', True)
        
        # Initialize client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the LLM client."""
        if not OPENAI_AVAILABLE:
            raise ImportError("OpenAI package required. Install with: pip install openai")
        
        if not self.api_key:
            raise ValueError("LLM API key not configured. Set OPENAI_API_KEY environment variable")
        
        # Initialize OpenAI client
        client_kwargs = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        
        self.client = openai.OpenAI(**client_kwargs)
        
        self.logger.info(f"Initialized LLM client with model: {self.model}")
    
    def extract_osig(self, context_bundle: Dict[str, Any]) -> LLMResponse:
        """
        Extract OSig from context bundle using LLM.
        
        Args:
            context_bundle: Context pack bundle from Step 4
            
        Returns:
            LLMResponse with OSig JSON or error
        """
        # Create cache key
        cache_key = self._get_cache_key(context_bundle)
        
        # Check cache first
        if self.cache_enabled and cache_key in self.cache:
            self.logger.debug("Using cached LLM response")
            return self.cache[cache_key]
        
        # Rate limiting
        self._rate_limit()
        
        # Build prompt
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(context_bundle)
        
        # Make API call with retries
        response = self._call_llm_with_retries(system_prompt, user_prompt)
        
        # Cache successful responses
        if self.cache_enabled and response.success:
            self.cache[cache_key] = response
        
        return response
    
    def _build_system_prompt(self) -> str:
        """Build the system prompt for OSig extraction."""
        return """You are an OSig (Operational Signature) extractor. Your job is to analyze code context and extract structured operational signatures.

RULES:
1. Only extract operations you can prove from the provided code citations
2. Always return valid JSON matching the exact schema provided
3. If uncertain about any field, set lower confidence and add anomaly codes
4. Summaries must be 1-2 lines starting with an action verb
5. Citations must point to exact file:line spans that prove your extraction
6. Data atoms should be domain entities (userId, orderId, email, etc.)
7. Joins should capture relationships for later OSig stitching

CONFIDENCE GUIDELINES:
- 0.9-1.0: Completely certain from literal code
- 0.7-0.9: High confidence with minor inference
- 0.5-0.7: Medium confidence, some uncertainty
- 0.3-0.5: Low confidence, significant inference
- 0.0-0.3: Very uncertain, mostly guesswork

ANOMALY CODES (use when uncertain):
- INFERRED_FIELD: Field value inferred, not literal
- MISSING_CITATION: Cannot cite specific code for claim
- DYNAMIC_VALUE: Value is dynamic/computed at runtime
- INCOMPLETE_CONTEXT: Insufficient context to be certain
- FRAMEWORK_ASSUMPTION: Assuming framework behavior

OUTPUT FORMAT:
Return ONLY valid JSON matching this schema:
{
  "kind": "string (http_response, db_write, external_call, etc.)",
  "fields": {"method": "GET", "path": "/users", "statuses": [200, 404]},
  "data_atoms": ["userId", "email"],
  "joins": {"path_family": "/users", "tables": ["user"]},
  "summary": "Gets user information by ID from the database",
  "citations": [{"file": "app.py", "start": 25, "end": 30, "note": "route handler"}],
  "llm_confidence": 0.85,
  "anomalies": ["INFERRED_FIELD"],
  "hypothesis": false
}"""
    
    def _build_user_prompt(self, context_bundle: Dict[str, Any]) -> str:
        """Build the user prompt with context bundle."""
        return f"""Extract an OSig from this code context:

CONTEXT BUNDLE:
{json.dumps(context_bundle, indent=2)}

INSTRUCTIONS:
1. Analyze the anchor, code snippet, and context
2. Extract a complete OSig with all fields filled
3. Provide citations for every claim you make
4. Set appropriate confidence based on evidence quality
5. Return ONLY the JSON object, no other text

JSON OUTPUT:"""
    
    def _call_llm_with_retries(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Call LLM with retry logic."""
        start_time = time.time()
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.timeout
                )
                
                # Extract response content
                content = response.choices[0].message.content.strip()
                
                # Calculate metrics
                latency_ms = int((time.time() - start_time) * 1000)
                tokens_used = response.usage.total_tokens if response.usage else 0
                cost_estimate = self._estimate_cost(tokens_used)
                
                return LLMResponse(
                    content=content,
                    model=self.model,
                    tokens_used=tokens_used,
                    cost_estimate=cost_estimate,
                    latency_ms=latency_ms,
                    success=True
                )
                
            except openai.RateLimitError as e:
                wait_time = min(2 ** attempt, 60)  # Exponential backoff, max 60s
                self.logger.warning(f"Rate limit hit, waiting {wait_time}s (attempt {attempt + 1})")
                time.sleep(wait_time)
                continue
                
            except openai.APITimeoutError as e:
                self.logger.warning(f"API timeout on attempt {attempt + 1}: {e}")
                if attempt == self.max_retries:
                    break
                time.sleep(1)
                continue
                
            except Exception as e:
                self.logger.error(f"LLM API error on attempt {attempt + 1}: {e}")
                if attempt == self.max_retries:
                    break
                time.sleep(1)
                continue
        
        # All retries failed
        latency_ms = int((time.time() - start_time) * 1000)
        return LLMResponse(
            content="",
            model=self.model,
            tokens_used=0,
            cost_estimate=0.0,
            latency_ms=latency_ms,
            success=False,
            error="Max retries exceeded"
        )
    
    def _rate_limit(self):
        """Simple rate limiting."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def _get_cache_key(self, context_bundle: Dict[str, Any]) -> str:
        """Generate cache key for context bundle."""
        # Create a hash of the bundle content
        bundle_str = json.dumps(context_bundle, sort_keys=True)
        return hashlib.md5(bundle_str.encode()).hexdigest()
    
    def _estimate_cost(self, tokens: int) -> float:
        """Estimate API cost based on token usage."""
        # Rough cost estimates (as of 2024, will need updating)
        cost_per_1k_tokens = {
            "gpt-4": 0.03,
            "gpt-4-turbo": 0.01,
            "gpt-3.5-turbo": 0.002,
        }
        
        base_model = self.model.split('-')[0] + '-' + self.model.split('-')[1] if '-' in self.model else self.model
        rate = cost_per_1k_tokens.get(base_model, 0.01)  # Default rate
        
        return (tokens / 1000.0) * rate
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "cache_size": len(self.cache),
            "cache_enabled": self.cache_enabled
        }
    
    def clear_cache(self):
        """Clear the response cache."""
        self.cache.clear()
        self.logger.info("LLM response cache cleared")


# Convenience function for testing
def test_llm_connection(config: Optional[Config] = None) -> bool:
    """Test LLM connection and return True if successful."""
    if config is None:
        config = Config()
    
    try:
        client = LLMClient(config)
        
        # Simple test prompt
        test_bundle = {
            "anchor": {"kind": "test", "resolved_fields": {}},
            "file_header": {"imports": []},
            "span_snippet": ["1| # test"],
            "neighbor_facts": [],
            "cfg_outcomes": [],
            "dfg_bindings": {},
            "framework_hints": {"lang": "python", "framework": "test"}
        }
        
        response = client.extract_osig(test_bundle)
        return response.success
        
    except Exception as e:
        logger.error(f"LLM connection test failed: {e}")
        return False
