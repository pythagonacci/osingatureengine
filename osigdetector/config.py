"""
Configuration management for OSig Detector.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Config:
    """Main configuration class for OSig Detector."""
    
    # Resolution settings
    max_resolution_depth: int = 10
    resolve_environment_vars: bool = True
    resolve_config_files: bool = True
    constant_propagation_limit: int = 1000
    
    # LLM settings
    llm_provider: str = "openai"
    llm_model: str = "gpt-4"
    llm_api_key: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: int = 30
    llm_max_retries: int = 3
    llm_temperature: float = 0.1
    llm_max_tokens: int = 2048
    
    # General settings
    debug: bool = False
    verbose: bool = False
    max_workers: int = 4
    
    # File processing
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    supported_extensions: List[str] = None
    
    def __post_init__(self):
        if self.supported_extensions is None:
            self.supported_extensions = [
                ".py", ".js", ".ts", ".java", ".go", ".cpp", ".c", ".cs", ".rb", ".php"
            ]


class AnomalyCodes:
    """Standard anomaly codes used throughout the pipeline."""
    
    # Ingestion anomalies (1000-1999)
    PARSE_ERROR = 1001
    UNSUPPORTED_LANGUAGE = 1002
    FILE_TOO_LARGE = 1003
    ENCODING_ERROR = 1004
    UCG_BUILD_FAILED = 1005
    
    # Mining anomalies (2000-2999) 
    NO_CANDIDATES_FOUND = 2001
    PATTERN_MATCH_FAILED = 2002
    FRAMEWORK_NOT_DETECTED = 2003
    RULE_EXECUTION_ERROR = 2004
    
    # Resolution anomalies (3000-3999)
    CONSTANT_UNRESOLVED = 3001
    STRING_INTERPOLATION_FAILED = 3002
    ENVIRONMENT_VAR_MISSING = 3003
    CONFIG_FILE_NOT_FOUND = 3004
    CIRCULAR_DEPENDENCY = 3005
    
    # Enrichment anomalies (4000-4999)
    LLM_API_ERROR = 4001
    CONTEXT_TOO_LARGE = 4002
    PROMPT_TEMPLATE_ERROR = 4003
    SCHEMA_VALIDATION_FAILED = 4004
    EXTRACTION_TIMEOUT = 4005
