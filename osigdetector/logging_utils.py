"""
Logging utilities for OSig Detector.
"""

import logging
from typing import Dict, Any, Optional


def get_logger(name: str):
    """Get a logger for the given module."""
    return logging.getLogger(name)


def log_pipeline_step(step: str, status: str, metadata: Optional[Dict[str, Any]] = None):
    """Log a pipeline step with structured data."""
    logger = get_logger("osig.pipeline")
    
    log_data = {
        "step": step,
        "status": status,
        "metadata": metadata or {}
    }
    
    level = logging.INFO if status in ["started", "completed"] else logging.ERROR
    logger.log(level, f"Pipeline {step}: {status}", extra=log_data)
