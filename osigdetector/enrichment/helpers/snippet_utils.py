"""
Code snippet extraction utilities for context packing.

Extracts focused code snippets around anchor provenance spans.
"""

import zipfile
from pathlib import Path
from typing import List, Optional

from ...config import Config, AnomalyCodes
from ...logging_utils import get_logger

logger = get_logger(__name__)


def extract_snippet(
    file_locator: str, 
    start_line: int, 
    end_line: int, 
    window: int = 10,
    highlight_anchor: bool = True
) -> List[str]:
    """
    Extract code snippet with ±N lines around anchor span.
    
    Args:
        file_locator: File path or locator (file:// or zip://)
        start_line: Anchor start line (1-based)
        end_line: Anchor end line (1-based) 
        window: Number of lines before/after to include
        highlight_anchor: Whether to mark anchor lines with >>
        
    Returns:
        List of formatted lines with line numbers
    """
    try:
        content = _read_file_content(file_locator)
        if not content:
            return [f"ERROR: Could not read {file_locator}"]
        
        lines = content.splitlines()
        total_lines = len(lines)
        
        # Calculate snippet bounds
        snippet_start = max(0, start_line - 1 - window)  # Convert to 0-based
        snippet_end = min(total_lines, end_line + window)
        
        snippet = []
        anchor_start_idx = start_line - 1  # 0-based
        anchor_end_idx = end_line - 1      # 0-based
        
        for i in range(snippet_start, snippet_end):
            line_num = i + 1
            line_content = lines[i] if i < total_lines else ""
            
            # Mark anchor lines if requested
            if highlight_anchor and anchor_start_idx <= i <= anchor_end_idx:
                prefix = ">> "
            else:
                prefix = "   "
            
            formatted_line = f"{prefix}{line_num:3d}| {line_content}"
            snippet.append(formatted_line)
        
        return snippet
        
    except Exception as e:
        logger.warning(f"Failed to extract snippet from {file_locator}: {e}")
        return [f"ERROR: Snippet extraction failed - {str(e)}"]


def extract_function_signature(
    file_locator: str,
    func_start_line: int,
    func_end_line: int
) -> Optional[str]:
    """
    Extract just the function signature (def/function declaration).
    
    Args:
        file_locator: File path or locator
        func_start_line: Function start line (1-based)
        func_end_line: Function end line (1-based)
        
    Returns:
        Function signature string or None
    """
    try:
        content = _read_file_content(file_locator)
        if not content:
            return None
        
        lines = content.splitlines()
        
        # Look for function signature in first few lines of function
        search_end = min(func_start_line + 3, func_end_line, len(lines))
        
        for i in range(func_start_line - 1, search_end):  # Convert to 0-based
            line = lines[i].strip()
            
            # Python function signatures
            if line.startswith('def ') and ':' in line:
                return line
            
            # JavaScript/TypeScript function signatures  
            if ('function ' in line or '=>' in line) and ('{' in line or ':' in line):
                return line
            
            # Java/C# method signatures
            if any(keyword in line for keyword in ['public ', 'private ', 'protected ']) and '(' in line:
                return line
        
        return None
        
    except Exception as e:
        logger.debug(f"Failed to extract function signature: {e}")
        return None


def get_file_imports(file_locator: str, max_imports: int = 10) -> List[str]:
    """
    Extract import statements from the beginning of a file.
    
    Args:
        file_locator: File path or locator
        max_imports: Maximum number of imports to return
        
    Returns:
        List of import statement strings
    """
    try:
        content = _read_file_content(file_locator)
        if not content:
            return []
        
        lines = content.splitlines()
        imports = []
        
        for line in lines[:50]:  # Only check first 50 lines
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Python imports
            if line.startswith('import ') or line.startswith('from '):
                imports.append(line)
            
            # JavaScript/TypeScript imports
            elif line.startswith('import ') or line.startswith('const ') and ' require(' in line:
                imports.append(line)
            
            # Java imports
            elif line.startswith('import ') and line.endswith(';'):
                imports.append(line)
            
            # Stop at first non-import code (rough heuristic)
            elif line and not line.startswith(('import', 'from', 'const', 'var', 'let')):
                if not any(keyword in line for keyword in ['package ', '@', '/**', '/*']):
                    break
            
            if len(imports) >= max_imports:
                break
        
        return imports[:max_imports]
        
    except Exception as e:
        logger.debug(f"Failed to extract imports: {e}")
        return []


def _read_file_content(file_locator: str) -> Optional[str]:
    """
    Read file content from various locator types.
    
    Args:
        file_locator: File path, file:// URL, or zip:// URL
        
    Returns:
        File content as string or None if failed
    """
    try:
        if file_locator.startswith("file://"):
            # File system path
            file_path = file_locator[7:]  # Remove file:// prefix
            return Path(file_path).read_text(encoding='utf-8', errors='replace')
        
        elif file_locator.startswith("zip://"):
            # Zip archive path: zip://path/to/archive.zip!/internal/path
            rest = file_locator[6:]  # Remove zip:// prefix
            if "!/" not in rest:
                return None
            
            zip_path, internal_path = rest.split("!/", 1)
            
            with zipfile.ZipFile(zip_path, 'r') as zf:
                with zf.open(internal_path, 'r') as f:
                    return f.read().decode('utf-8', errors='replace')
        
        else:
            # Assume it's a regular file path
            return Path(file_locator).read_text(encoding='utf-8', errors='replace')
    
    except Exception as e:
        logger.debug(f"Failed to read file content from {file_locator}: {e}")
        return None
