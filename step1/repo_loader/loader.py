"""
Repository Loader Module
Handles repository ingestion, file discovery, and language detection
Part of Step 1: UCG Pipeline
"""

import os
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FileInfo:
    """Metadata for a single source file"""
    id: str                # Unique identifier (hash of path)
    path: str              # Relative path from repo root
    absolute_path: str     # Absolute path for reading
    language: str          # Detected programming language
    size: int              # File size in bytes
    hash: str              # Content hash for caching
    status: str = "ready"  # ready, too_large, error
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return asdict(self)

@dataclass
class RepoManifest:
    """Complete repository manifest with all discovered files"""
    root_path: str
    files: List[FileInfo]
    total_size: int
    language_counts: Dict[str, int]
    skipped_files: List[Dict[str, str]]  # Path and reason
    timestamp: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'root_path': self.root_path,
            'files': [f.to_dict() for f in self.files],
            'total_size': self.total_size,
            'language_counts': self.language_counts,
            'skipped_files': self.skipped_files,
            'timestamp': self.timestamp,
            'summary': {
                'total_files': len(self.files),
                'total_skipped': len(self.skipped_files),
                'languages': self.language_counts
            }
        }
    
    def save(self, output_path: str):
        """Save manifest to JSON file"""
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, manifest_path: str) -> 'RepoManifest':
        """Load manifest from JSON file"""
        with open(manifest_path, 'r') as f:
            data = json.load(f)
        
        files = [FileInfo(**f) for f in data['files']]
        return cls(
            root_path=data['root_path'],
            files=files,
            total_size=data['total_size'],
            language_counts=data['language_counts'],
            skipped_files=data['skipped_files'],
            timestamp=data['timestamp']
        )


class RepoLoader:
    """
    Repository loader that discovers and catalogs source files.
    Handles file discovery, language detection, and manifest generation.
    """
    
    # Directories to ignore during traversal
    IGNORE_DIRS = {
        # Version control
        '.git', '.svn', '.hg', '.bzr',
        # Python
        '__pycache__', '.pytest_cache', '.mypy_cache', '.tox',
        'venv', '.venv', 'env', '.env', 'virtualenv',
        # JavaScript/Node
        'node_modules', '.npm', '.yarn',
        # Build outputs
        'dist', 'build', 'out', 'target', 'bin',
        # IDE
        '.idea', '.vscode', '.vs',
        # Testing/Coverage
        'coverage', '.nyc_output', 'htmlcov',
        # Next.js
        '.next', '.vercel',
        # Other
        'tmp', 'temp', 'cache', 'logs'
    }
    
    # File extensions to ignore
    IGNORE_EXTENSIONS = {
        # Compiled
        '.pyc', '.pyo', '.pyd', '.so', '.dylib', '.dll', '.exe', '.o',
        # Archives
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
        # Media
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
        '.mp3', '.mp4', '.avi', '.mov', '.wav',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Data
        '.db', '.sqlite', '.sqlite3',
        # Lock files
        '.lock',
        # Other
        '.DS_Store', '.env', '.env.local'
    }
    
    # Language detection mapping
    LANGUAGE_MAP = {
        # Python
        '.py': 'python',
        '.pyi': 'python',
        '.pyx': 'python',
        # JavaScript
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        # TypeScript
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.d.ts': 'typescript'
    }
    
    # Maximum file size (1MB default)
    MAX_FILE_SIZE = 1024 * 1024
    
    def __init__(self, repo_path: str, max_file_size: int = None):
        """
        Initialize repository loader.
        
        Args:
            repo_path: Path to repository root
            max_file_size: Maximum file size in bytes (default 1MB)
        """
        self.repo_path = Path(repo_path).resolve()
        
        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
        
        if not self.repo_path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {repo_path}")
        
        if max_file_size:
            self.MAX_FILE_SIZE = max_file_size
        
        logger.info(f"Initialized RepoLoader for: {self.repo_path}")
    
    def scan(self) -> RepoManifest:
        """
        Scan repository and build complete manifest.
        
        Returns:
            RepoManifest containing all discovered files and metadata
        """
        logger.info(f"Starting repository scan: {self.repo_path}")
        
        files = []
        skipped_files = []
        total_size = 0
        language_counts = {}
        
        # Walk through repository
        for file_path in self._walk_repository():
            try:
                # Get file stats
                stat = file_path.stat()
                size = stat.st_size
                
                # Check file size
                if size > self.MAX_FILE_SIZE:
                    skipped_files.append({
                        'path': str(file_path.relative_to(self.repo_path)),
                        'reason': f'File too large ({size} bytes)'
                    })
                    continue
                
                # Detect language
                language = self._detect_language(file_path)
                if not language:
                    # Only skip if it's not a potential source file
                    if self._is_potential_source_file(file_path):
                        skipped_files.append({
                            'path': str(file_path.relative_to(self.repo_path)),
                            'reason': 'Unsupported language'
                        })
                    continue
                
                # Calculate file hash
                file_hash = self._calculate_file_hash(file_path)
                
                # Create file info
                relative_path = str(file_path.relative_to(self.repo_path))
                file_id = self._generate_file_id(relative_path)
                
                file_info = FileInfo(
                    id=file_id,
                    path=relative_path,
                    absolute_path=str(file_path),
                    language=language,
                    size=size,
                    hash=file_hash,
                    status="ready"
                )
                
                files.append(file_info)
                total_size += size
                language_counts[language] = language_counts.get(language, 0) + 1
                
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
                skipped_files.append({
                    'path': str(file_path.relative_to(self.repo_path)),
                    'reason': f'Error: {str(e)}'
                })
        
        # Sort files for deterministic processing
        files.sort(key=lambda f: f.path)
        
        # Create manifest
        from datetime import datetime
        manifest = RepoManifest(
            root_path=str(self.repo_path),
            files=files,
            total_size=total_size,
            language_counts=language_counts,
            skipped_files=skipped_files,
            timestamp=datetime.now().isoformat()
        )
        
        logger.info(f"Scan complete: {len(files)} files found, {len(skipped_files)} skipped")
        logger.info(f"Languages: {language_counts}")
        
        return manifest
    
    def _walk_repository(self):
        """
        Walk repository directory tree, yielding valid file paths.
        Respects ignore patterns and follows file symlinks (not directory symlinks).
        """
        for root, dirs, files in os.walk(self.repo_path, followlinks=False):
            root_path = Path(root)
            
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            
            # Sort for deterministic order
            dirs.sort()
            files.sort()
            
            for file_name in files:
                file_path = root_path / file_name
                
                # Skip if extension is ignored
                if file_path.suffix.lower() in self.IGNORE_EXTENSIONS:
                    continue
                
                # Skip if filename starts with dot (hidden files)
                if file_name.startswith('.') and file_name != '.gitignore':
                    continue
                
                # Handle symlinks
                if file_path.is_symlink():
                    # Follow file symlinks but not directory symlinks
                    try:
                        resolved = file_path.resolve()
                        if resolved.is_file():
                            yield resolved
                    except Exception:
                        continue
                else:
                    yield file_path
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """
        Detect programming language from file extension.
        
        Args:
            file_path: Path to file
            
        Returns:
            Language string or None if unsupported
        """
        suffix = file_path.suffix.lower()
        return self.LANGUAGE_MAP.get(suffix)
    
    def _is_potential_source_file(self, file_path: Path) -> bool:
        """
        Check if file might be source code (for logging purposes).
        """
        # Common source file patterns that we might want to support later
        potential_extensions = {'.rb', '.go', '.java', '.c', '.cpp', '.rs', '.php'}
        return file_path.suffix.lower() in potential_extensions
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of file contents.
        Used for caching and change detection.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hex digest of file hash
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def _generate_file_id(self, relative_path: str) -> str:
        """
        Generate unique ID for file based on its path.
        
        Args:
            relative_path: Relative path from repo root
            
        Returns:
            Short unique identifier
        """
        # Use MD5 for speed (this is just an ID, not security)
        return hashlib.md5(relative_path.encode()).hexdigest()[:12]


# Anomaly tracking for loader issues
class LoaderAnomaly:
    """Track anomalies during loading"""
    UNSUPPORTED_LANG = "unsupported_language"
    FILE_TOO_LARGE = "file_too_large"
    PERMISSION_ERROR = "permission_error"
    ENCODING_ERROR = "encoding_error"
    SYMLINK_ERROR = "symlink_error"


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python loader.py <repo_path>")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    loader = RepoLoader(repo_path)
    manifest = loader.scan()
    
    # Save manifest
    output_path = "repo_manifest.json"
    manifest.save(output_path)
    print(f"Manifest saved to {output_path}")
    
    # Print summary
    print(f"\nRepository: {manifest.root_path}")
    print(f"Total files: {len(manifest.files)}")
    print(f"Total size: {manifest.total_size / (1024*1024):.2f} MB")
    print(f"Languages: {manifest.language_counts}")
    print(f"Skipped: {len(manifest.skipped_files)} files")