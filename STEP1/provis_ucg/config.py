DEFAULT_VENDOR_DIRS = {
    "node_modules",
    "vendor",
    "third_party",
    ".venv",
    "site-packages",
    "dist",
    "build",
    ".next",
    ".cache",
    ".turbo",
    ".parcel-cache",
}
DEFAULT_DENY_GLOBS = {"**/.git/**", "**/.hg/**", "**/.svn/**", "**/*.lock"}
DEFAULT_ALLOW_GLOBS = {"**"}
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10MB
