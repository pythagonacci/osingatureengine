from __future__ import annotations
import argparse
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .discovery import DiscoveryOptions, DiscoveryResult, discover_files
from .otel import init_tracing, get_tracer

def _default(o: Any) -> Any:
    # dataclasses (DiscoveredFile/Anomaly) → dict for JSON
    if hasattr(o, "__dict__"):
        return o.__dict__
    if hasattr(o, "value"):
        return getattr(o, "value")
    return str(o)

def run(repo_path: str, include_vendor=False, include_minified=False, include_generated=False) -> Dict[str, Any]:
    init_tracing("provis-ucg")
    tracer = get_tracer("provis-ucg.runner")

    options = DiscoveryOptions(
        include_vendor=include_vendor,
        include_minified=include_minified,
        include_generated=include_generated,
    )

    with tracer.start_as_current_span("discover"):
        result: DiscoveryResult = discover_files(repo_path, options=options)

    # Summarize for run report
    ts = datetime.now(timezone.utc).isoformat()
    report: Dict[str, Any] = {
        "ucg_step": "discovery",
        "repo_root": str(Path(repo_path).resolve()),
        "timestamp_utc": ts,
        "tallies": result.tallies,
        "anomalies": [asdict(a) | {"typ": a.typ.name, "severity": a.severity.value} for a in result.anomalies],
        "files": [asdict(f) | {"language": f.language.value} for f in result.files],
        "versions": {
            "schema_version": "v0",
            "ucg_version": "0.1.0",
        },
    }
    return report

def _write_report(report: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = f"run_report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path = out_dir / fname
    with path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path

def main() -> None:
    parser = argparse.ArgumentParser(description="Provis UCG — Step 1 runner (discovery only)")
    parser.add_argument("repo", help="Path to repository root")
    parser.add_argument("--include-vendor", action="store_true", help="Include vendor dirs (still flagged)")
    parser.add_argument("--include-minified", action="store_true", help="Include minified JS (still flagged)")
    parser.add_argument("--include-generated", action="store_true", help="Include generated files (still flagged)")
    parser.add_argument("--out", default="artifacts", help="Directory to write run report JSON")
    args = parser.parse_args()

    report = run(
        repo_path=args.repo,
        include_vendor=args.include_vendor,
        include_minified=args.include_minified,
        include_generated=args.include_generated,
    )
    out_path = _write_report(report, Path(args.out))
    print(f"Wrote run report → {out_path}")

if __name__ == "__main__":
    main()
