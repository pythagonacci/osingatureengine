# provis_ucg/obs/report.py
from __future__ import annotations
# -----------------------------------------------------------------------------
# Run report (JSON) + SARIF export from DuckDB for Step-1
# -----------------------------------------------------------------------------

import json
from typing import Any, Dict, List, Tuple, Optional
import duckdb
from datetime import datetime

SEVERITY_ORDER = {"ERROR": 3, "WARN": 2, "INFO": 1}

# ------------------------------ Run report ------------------------------------

def compute_run_report(
    con: duckdb.DuckDBPyConnection, *, repo_id: str, run_id: str
) -> Dict[str, Any]:
    """
    Aggregate key metrics and anomaly histogram for a single run.
    Returns a JSON-serializable dict.
    """
    # Files seen/supported (from files table)
    files_total = con.execute(
        "SELECT COUNT(*) FROM files WHERE repo_id=? AND run_id=?", [repo_id, run_id]
    ).fetchone()[0]

    # Metrics aggregates (p50/p95 by parse_time_ms)
    metrics_rows = con.execute(
        """
        SELECT parse_time_ms FROM metrics
        WHERE repo_id=? AND run_id=? AND parse_time_ms IS NOT NULL
        """,
        [repo_id, run_id],
    ).fetchall()
    times = sorted([r[0] for r in metrics_rows]) if metrics_rows else []
    p50 = _percentile(times, 50)
    p95 = _percentile(times, 95)

    node_sum = con.execute(
        "SELECT COALESCE(SUM(node_count),0) FROM metrics WHERE repo_id=? AND run_id=?",
        [repo_id, run_id],
    ).fetchone()[0]

    # Cache hit ratio: count by cache_state
    cache_counts = dict(
        con.execute(
            """
            SELECT COALESCE(cache_state,'unknown') AS cs, COUNT(*)
            FROM metrics WHERE repo_id=? AND run_id=?
            GROUP BY cs
            """,
            [repo_id, run_id],
        ).fetchall()
    )
    cache_total = sum(cache_counts.values()) or 1
    cache_hit = cache_counts.get("hit", 0) / cache_total

    # Effects by kind
    effects_by_kind = dict(
        con.execute(
            """
            SELECT kind, COUNT(*) FROM effects
            WHERE repo_id=? AND run_id=? GROUP BY kind
            """,
            [repo_id, run_id],
        ).fetchall()
    )

    # Anomaly histogram
    anomalies = con.execute(
        """
        SELECT anomaly_type, severity, COUNT(*)
        FROM anomalies
        WHERE repo_id=? AND run_id=?
        GROUP BY anomaly_type, severity
        """,
        [repo_id, run_id],
    ).fetchall()

    anom_hist: Dict[str, Dict[str, int]] = {}
    for typ, sev, cnt in anomalies:
        anom_hist.setdefault(typ, {})[sev] = int(cnt)

    # Languages processed
    languages = [r[0] for r in con.execute(
        "SELECT DISTINCT language FROM files WHERE repo_id=? AND run_id=?",
        [repo_id, run_id],
    ).fetchall()]

    return {
        "repo_id": repo_id,
        "run_id": run_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files_total": files_total,
        "node_count_total": int(node_sum),
        "parse_time_ms": {
            "p50": p50,
            "p95": p95,
        },
        "cache": {
            "hit_ratio": round(cache_hit, 4),
            "by_state": cache_counts,
        },
        "effects_by_kind": effects_by_kind,
        "anomalies": anom_hist,
        "languages": languages,
    }

def save_run_report_json(report: Dict[str, Any], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

# ------------------------------ SARIF export ----------------------------------

def export_anomalies_sarif(
    con: duckdb.DuckDBPyConnection, *,
    repo_id: str,
    run_id: str,
    out_path: str,
    severities: Tuple[str, ...] = ("ERROR",),
) -> None:
    """
    Emit a minimal SARIF v2.1.0 file for selected severities (default: ERROR).
    Maps each anomaly to a result; file region is best-effort from stored spans.
    """
    rows = con.execute(
        """
        SELECT path, blob_sha256, anomaly_type, severity, reason_detail, spans, ts
        FROM anomalies
        WHERE repo_id=? AND run_id=? AND severity IN ({})
        ORDER BY ts ASC
        """.format(",".join(["?"] * len(severities))),
        [repo_id, run_id, *severities],
    ).fetchall()

    results = []
    rules_seen = set()
    for path, blob, typ, sev, detail, spans, ts in rows:
        rule_id = f"UCG.{typ}"
        rules_seen.add(rule_id)

        region = _first_region(spans)
        result = {
            "ruleId": rule_id,
            "level": _sarif_level(sev),
            "message": {"text": f"{typ}: {detail or ''}".strip()},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": region
                }
            }],
            "properties": {
                "blob_sha256": blob,
                "timestamp": str(ts),
            }
        }
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Provis UCG",
                    "informationUri": "https://example.invalid/provis-ucg",
                    "rules": [{"id": r} for r in sorted(rules_seen)],
                }
            },
            "results": results
        }]
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)

# ------------------------------- Helpers --------------------------------------

def _percentile(sorted_vals: List[int], p: int) -> Optional[int]:
    if not sorted_vals:
        return None
    if p <= 0: return sorted_vals[0]
    if p >= 100: return sorted_vals[-1]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return int(d0 + d1)

def _first_region(spans_json: Any) -> Dict[str, int]:
    """
    Best-effort SARIF region from spans JSON.
    """
    try:
        if isinstance(spans_json, str):
            import json as _json
            spans = _json.loads(spans_json)
        else:
            spans = spans_json
        if not spans:
            return {}
        sp = spans[0]
        line = int(sp.get("line_start", 1))
        col  = int(sp.get("col_start", 1))
        end_line = int(sp.get("line_end", line))
        end_col  = int(sp.get("col_end", col))
        return {
            "startLine": max(1, line),
            "startColumn": max(1, col + 1),
            "endLine": max(1, end_line),
            "endColumn": max(1, end_col + 1),
        }
    except Exception:
        return {}

def _sarif_level(sev: str) -> str:
    sev = (sev or "").upper()
    if sev == "ERROR": return "error"
    if sev == "WARN": return "warning"
    return "note"
