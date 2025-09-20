from __future__ import annotations

from pathlib import Path

from provis_ucg.discovery import DiscoveryOptions, discover_files
from provis_ucg.models import AnomalyType, Language


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_discovery_supports_basic_langs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "src" / "a.py", "print('hi')\n")
    _write(repo / "src" / "b.ts", "export const x = 1;\n")
    _write(repo / "src" / "c.jsx", "export default function C(){return <div/>}\n")
    (repo / "node_modules").mkdir()
    _write(repo / "node_modules" / "lib.js", "console.log('vendor');\n")

    out = discover_files(repo)
    rels = sorted(f.rel_path for f in out.files)
    langs = {f.rel_path: f.language for f in out.files}
    assert rels == ["src/a.py", "src/b.ts", "src/c.jsx"]
    assert langs["src/a.py"] == Language.PYTHON
    assert langs["src/b.ts"] == Language.TYPESCRIPT
    assert langs["src/c.jsx"] == Language.JAVASCRIPT
    # vendor skipped + anomaly recorded
    assert any(a.typ == AnomalyType.VENDORED_CODE for a in out.anomalies)


def test_minified_heuristic_skips_by_default(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    # synthetically long line to trigger heuristic
    _write(repo / "web" / "bundle.min.js", "var a=" + "1" * 5000 + ";\n")
    out = discover_files(repo)
    assert out.tallies["skipped_minified"] == 1
    assert any(a.typ == AnomalyType.MINIFIED_JS for a in out.anomalies)


def test_generated_header_skips_by_default(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    _write(repo / "gen" / "auto.ts", "// @generated\nexport const z=1;\n")
    out = discover_files(repo)
    assert out.tallies["skipped_generated"] == 1
    assert any(a.typ == AnomalyType.GENERATED_CODE for a in out.anomalies)


def test_globs_allow_and_deny(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    _write(repo / "keep" / "ok.py", "print(1)\n")
    _write(repo / "drop" / "bad.py", "print(0)\n")
    opts = DiscoveryOptions(
        allow_globs=("keep/**",),
        deny_globs=("drop/**",),
    )
    out = discover_files(repo, options=opts)
    rels = [f.rel_path for f in out.files]
    assert rels == ["keep/ok.py"]
    assert out.tallies["skipped_not_allowed"] >= 1 or out.tallies["skipped_deny_glob"] >= 1


def test_symlink_out_of_root_is_flagged(tmp_path: Path) -> None:
    # create two dirs; symlink from repo to outside
    repo = tmp_path / "repo"
    other = tmp_path / "outside"
    other.mkdir(parents=True)
    repo.mkdir(parents=True)
    target = other / "x.py"
    _write(target, "print('x')\n")
    link = repo / "x.py"
    link.symlink_to(target)
    out = discover_files(repo)
    assert out.tallies["symlink_out_of_root"] == 1
    assert not out.files  # the out-of-root file is not included
