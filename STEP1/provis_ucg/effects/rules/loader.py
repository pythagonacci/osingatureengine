# provis_ucg/effects/rules/loader.py
from __future__ import annotations

# -----------------------------------------------------------------------------
# Rule-pack loader/registry with YAML/JSON support, version pinning, hot reload
# -----------------------------------------------------------------------------
import json
import time
from pathlib import Path

from .schema import RulePack, validate_pack

try:
    import yaml  # type: ignore

    _HAS_YAML = True
except Exception:
    _HAS_YAML = False


class RuleRegistry:
    """
    Holds loaded packs by name (e.g., 'fastapi@0.115', 'express@4', 'core@1').
    Provides telemetry counters and simple timestamp-based hot reload.
    """

    def __init__(self) -> None:
        self._packs: dict[str, RulePack] = {}
        self._mtimes: dict[str, float] = {}
        self.telemetry: dict[str, int] = {}  # match counters by pack/rule id

    def load_path(self, path: str | Path) -> tuple[RulePack | None, list[str]]:
        p = Path(path)
        if not p.exists():
            return None, [f"Rule file not found: {p}"]
        try:
            txt = p.read_text(encoding="utf-8")
        except Exception as e:
            return None, [f"Failed to read rule file: {e}"]

        try:
            obj = (
                yaml.safe_load(txt)
                if _HAS_YAML and p.suffix.lower() in (".yml", ".yaml")
                else json.loads(txt)
            )
        except Exception as e:
            return None, [f"Failed to parse rule file: {e}"]

        try:
            pack = _decode_pack(obj)
        except Exception as e:
            return None, [f"Failed to decode RulePack: {e}"]

        ok, errs = validate_pack(pack)
        if not ok:
            return None, errs

        self._packs[pack.name] = pack
        try:
            self._mtimes[pack.name] = p.stat().st_mtime
        except Exception:
            self._mtimes[pack.name] = time.time()
        return pack, []

    def maybe_reload(self, name: str, file_path: str | Path) -> bool:
        """Reload if file mtime changed; return True if reloaded."""
        p = Path(file_path)
        if not p.exists():
            return False
        try:
            m = p.stat().st_mtime
        except Exception:
            return False
        if self._mtimes.get(name) and m <= self._mtimes[name]:
            return False
        pack, errs = self.load_path(p)
        return pack is not None and not errs

    def get(self, name: str) -> RulePack | None:
        return self._packs.get(name)

    def all(self) -> list[RulePack]:
        return list(self._packs.values())


def _decode_pack(obj: dict) -> RulePack:
    # lightweight dataclass reconstruction without pydantic
    from .schema import EffectRule, FieldSpec, Pattern

    rules = []
    for r in obj.get("rules", []):
        patterns = [Pattern(**p) for p in r.get("patterns", [])]
        fields = [FieldSpec(**f) for f in r.get("fields", [])]
        rules.append(
            EffectRule(
                id=r["id"],
                effect_kind=r["effect_kind"],
                provider=r["provider"],
                family=r.get("family", ""),
                patterns=patterns,
                fields=fields,
                confidence=r.get("confidence", 0.95),
                notes=r.get("notes"),
            )
        )
    pack = RulePack(
        name=obj["name"],
        version=obj.get("version", "1.0"),
        language=obj.get("language", "any"),
        rules=rules,
        requires=obj.get("requires", []),
        telemetry_tag=obj.get("telemetry_tag"),
    )
    return pack
