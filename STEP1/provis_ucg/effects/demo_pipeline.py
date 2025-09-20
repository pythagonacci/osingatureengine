#!/usr/bin/env python3
"""
Demonstration of how to use effects detection with rule packs in a pipeline.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Language
from .detector import EffectDetector
from .rules.loader import RuleRegistry


def demo_full_pipeline():
    """Demonstrate the complete effects detection pipeline."""
    print("🚀 Effects Detection Pipeline Demo")
    print("=" * 50)

    # 1. Load rule packs
    print("\n📦 Loading rule packs...")
    registry = RuleRegistry()
    rules_dir = Path(__file__).parent / "rules"

    rule_files = [
        "core@1.yaml",
        "fastapi@0.115.yaml",
        "express@4.yaml",
        "sequelize@6.yaml",
        "prisma@5.yaml",
    ]

    loaded_packs = []
    for rule_file in rule_files:
        rule_path = rules_dir / rule_file
        if rule_path.exists():
            pack, errors = registry.load_path(str(rule_path))
            if errors:
                print(f"❌ {rule_file}: {errors}")
            else:
                print(f"✅ {rule_file}: {len(pack.rules)} rules")
                loaded_packs.append(pack.name)
        else:
            print(f"⚠️  {rule_file}: not found")

    print(f"\n📊 Loaded {len(loaded_packs)} rule packs: {', '.join(loaded_packs)}")

    # 2. Create detector
    print("\n🔍 Creating effect detector...")
    detector = EffectDetector(registry)

    # 3. Example usage for different languages
    print("\n🐍 Python Example (FastAPI):")
    python_result = detector.detect_effects(
        nodes=[],  # Would be real UCG nodes from normalize/lift.py
        edges=[],  # Would be real UCG edges from normalize/lift.py
        language=Language.PYTHON,
        rule_pack_names=["core@1", "fastapi@0.115"],
    )
    print(f"   Effects: {len(python_result.effects)}")
    print(f"   Anomalies: {len(python_result.anomalies)}")
    print(f"   Metrics: {python_result.metrics}")

    print("\n🟨 JavaScript Example (Express + Sequelize):")
    js_result = detector.detect_effects(
        nodes=[],
        edges=[],
        language=Language.JAVASCRIPT,
        rule_pack_names=["core@1", "express@4", "sequelize@6"],
    )
    print(f"   Effects: {len(js_result.effects)}")
    print(f"   Anomalies: {len(js_result.anomalies)}")
    print(f"   Metrics: {js_result.metrics}")

    print("\n🔷 TypeScript Example (Prisma):")
    ts_result = detector.detect_effects(
        nodes=[],
        edges=[],
        language=Language.TYPESCRIPT,
        rule_pack_names=["core@1", "prisma@5"],
    )
    print(f"   Effects: {len(ts_result.effects)}")
    print(f"   Anomalies: {len(ts_result.anomalies)}")
    print(f"   Metrics: {ts_result.metrics}")

    print("\n✅ Pipeline demo complete!")
    print("\n💡 Integration example:")
    print(
        """
# In your main UCG pipeline:
from provis_ucg.effects.rules.loader import RuleRegistry
from provis_ucg.effects.detector import EffectDetector

# Load rule packs
registry = RuleRegistry()
for path in ["rules/core@1.yaml", "rules/fastapi@0.115.yaml"]:
    registry.load_path(path)

# Create detector  
detector = EffectDetector(registry)

# Run detection on UCG data
result = detector.detect_effects(
    nodes=lifted.nodes,     # from normalize/lift.py
    edges=lifted.edges,     # from normalize/lift.py  
    language=Language.PYTHON,
    rule_pack_names=["core@1", "fastapi@0.115"],
)

# Process results
for effect in result.effects:
    print(f"Effect: {effect.effect_kind} ({effect.provider}.{effect.family})")
    # Persist to DuckDB effects table with receipt_id, etc.
"""
    )


if __name__ == "__main__":
    demo_full_pipeline()
