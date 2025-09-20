"""Test the effects rule packs can be loaded and used."""

from __future__ import annotations

from pathlib import Path

from provis_ucg.effects.detector import EffectDetector
from provis_ucg.effects.rules.loader import RuleRegistry
from provis_ucg.models import Language


def test_core_rule_pack_loads():
    """Test that the core rule pack loads without errors."""
    registry = RuleRegistry()
    rules_dir = Path(__file__).parent.parent / "provis_ucg" / "effects" / "rules"
    core_path = rules_dir / "core@1.yaml"

    assert core_path.exists(), f"Core rule pack not found at {core_path}"
    pack, errors = registry.load_path(str(core_path))

    assert not errors, f"Errors loading core pack: {errors}"
    assert pack is not None
    assert pack.name == "core@1"
    assert pack.version == "1.0"
    assert "core@1" in registry._packs


def test_fastapi_rule_pack_loads():
    """Test that the FastAPI rule pack loads with dependencies."""
    registry = RuleRegistry()
    rules_dir = Path(__file__).parent.parent / "provis_ucg" / "effects" / "rules"

    # Load core first (dependency)
    pack1, errors1 = registry.load_path(str(rules_dir / "core@1.yaml"))
    assert not errors1, f"Errors loading core: {errors1}"

    pack2, errors2 = registry.load_path(str(rules_dir / "fastapi@0.115.yaml"))
    assert not errors2, f"Errors loading FastAPI: {errors2}"

    assert "fastapi@0.115" in registry._packs
    fastapi_pack = registry._packs["fastapi@0.115"]
    assert fastapi_pack.name == "fastapi@0.115"
    assert fastapi_pack.language == "python"
    assert "core@1" in fastapi_pack.requires
    assert len(fastapi_pack.rules) == 3  # router.get, app.post, raw_sql


def test_express_rule_pack_loads():
    """Test that the Express rule pack loads correctly."""
    registry = RuleRegistry()
    rules_dir = Path(__file__).parent.parent / "provis_ucg" / "effects" / "rules"

    registry.load_path(str(rules_dir / "core@1.yaml"))
    registry.load_path(str(rules_dir / "express@4.yaml"))

    assert "express@4" in registry._packs
    express_pack = registry._packs["express@4"]
    assert express_pack.language == "javascript"
    assert len(express_pack.rules) == 1  # app.method with multiple patterns


def test_detector_creation():
    """Test that a detector can be created with loaded rule packs."""
    registry = RuleRegistry()
    rules_dir = Path(__file__).parent.parent / "provis_ucg" / "effects" / "rules"

    # Load a few rule packs
    registry.load_path(str(rules_dir / "core@1.yaml"))
    registry.load_path(str(rules_dir / "fastapi@0.115.yaml"))

    # Create detector
    detector = EffectDetector(registry)
    assert detector is not None

    # Test basic detection call (with empty data)
    result = detector.detect_effects(
        nodes=[],
        edges=[],
        language=Language.PYTHON,
        rule_pack_names=["core@1", "fastapi@0.115"],
    )

    # Should not crash and return valid result structure
    assert hasattr(result, "effects")
    assert hasattr(result, "anomalies")
    assert hasattr(result, "metrics")


def test_all_rule_packs_load():
    """Test that all provided rule packs can be loaded together."""
    registry = RuleRegistry()
    rules_dir = Path(__file__).parent.parent / "provis_ucg" / "effects" / "rules"

    rule_files = [
        "core@1.yaml",
        "fastapi@0.115.yaml",
        "express@4.yaml",
        "sequelize@6.yaml",
        "prisma@5.yaml",
    ]

    for rule_file in rule_files:
        rule_path = rules_dir / rule_file
        if rule_path.exists():
            registry.load_path(str(rule_path))

    # All should be loaded
    assert len(registry._packs) == len(rule_files)

    # Check specific properties
    assert registry._packs["core@1"].language == "any"
    assert registry._packs["fastapi@0.115"].telemetry_tag == "fastapi"
    assert registry._packs["express@4"].telemetry_tag == "express"
    assert registry._packs["sequelize@6"].telemetry_tag == "sequelize"
    assert registry._packs["prisma@5"].telemetry_tag == "prisma"
