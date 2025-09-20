#!/usr/bin/env python3
"""
Example usage of the effects detection system with rule packs.

This demonstrates how to:
1. Load rule packs from YAML files
2. Create an effect detector
3. Run detection on UCG nodes and edges
4. Process the results
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..models import Language
from .rules.loader import RuleRegistry
from .detector import EffectDetector

def load_core_rule_packs() -> RuleRegistry:
    """Load the core rule packs for common frameworks."""
    registry = RuleRegistry()
    
    # Path to rules directory
    rules_dir = Path(__file__).parent / "rules"
    
    # Load rule packs in dependency order
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
            print(f"Loading rule pack: {rule_file}")
            registry.load_path(str(rule_path))
        else:
            print(f"Warning: Rule pack not found: {rule_file}")
    
    return registry

def detect_python_effects(nodes, edges, lifted_result=None):
    """Example: Detect effects in Python code (FastAPI)."""
    registry = load_core_rule_packs()
    detector = EffectDetector(registry)
    
    result = detector.detect_effects(
        nodes=nodes,
        edges=edges, 
        language=Language.PYTHON,
        rule_pack_names=["core@1", "fastapi@0.115"],
    )
    
    print(f"Detected {len(result.effects)} Python effects")
    for effect in result.effects:
        print(f"  - {effect.effect_kind}: {effect.provider}.{effect.family}")
        
    return result

def detect_javascript_effects(nodes, edges, lifted_result=None):
    """Example: Detect effects in JavaScript code (Express + Sequelize)."""
    registry = load_core_rule_packs()
    detector = EffectDetector(registry)
    
    result = detector.detect_effects(
        nodes=nodes,
        edges=edges,
        language=Language.JAVASCRIPT, 
        rule_pack_names=["core@1", "express@4", "sequelize@6"],
    )
    
    print(f"Detected {len(result.effects)} JavaScript effects")
    for effect in result.effects:
        print(f"  - {effect.effect_kind}: {effect.provider}.{effect.family}")
        
    return result

def detect_typescript_effects(nodes, edges, lifted_result=None):
    """Example: Detect effects in TypeScript code (Prisma).""" 
    registry = load_core_rule_packs()
    detector = EffectDetector(registry)
    
    result = detector.detect_effects(
        nodes=nodes,
        edges=edges,
        language=Language.TYPESCRIPT,
        rule_pack_names=["core@1", "prisma@5"],
    )
    
    print(f"Detected {len(result.effects)} TypeScript effects")
    for effect in result.effects:
        print(f"  - {effect.effect_kind}: {effect.provider}.{effect.family}")
        
    return result

def main():
    """Example main function showing the full pipeline integration."""
    print("Effects Detection Example")
    print("=" * 40)
    
    # This would typically come from your UCG lifting step
    # For now, just demonstrate the API
    nodes = []  # List[UCGNode] from normalize/lift.py
    edges = []  # List[UCGEdge] from normalize/lift.py
    
    print("\n1. Loading rule registry...")
    registry = load_core_rule_packs()
    print(f"Loaded {len(registry.rule_packs)} rule packs")
    
    print("\n2. Creating detector...")
    detector = EffectDetector(registry)
    
    print("\n3. Example detection calls:")
    print("   (These would use real UCG nodes/edges from your pipeline)")
    
    # Example calls - in real usage, you'd have actual nodes/edges
    # detect_python_effects(nodes, edges)
    # detect_javascript_effects(nodes, edges) 
    # detect_typescript_effects(nodes, edges)
    
    print("\n✅ Setup complete! Ready for real UCG data.")

if __name__ == "__main__":
    main()
