# Effects Rule Packs

This directory contains YAML rule packs that define how to detect specific framework effects in code.

## Available Rule Packs

### Core
- **`core@1.yaml`** - Base rule pack with no rules, required by all others

### Web Frameworks
- **`fastapi@0.115.yaml`** - FastAPI HTTP routes and SQL execution (Python)
- **`express@4.yaml`** - Express.js HTTP routes (JavaScript)

### Database ORMs
- **`sequelize@6.yaml`** - Sequelize ORM operations (JavaScript)
- **`prisma@5.yaml`** - Prisma ORM operations (TypeScript)

## Rule Pack Structure

Each rule pack is a YAML file with:

```yaml
name: package@version
version: "1.0"
language: python|javascript|typescript|any
requires: ["dependency@1"]  # optional
telemetry_tag: framework_name  # optional
rules:
  - id: unique.rule.id
    effect_kind: http.route|db.sql|db.orm
    provider: framework_name
    family: component_type
    patterns:
      - language: python
        kind: call
        callee: "function.name"
        arg_count_min: 1
    fields:
      - name: method
        source: literal|arg
        value_expr: "GET"
        index: 0  # for arg source
```

## Usage

```python
from provis_ucg.effects.rules.loader import RuleRegistry
from provis_ucg.effects.detector import EffectDetector

# Load rule packs
registry = RuleRegistry()
registry.load_path("rules/core@1.yaml")
registry.load_path("rules/fastapi@0.115.yaml")

# Create detector
detector = EffectDetector(registry)

# Run detection
result = detector.detect_effects(
    nodes=ucg_nodes,
    edges=ucg_edges, 
    language=Language.PYTHON,
    rule_pack_names=["core@1", "fastapi@0.115"],
)

# Process results
for effect in result.effects:
    print(f"Found {effect.effect_kind}: {effect.provider}.{effect.family}")
```

## Adding New Rule Packs

1. Create a new YAML file following the structure above
2. Add dependency on `core@1` in the `requires` field
3. Define patterns that match your framework's call signatures
4. Specify fields to extract from matched calls
5. Test with the provided test suite

## Field Sources

- **`literal`** - Static value from `value_expr`
- **`arg`** - Extract from function argument at `index`
- **`kw`** - Extract from keyword argument (future)
- **`inferred`** - Let the engine infer from context (future)
