PY=uv run
PKG=provis_ucg

.PHONY: setup fmt lint type test cov pin-grammars run
setup:
	uv sync --extra dev
	cd node_sidecar && npm i --no-audit --no-fund

fmt:
	$(PY) ruff check --fix .
	$(PY) isort .
	$(PY) black .

lint:
	$(PY) ruff check .

type:
	$(PY) mypy $(PKG)

test:
	$(PY) pytest

cov:
	$(PY) pytest --cov=$(PKG) --cov-report=term-missing

pin-grammars:
	$(PY) python scripts/pin_grammars.py

run:
	$(PY) python -m $(PKG).runner
