SHELL := /bin/bash
.PHONY: help install sync test lint type format docs precommit clean

help:
	@echo "Available targets:"
	@echo "  make install    # install uv (if missing) and sync dependencies"
	@echo "  make sync       # uv sync --all-extras"
	@echo "  make test       # run tests with coverage"
	@echo "  make lint       # run ruff"
	@echo "  make type       # run mypy"
	@echo "  make format     # format with ruff"
	@echo "  make docs       # build Sphinx docs"
	@echo "  make precommit  # install pre-commit hooks"
	@echo "  make clean      # remove build artifacts"

install:
	@command -v uv >/dev/null 2>&1 || \
	  { echo "uv not found. Please install uv in your Python environment. Example:"; \
	    echo "  python -m pip install --upgrade pip && python -m pip install uv"; exit 1; }
	uv sync --all-extras

sync:
	uv sync --all-extras

test:
	uv run pytest --cov

lint:
	uv run ruff check .

type:
	uv run mypy src --ignore-missing-imports

format:
	uv run ruff format .

docs:
	uv run sphinx-build -b html docs docs/_build

precommit:
	uv run pre-commit install

clean:
	rm -rf .venv build dist htmlcov coverage.xml coverage.json docs/_build
