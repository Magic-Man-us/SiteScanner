# Contributing

Thank you for helping improve SecSuite! This short guide gets you up and running quickly.

Developer quick-start
---------------------

1. Install `uv` (if you don't have it). Follow platform-specific instructions at https://docs.astral.sh/uv/.

2. Sync the development environment and install dev dependencies:

```bash
make install
```

3. Common tasks

- Run tests: `make test` or `./scripts/dev pytest`
- Run lint: `make lint` or `./scripts/dev ruff check .`
- Type check: `make type` or `./scripts/dev mypy src`
- Build docs: `make docs` or `./scripts/dev sphinx-build -b html docs docs/_build`

Pre-commit
----------

Install pre-commit hooks locally:

```bash
make precommit
```

Branching and PRs
------------------

- Create a branch for your feature/fix: `git checkout -b feature/thing`
- Run tests and linters locally before opening a PR.
- Open a PR against `main` and include a short description of the change and why.

Thank you! Keep changes small and focused and include tests for new behavior.
