# Pre-commit Setup

Pre-commit hooks have been configured to automatically check code quality before each commit.

## Installed Hooks

The following checks run automatically on every commit:

1. **Ruff** - Fast Python linter (checks and fixes issues)
2. **Black** - Python code formatter
3. **Mypy** - Static type checker
4. **Pre-commit hooks** - Trailing whitespace, YAML checks, etc.

## Usage

### Automatic (on git commit)
Hooks run automatically when you commit:
```bash
git add <files>
git commit -m "Your message"
# Pre-commit hooks will run automatically
```

### Manual run on all files
```bash
pre-commit run --all-files
```

### Manual run on staged files
```bash
pre-commit run
```

### Run specific hook
```bash
pre-commit run ruff --all-files
pre-commit run black --all-files
pre-commit run mypy --all-files
```

### Skip hooks (not recommended)
```bash
git commit --no-verify -m "Skip hooks"
```

## Individual Tool Usage

### Ruff
```bash
# Check for issues
ruff check src/ tests/

# Fix auto-fixable issues
ruff check --fix src/ tests/

# Format code
ruff format src/ tests/
```

### Black
```bash
# Check formatting
black --check src/ tests/

# Format code
black src/ tests/
```

### Mypy
```bash
# Type check
mypy src/

# With ignore missing imports
mypy src/ --ignore-missing-imports
```

## Configuration Files

- `.pre-commit-config.yaml` - Pre-commit hook configuration
- `pyproject.toml` - Contains Ruff, Black, and Mypy configurations

## What Gets Checked

✅ Code formatting (Black)
✅ Import sorting (Ruff)
✅ Linting (Ruff) - unused imports, code quality, etc.
✅ Type hints (Mypy)
✅ Trailing whitespace
✅ End of file fixes
✅ YAML/TOML syntax

## Installation on New Clones

If you clone this repo elsewhere:
```bash
source .venv/bin/activate
pre-commit install
```
