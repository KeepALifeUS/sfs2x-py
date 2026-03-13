# Contributing

## Setup

```bash
git clone https://github.com/KeepALifeUS/sfs2x-py.git
cd sfs2x-py
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/ -v
```

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting:

```bash
pip install ruff
ruff check src/ tests/
```

## Submitting changes

1. Fork the repo and create a feature branch
2. Make your changes
3. Ensure all tests pass and ruff reports no errors
4. Submit a pull request against `main`
