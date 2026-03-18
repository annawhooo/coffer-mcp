# Contributing to Krypteia MCP

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/annawhooo/krypteia-mcp.git
cd krypteia-mcp

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # macOS/Linux

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

## Code Style

We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Security Guidelines

**CRITICAL:** Never commit credentials, master keys, or vault data.

- The `.gitignore` already excludes `~/.krypteia/` and related files
- Never log credential values in audit events — log aliases only
- Never return credential values in MCP tool responses
- Always sanitize HTTP responses before returning to the LLM
- New tools must enforce URL allowlisting

## Pull Request Process

1. Fork the repo and create a feature branch
2. Add tests for any new functionality
3. Ensure all tests pass: `pytest`
4. Ensure code passes lint: `ruff check src/ tests/`
5. Update README.md if you've added new tools or CLI commands
6. Submit a PR with a clear description of what and why

## Adding a New MCP Tool

1. Create a new file in `src/krypteia_mcp/tools/`
2. The tool function should accept `store` and `audit` as first args
3. Always audit every credential access (success and failure)
4. Never return `entry.secret` or `entry.username` in the response
5. Register the tool in `src/krypteia_mcp/server.py`
6. Add tests in `tests/`

## Reporting Issues

- **Bugs:** Open a GitHub issue with steps to reproduce
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md)
- **Feature requests:** Open a GitHub issue tagged `enhancement`
