# Contributing to Itzraven

Thank you for your interest in contributing to Itzraven! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported
2. Create a detailed issue with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Features

1. Check if the feature has been suggested
2. Create an issue describing:
   - The problem it solves
   - Proposed solution
   - Alternative approaches considered

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Write/update tests
5. Update documentation
6. Commit with clear messages
7. Push to your fork
8. Create a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/iamaworker-github/itzraven.git
cd itzraven

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for public APIs
- Keep functions focused and small
- Use meaningful variable names

## Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=itzraven

# Run specific test
pytest tests/test_agents.py
```

## Adding New Agents

To add a new security testing agent:

1. Create a new file in `itzraven/agents/`
2. Inherit from `BaseAgent`
3. Implement the `execute()` method
4. Add tests in `tests/`
5. Update documentation

Example:

```python
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding

class MyAgent(BaseAgent):
    def __init__(self, target: str):
        super().__init__("My Agent", target)
    
    async def execute(self) -> AgentResult:
        # Your testing logic here
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )
```

## Documentation

- Update README.md for user-facing changes
- Add docstrings to new functions/classes
- Update examples if needed

## Commit Messages

Use clear, descriptive commit messages:

```
feat: Add authentication bypass agent
fix: Correct SQL injection detection logic
docs: Update installation instructions
test: Add tests for XSS agent
refactor: Simplify orchestrator logic
```

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Questions?

Open an issue or start a discussion on GitHub.

Thank you for contributing to Itzraven!
