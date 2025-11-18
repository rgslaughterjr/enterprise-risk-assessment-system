# Contributing Guide

Thank you for your interest in contributing to the Enterprise Risk Assessment System! This guide will help you get started with development setup, code standards, and our contribution workflow.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Review Guidelines](#review-guidelines)
- [Branch Naming Conventions](#branch-naming-conventions)
- [Commit Message Conventions](#commit-message-conventions)
- [Release Process](#release-process)

---

## Development Setup

### Prerequisites

**Required:**
- Python 3.11 or higher
- Git 2.30+
- Tesseract OCR (for document intelligence features)

**Optional:**
- Redis (for caching)
- Docker (for containerized development)

### Initial Setup

**1. Clone the repository:**

```bash
git clone https://github.com/your-org/enterprise-risk-assessment-system.git
cd enterprise-risk-assessment-system
```

**2. Create virtual environment:**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies:**

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

**4. Install pre-commit hooks:**

```bash
pre-commit install
```

**5. Configure environment:**

```bash
cp .env.example .env
# Edit .env with your API keys
```

**6. Install Tesseract OCR:**

```bash
# macOS
brew install tesseract

# Ubuntu/Debian
sudo apt-get install tesseract-ocr

# Windows
# Download from: https://github.com/UB-Mannheim/tesseract/wiki
```

**7. Verify installation:**

```bash
python check_tools.py
pytest tests/ -v --ignore=tests/security/ --ignore=tests/reasoning/
```

### Development Tools

**Required in `requirements-dev.txt`:**

```
# Testing
pytest==8.3.5
pytest-cov==7.0.6
pytest-mock==3.14.0
pytest-asyncio==0.25.2

# Linting
ruff==0.9.1
black==24.12.0
mypy==1.14.1
bandit==1.8.0

# Pre-commit
pre-commit==4.0.1

# Documentation
mkdocs==1.6.1
mkdocs-material==9.5.47
```

---

## Code Standards

### Python Style Guide

We follow **PEP 8** with the following modifications:

- **Line length:** 100 characters (not 79)
- **Quotes:** Double quotes for strings
- **Imports:** Organized by `isort`

### Code Formatting

**Black (code formatter):**

```bash
# Format all Python files
black src/ tests/

# Check without modifying
black --check src/ tests/
```

**Ruff (fast linter):**

```bash
# Lint and auto-fix
ruff check src/ tests/ --fix

# Check only
ruff check src/ tests/
```

**isort (import sorting):**

```bash
# Sort imports
isort src/ tests/

# Check without modifying
isort --check-only src/ tests/
```

### Type Hints

**All new code must include type hints:**

```python
# Good
def analyze_cve(cve_id: str, severity_threshold: float = 7.0) -> VulnerabilityAnalysis:
    """Analyze a CVE and return detailed assessment."""
    pass

# Bad - no type hints
def analyze_cve(cve_id, severity_threshold=7.0):
    pass
```

**Run type checker:**

```bash
mypy src/ --strict
```

### Docstrings

**Use Google-style docstrings:**

```python
def calculate_risk_score(
    likelihood: int,
    impact: int,
    confidence: float = 1.0
) -> RiskRating:
    """Calculate risk score using FAIR methodology.

    Args:
        likelihood: Likelihood rating (1-5)
        impact: Impact rating (1-5)
        confidence: Confidence in assessment (0.0-1.0)

    Returns:
        RiskRating object with score and severity level

    Raises:
        ValueError: If likelihood or impact out of range (1-5)

    Example:
        >>> rating = calculate_risk_score(likelihood=4, impact=5)
        >>> print(rating.level)
        'Critical'
    """
    if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
        raise ValueError("Likelihood and impact must be between 1-5")

    score = likelihood * impact
    level = get_risk_level(score)
    return RiskRating(score=score, level=level, confidence=confidence)
```

### Code Organization

**Module structure:**

```
src/
├── agents/          # Agent implementations (one per file)
├── tools/           # External API clients and utilities
├── models/          # Pydantic models (schemas.py)
├── supervisor/      # LangGraph orchestration
└── utils/           # Helper functions

tests/
├── test_*.py        # Unit tests (mirror src/ structure)
├── integration/     # E2E tests
└── fixtures/        # Test data and fixtures
```

**File naming:**
- Modules: `lowercase_with_underscores.py`
- Classes: `PascalCase`
- Functions: `snake_case`
- Constants: `UPPER_CASE_WITH_UNDERSCORES`

---

## Testing Requirements

### Test Coverage Requirements

**Minimum coverage thresholds:**

- Overall: **70%**
- New features: **80%**
- Critical paths (risk scoring, vulnerability analysis): **90%**

### Writing Tests

**Test structure (AAA pattern):**

```python
def test_calculate_risk_score_critical_risk():
    """Test risk calculation for critical severity."""
    # Arrange
    agent = RiskScoringAgent()
    likelihood = 5
    impact = 5

    # Act
    result = agent.calculate_risk_score(likelihood, impact)

    # Assert
    assert result.score == 25
    assert result.level == "Critical"
    assert 1.0 <= result.confidence <= 1.0
```

**Use pytest fixtures for common setup:**

```python
@pytest.fixture
def mock_nvd_client(mocker):
    """Mock NVD client to avoid real API calls."""
    mock = mocker.patch("src.tools.nvd_client.NVDClient.get_cve")
    mock.return_value = CVEDetail(
        cve_id="CVE-2024-1234",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        description="Test vulnerability"
    )
    return mock

def test_vulnerability_analysis_with_mock(mock_nvd_client):
    """Test vulnerability analysis with mocked NVD client."""
    agent = VulnerabilityAgent()
    result = agent.analyze_cve("CVE-2024-1234")

    assert result.cve_id == "CVE-2024-1234"
    assert result.priority_score > 80
    mock_nvd_client.assert_called_once_with("CVE-2024-1234")
```

### Test Markers

**Use markers to categorize tests:**

```python
@pytest.mark.integration
def test_full_risk_assessment_workflow():
    """E2E test for complete risk assessment (slow)."""
    pass

@pytest.mark.slow
def test_batch_processing_100_cves():
    """Test batch processing (takes >5 seconds)."""
    pass

@pytest.mark.unit
def test_cve_id_validation():
    """Fast unit test for input validation."""
    pass
```

**Run specific test categories:**

```bash
pytest -m unit              # Fast unit tests only
pytest -m "not integration" # Skip E2E tests
pytest -m "not slow"        # Skip slow tests
```

### Running Tests

```bash
# Run all passing tests (ignore incomplete Week 8-12)
pytest tests/ -v --ignore=tests/security/ --ignore=tests/reasoning/

# Run with coverage report
pytest --cov=src --cov-report=html --cov-report=term

# Run specific test file
pytest tests/test_risk_scoring_agent.py -v

# Run single test
pytest tests/test_risk_scoring_agent.py::test_calculate_risk_score_critical -v

# Run in parallel (faster)
pytest -n auto
```

### Code Coverage

**View coverage report:**

```bash
# Generate HTML report
pytest --cov=src --cov-report=html

# Open in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

**Coverage configuration (`.coveragerc`):**

```ini
[run]
source = src
omit =
    */tests/*
    */venv/*
    */migrations/*
    */__pycache__/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
    if TYPE_CHECKING:
```

---

## Pull Request Process

### Before Opening a PR

**1. Run full test suite:**

```bash
pytest tests/ -v --ignore=tests/security/ --ignore=tests/reasoning/
```

**2. Run linters:**

```bash
black src/ tests/
ruff check src/ tests/ --fix
mypy src/ --strict
```

**3. Update documentation:**

- Update docstrings for new functions
- Update `CLAUDE.md` if adding new features
- Update `README.md` if changing user-facing behavior

**4. Add tests:**

- Unit tests for new functions
- Integration tests for new workflows
- Ensure coverage >= 80% for new code

### Opening the PR

**1. Create feature branch:**

```bash
git checkout -b feature/add-virustotal-v4-support
```

**2. Make your changes and commit:**

```bash
git add src/tools/virustotal_client.py tests/test_virustotal_client.py
git commit -m "feat: Add VirusTotal API v4 support"
```

**3. Push to your fork:**

```bash
git push origin feature/add-virustotal-v4-support
```

**4. Open PR on GitHub:**

Use this template:

```markdown
## Summary
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Changes Made
- Added VirusTotal API v4 client in `src/tools/virustotal_client.py`
- Updated tests to cover new API version
- Added rate limiting (4 req/min for free tier)

## Testing
- [ ] All tests pass (`pytest -v`)
- [ ] Coverage >= 80% for new code
- [ ] Manual testing completed (describe below)

**Manual Testing:**
- Tested with 10 CVEs, all returned valid results
- Verified rate limiting works correctly
- Tested error handling for invalid API key

## Breaking Changes
None

## Related Issues
Closes #123
```

### PR Size Guidelines

- **Small PR (< 200 lines):** Preferred, fast review
- **Medium PR (200-500 lines):** Acceptable, may take longer to review
- **Large PR (> 500 lines):** Break into smaller PRs if possible

---

## Review Guidelines

### For PR Authors

**Respond to review comments within 48 hours:**

- Accept suggestions or provide rationale for disagreement
- Mark conversations as resolved when addressed
- Request re-review after making changes

**Don't merge your own PRs:**

- At least one approval required
- Wait for CI checks to pass
- Resolve all review comments

### For Reviewers

**Review within 2 business days:**

**Focus on:**

1. **Correctness:** Does the code work as intended?
2. **Testing:** Are tests comprehensive? Do they pass?
3. **Security:** Any security vulnerabilities (SQL injection, XSS, etc.)?
4. **Performance:** Will this scale? Any obvious bottlenecks?
5. **Maintainability:** Is code readable? Well-documented?

**Use constructive language:**

```markdown
# Good
"Consider using a list comprehension here for better performance:
`results = [process(x) for x in items]`"

# Bad
"This code is slow and inefficient."
```

**Approve when:**
- Code meets standards
- Tests pass and cover >= 80% of new code
- Documentation updated
- No security issues

---

## Branch Naming Conventions

**Format:** `<type>/<short-description>`

**Types:**

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Adding or updating tests
- `chore/` - Maintenance tasks

**Examples:**

```
feature/add-mitre-attack-v15-support
fix/servicenow-rate-limit-handling
docs/update-architecture-diagram
refactor/simplify-risk-calculation
test/add-integration-tests-for-rag
chore/update-dependencies
```

**Rules:**

- Use kebab-case (lowercase with hyphens)
- Keep descriptions short (< 50 chars)
- Be descriptive but concise

---

## Commit Message Conventions

We follow **Conventional Commits** specification.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks (dependency updates, etc.)
- `perf`: Performance improvements

### Examples

**Feature:**
```
feat(agents): Add MITRE ATT&CK v15 support

- Update MITRE client to use ATT&CK v15 API
- Add 50+ new techniques from v15
- Update threat agent to map to new techniques

Closes #456
```

**Bug fix:**
```
fix(nvd): Handle rate limiting for NVD API

Previously, the client would crash when hitting NVD rate limits.
Now it retries with exponential backoff (2s, 4s, 8s).

Fixes #789
```

**Breaking change:**
```
feat(risk-scoring)!: Change risk matrix from 3x3 to 5x5

BREAKING CHANGE: Risk scores now range from 1-25 instead of 1-9.
All existing risk ratings need to be recalculated.

Migration guide:
- Run `python scripts/migrate_risk_scores.py`
- Update custom risk thresholds in config

Closes #234
```

**Documentation:**
```
docs: Add performance tuning guide

Added comprehensive guide covering:
- Agent optimization strategies
- Caching patterns
- Cost optimization
- Database query optimization
```

### Commit Message Rules

1. **Subject line:**
   - Max 72 characters
   - Imperative mood ("Add feature" not "Added feature")
   - No period at the end
   - Capitalize first letter

2. **Body (optional but recommended):**
   - Wrap at 72 characters
   - Explain **what** and **why**, not **how**
   - Reference issues/PRs

3. **Footer (optional):**
   - Reference issues: `Closes #123`, `Fixes #456`
   - Breaking changes: `BREAKING CHANGE: description`

---

## Release Process

### Versioning

We use **Semantic Versioning** (SemVer):

- `MAJOR.MINOR.PATCH` (e.g., `1.2.3`)
- **MAJOR:** Breaking changes
- **MINOR:** New features (backward compatible)
- **PATCH:** Bug fixes (backward compatible)

### Release Checklist

**1. Pre-release:**

- [ ] All tests pass on `main` branch
- [ ] Coverage >= 70%
- [ ] Security scan passed (Bandit, Snyk)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated

**2. Create release:**

```bash
# Update version
echo "1.2.0" > VERSION

# Tag release
git tag -a v1.2.0 -m "Release v1.2.0: Add advanced RAG features"
git push origin v1.2.0
```

**3. Generate release notes:**

```markdown
## v1.2.0 - 2025-11-18

### Features
- Added semantic chunking with 5 strategies (#123)
- Implemented hybrid retrieval (BM25 + semantic) (#124)
- Added query optimization (expansion, rewriting, HyDE) (#125)

### Bug Fixes
- Fixed NVD rate limiting issue (#130)
- Corrected CVSS score parsing for CVSSv4 (#131)

### Performance
- 40% faster RAG retrieval with caching (#126)
- Reduced token usage by 25% with prompt optimization (#127)

### Documentation
- Added performance tuning guide (#128)
- Updated architecture diagrams (#129)

### Breaking Changes
None
```

**4. Deploy:**

- Deploy to staging environment
- Run smoke tests
- Deploy to production
- Monitor for issues

---

## Getting Help

### Resources

- **Documentation:** See `CLAUDE.md` for architecture overview
- **Examples:** See `examples/basic_usage.py` for code samples
- **Issues:** Search existing issues before opening new ones

### Communication Channels

- **GitHub Issues:** Bug reports, feature requests
- **GitHub Discussions:** Questions, ideas, general discussion
- **Slack:** `#risk-assessment-dev` (for team members)
- **Email:** dev@yourcompany.com

### Questions?

If you have questions about:
- **Code standards:** Check this guide or ask in GitHub Discussions
- **Architecture decisions:** See `docs/ARCHITECTURE.md`
- **Security concerns:** See `docs/SECURITY_POLICY.md`
- **Performance:** See `docs/PERFORMANCE_TUNING.md`

---

## Code of Conduct

### Our Standards

- **Be respectful:** Treat everyone with respect and kindness
- **Be constructive:** Provide helpful feedback, not criticism
- **Be collaborative:** Work together to solve problems
- **Be patient:** Remember that everyone is learning

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Personal attacks or trolling
- Publishing others' private information
- Any conduct that would be inappropriate in a professional setting

### Reporting

Report violations to: conduct@yourcompany.com

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

**Thank you for contributing to the Enterprise Risk Assessment System!**

We appreciate your time and effort in making this project better. If you have any questions, don't hesitate to ask in GitHub Discussions or Issues.
