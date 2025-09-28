# Contributing to BoltVulnScanner

Thank you for your interest in contributing to BoltVulnScanner! This document provides guidelines and information to help you contribute effectively.

## 📋 Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. We are committed to providing a welcoming and inclusive environment for all contributors.

## 🛠️ Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/BoltVulnScanner.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Commit your changes: `git commit -m "Add your message here"`
6. Push to your fork: `git push origin feature/your-feature-name`
7. Create a Pull Request

## 📝 Code Style Guidelines

### Python Code Standards

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints for all function parameters and return types
- Write docstrings for all public classes and functions
- Keep functions focused and small (preferably under 50 lines)
- Use descriptive variable and function names

### Example Code Style

```python
def scan_for_xss(self, pages: List[WebPage]) -> List[Finding]:
    """
    Scan crawled pages for XSS vulnerabilities.
    
    Args:
        pages: List of crawled web pages to scan
        
    Returns:
        List of XSS findings
    """
    findings: List[Finding] = []
    
    for page in pages:
        # Implementation here
        pass
        
    return findings
```

## 🧪 Testing

### Unit Tests

- Write unit tests for all new functionality
- Use pytest for testing
- Mock external dependencies
- Aim for high code coverage (>80%)

### Running Tests

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_module.py
```

### Test Structure

```python
def test_xss_scanner_detects_reflected_xss(mocker):
    # Arrange
    config = ScanConfig(target_url="http://example.com")
    scanner = XSSScanner(config)
    
    # Mock HTTP response
    mock_response = mocker.Mock()
    mock_response.text = "<html>Hello <script>alert('XSS')</script></html>"
    mocker.patch('boltvuln.utils.safe_request', return_value=mock_response)
    
    # Act
    findings = scanner._scan_url_parameters("http://example.com?input=test", ["<script>alert('XSS')</script>"])
    
    # Assert
    assert len(findings) == 1
    assert findings[0].module == "xss"
```

## 📦 Dependencies

### Adding New Dependencies

1. Add to `pyproject.toml` using Poetry
2. Update `requirements.txt` accordingly
3. Document in README if user-facing

### Optional Dependencies

For optional features, add them as extras in `pyproject.toml`:

```toml
[tool.poetry.extras]
pdf = ["weasyprint"]
headless = ["playwright"]
tls = ["sslyze"]
```

## 🐳 Docker

When adding new dependencies or making changes that affect Docker:

1. Update `Dockerfile` if needed
2. Test Docker build locally
3. Update documentation if necessary

## 📖 Documentation

### README Updates

Update README.md when:
- Adding new features
- Changing command-line interface
- Modifying installation process

### Docstrings

Write comprehensive docstrings for:
- All public classes
- All public methods
- All public functions
- Module-level documentation for complex modules

## 🔄 Pull Request Process

1. Ensure your code follows the style guidelines
2. Add tests for new functionality
3. Update documentation as needed
4. Verify all tests pass
5. Create a pull request with a clear description
6. Link any related issues
7. Request review from maintainers

### Pull Request Description Template

```markdown
## Description
Brief description of the changes

## Related Issue
Fixes #123

## Changes
- List of key changes
- Made X more efficient
- Fixed bug in Y

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Documentation
- [ ] README updated
- [ ] Docstrings added/updated
```

## 🐛 Reporting Issues

### Before Submitting

1. Check existing issues
2. Reproduce with the latest version
3. Gather relevant information (version, OS, Python version)

### Issue Template

```markdown
## Description
Clear and concise description of the issue

## Steps to Reproduce
1. Step one
2. Step two
3. Observed behavior

## Expected Behavior
What you expected to happen

## Actual Behavior
What actually happened

## Environment
- OS: [e.g., Ubuntu 20.04]
- Python version: [e.g., 3.11.0]
- BoltVulnScanner version: [e.g., 0.1.0]
- Browser (for UI issues): [e.g., Chrome 98.0]

## Additional Context
Add any other context about the problem here
```

## 🎯 Development Goals

### Short-term Priorities
1. Improve scan accuracy
2. Add more security checks
3. Enhance reporting capabilities
4. Optimize performance

### Long-term Vision
1. Plugin architecture for custom checks
2. Advanced heuristics and machine learning
3. Integration with popular security tools
4. Enhanced visualization and analytics

## 🤝 Community

### Communication Channels
- GitHub Issues for bug reports and feature requests
- Discussions for general questions and community interaction

### Recognition
Contributors will be recognized in:
- Release notes
- CONTRIBUTORS file
- README acknowledgments

Thank you for contributing to BoltVulnScanner!