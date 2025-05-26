# Contributing to PCAP Analysis Project

First off, thank you for considering contributing to the PCAP Analysis project! It's people like you that make this tool better for everyone.

## 🤝 Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## 🚀 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (PCAP files if possible)
- **Describe the behavior you observed**
- **Explain which behavior you expected**
- **Include your environment details** (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Provide specific examples** to demonstrate the feature
- **Describe the current behavior** and **explain expected behavior**
- **Explain why this enhancement would be useful**

### Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code follows the existing style.
6. Issue that pull request!

## 📝 Development Process

### Setup Development Environment

```bash
# Clone your fork
git clone https://github.com/your-username/pcap-analysis.git
cd pcap-analysis

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r tools/requirements.txt
pip install pytest pytest-cov flake8 black pre-commit

# Install pre-commit hooks
pre-commit install
```

### Code Style

We use Black for Python code formatting:

```bash
# Format code
black scripts tests

# Check formatting
black --check scripts tests
```

We use Flake8 for linting:

```bash
# Run linter
flake8 scripts tests
```

### Testing

All new features must include tests:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=scripts

# Run specific test file
pytest tests/test_pcap_analyzer.py -v
```

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

Example:
```
Add DNS tunneling detection for TXT records

- Implement entropy calculation for TXT record data
- Add configurable threshold for detection sensitivity  
- Include unit tests for new functionality

Fixes #123
```

## 🏗️ Project Structure

When adding new features, follow the existing structure:

```
scripts/           # Add new analysis scripts here
├── your_analyzer.py

tests/            # Add corresponding tests
├── test_your_analyzer.py

wireshark-filters/ # Add new filter collections
├── your-filters.txt

analysis-reports/  # Add example reports
├── your-analysis-example.md
```

## 📚 Adding New Analysis Capabilities

When adding a new analysis script:

1. **Create the script** in `scripts/` with:
   - Proper shebang (`#!/usr/bin/env python3`)
   - Docstring explaining purpose
   - Command-line interface using argparse
   - Main function pattern

2. **Add comprehensive tests** in `tests/`:
   - Unit tests for all functions
   - Integration tests for workflows
   - Edge case handling
   - Mock data as needed

3. **Update documentation**:
   - Add usage examples to README.md
   - Document any new dependencies
   - Add Wireshark filters if applicable

4. **Follow the template**:

```python
#!/usr/bin/env python3
"""
Your Analyzer - Brief description
Author: Your Name
"""

import argparse
import sys
from scapy.all import *

class YourAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.results = {}
    
    def analyze(self):
        """Main analysis logic"""
        pass
    
    def generate_report(self):
        """Generate output report"""
        pass

def main():
    parser = argparse.ArgumentParser(description='Your analyzer description')
    parser.add_argument('pcap', help='PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    analyzer = YourAnalyzer(args.pcap)
    analyzer.analyze()
    analyzer.generate_report()

if __name__ == "__main__":
    main()
```

## 🔍 Adding Wireshark Filters

When contributing filters:

1. **Group related filters** in themed files
2. **Comment each filter** explaining what it detects
3. **Test filters** with real PCAP data
4. **Provide examples** in comments

Example:
```
# Detect potential SQL injection attempts
# Looks for common SQL keywords in HTTP requests
http.request.uri contains "union" or http.request.uri contains "select" or http.request.uri contains "--"

# Find base64 encoded data in DNS queries
# May indicate DNS tunneling
dns.qry.name contains "==" and dns.qry.name.len > 50
```

## 🎯 Areas We Need Help

- **Machine Learning**: Anomaly detection algorithms
- **Performance**: Optimizing for very large PCAP files
- **Visualizations**: Creating graphical analysis outputs
- **Protocols**: Adding support for more protocols
- **Documentation**: Improving tutorials and examples

## 📋 Review Process

1. **Automated checks** must pass (tests, linting, formatting)
2. **Code review** by at least one maintainer
3. **Documentation** must be updated if needed
4. **Tests** must maintain or increase coverage

## 🏆 Recognition

Contributors will be recognized in:
- The project README
- Release notes
- Special mentions for significant contributions

## ❓ Questions?

Feel free to open an issue with the "question" label or reach out to the maintainers directly.

Thank you for contributing! 🎉