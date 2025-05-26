# 🧪 PCAP Analysis Test Suite

Comprehensive test suite for the PCAP Analysis project, ensuring reliability and performance of all analysis tools.

## 📁 Test Structure

```
tests/
├── conftest.py              # Pytest fixtures and configuration
├── test_pcap_analyzer.py    # Unit tests for main analyzer
├── test_dns_anomaly_detector.py  # DNS analysis tests
├── test_extract_credentials.py   # Credential extraction tests
├── test_filters.py          # Wireshark filter validation
├── test_integration.py      # End-to-end integration tests
├── test_performance.py      # Performance benchmarks
└── test_data_generator.py   # Mock data generation for testing
```

## 🚀 Running Tests

### Quick Start
```bash
# Run all tests
./run_tests.sh

# Run specific test file
pytest tests/test_pcap_analyzer.py -v

# Run with coverage
pytest --cov=scripts --cov-report=html

# Run only fast tests
pytest -m "not slow"
```

### Test Categories

#### Unit Tests
```bash
pytest tests/test_pcap_analyzer.py tests/test_dns_anomaly_detector.py tests/test_extract_credentials.py
```

#### Integration Tests
```bash
pytest tests/test_integration.py
```

#### Performance Tests
```bash
pytest tests/test_performance.py
```

#### Filter Validation
```bash
pytest tests/test_filters.py
```

## 📊 Coverage Requirements

- **Minimum Coverage**: 80%
- **Target Coverage**: 95%+
- **Critical Functions**: 100%

### Viewing Coverage Report
```bash
# Generate HTML report
pytest --cov=scripts --cov-report=html

# Open report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## 🧪 Test Data Generation

The `test_data_generator.py` module creates realistic mock packet data:

```python
from tests.test_data_generator import create_test_dataset

# Generate mixed traffic
packets = create_test_dataset('mixed')

# Generate specific scenarios
apt_attack = create_test_dataset('apt')
ransomware = create_test_dataset('ransomware')
```

### Available Scenarios
- **mixed**: Normal traffic with some malicious activity
- **apt**: Advanced Persistent Threat scenario
- **ransomware**: Ransomware infection pattern
- **cryptomining**: Cryptocurrency mining traffic

## 🎯 Test Fixtures

Common fixtures available in `conftest.py`:

### `temp_pcap_file`
Creates a temporary PCAP file for testing
```python
def test_with_temp_file(temp_pcap_file):
    analyzer = PCAPAnalyzer(temp_pcap_file)
    # Test logic here
```

### `mock_dns_packet`
Provides a mock DNS packet
```python
def test_dns_analysis(mock_dns_packet):
    result = analyze_dns(mock_dns_packet)
    assert result['query'] == 'example.com'
```

### `sample_analysis_results`
Provides realistic analysis results
```python
def test_report_generation(sample_analysis_results):
    report = generate_report(sample_analysis_results)
    assert 'summary' in report
```

## ⚡ Performance Benchmarks

Performance tests ensure the tools can handle real-world data volumes:

- **Packet Loading**: < 0.1s for 100 packets, < 5s for 10,000 packets
- **DNS Analysis**: > 1000 packets/second
- **Entropy Calculation**: < 0.1ms per string
- **Memory Usage**: Linear scaling with packet count

## 🔍 Test Markers

### `@pytest.mark.slow`
Marks tests that take > 1 second
```python
@pytest.mark.slow
def test_large_pcap_processing():
    # Long-running test
```

### `@pytest.mark.integration`
Marks integration tests
```python
@pytest.mark.integration
def test_full_workflow():
    # End-to-end test
```

### `@pytest.mark.performance`
Marks performance tests
```python
@pytest.mark.performance
def test_processing_speed():
    # Performance benchmark
```

## 🛡️ Continuous Integration

Tests run automatically on:
- Every push to `main` or `develop`
- All pull requests
- Multiple Python versions (3.8, 3.9, 3.10, 3.11)

### CI Pipeline
1. **Linting**: flake8 and black
2. **Unit Tests**: Core functionality
3. **Integration Tests**: Workflow validation
4. **Performance Tests**: Speed benchmarks
5. **Security Scan**: Bandit analysis
6. **Coverage Report**: Codecov integration

## 🐛 Debugging Failed Tests

### Verbose Output
```bash
pytest -vv tests/test_pcap_analyzer.py::TestPCAPAnalyzer::test_load_pcap_success
```

### Show Local Variables
```bash
pytest --showlocals
```

### Drop into Debugger
```bash
pytest --pdb
```

### Print Output
```bash
pytest -s  # Don't capture stdout
```

## 📝 Writing New Tests

### Test Template
```python
def test_new_feature():
    """Test description"""
    # Arrange
    test_data = create_test_data()
    
    # Act
    result = function_under_test(test_data)
    
    # Assert
    assert result.status == 'success'
    assert len(result.items) > 0
```

### Mock Best Practices
```python
from unittest.mock import Mock, patch

@patch('module.external_function')
def test_with_mock(mock_func):
    mock_func.return_value = 'mocked_result'
    
    result = function_that_uses_external()
    
    mock_func.assert_called_once()
    assert result == 'processed_mocked_result'
```

## 🏆 Test Quality Checklist

- [ ] Test covers happy path
- [ ] Test covers error cases
- [ ] Test covers edge cases
- [ ] Test has clear assertions
- [ ] Test is independent
- [ ] Test is deterministic
- [ ] Test runs quickly (< 1s)
- [ ] Test name describes what it tests

## 📈 Metrics

Current test suite statistics:
- **Total Tests**: 50+
- **Execution Time**: < 30 seconds
- **Code Coverage**: 85%+
- **Assertion Density**: 3+ per test

---

For more information about the project, see the main [README.md](../README.md)