#!/bin/bash
# Run comprehensive test suite for PCAP Analysis project

echo "🧪 PCAP Analysis Test Suite"
echo "=========================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -q -r tools/requirements.txt
pip install -q pytest pytest-cov pytest-mock flake8 black

echo ""
echo "🔍 Running Code Quality Checks"
echo "------------------------------"

# Run black formatting check
echo -n "Black formatting: "
if black --check scripts tests >/dev/null 2>&1; then
    echo -e "${GREEN}✓ PASSED${NC}"
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Run 'black scripts tests' to fix formatting"
fi

# Run flake8 linting
echo -n "Flake8 linting: "
if flake8 scripts --max-line-length=127 --exclude=__pycache__ >/dev/null 2>&1; then
    echo -e "${GREEN}✓ PASSED${NC}"
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Run 'flake8 scripts' to see issues"
fi

echo ""
echo "🧪 Running Unit Tests"
echo "--------------------"

# Run unit tests
pytest tests/test_pcap_analyzer.py tests/test_dns_anomaly_detector.py tests/test_extract_credentials.py -v --tb=short

echo ""
echo "🔗 Running Integration Tests"
echo "---------------------------"

# Run integration tests
pytest tests/test_integration.py -v --tb=short

echo ""
echo "⚡ Running Performance Tests"
echo "---------------------------"

# Run performance tests (excluding slow ones)
pytest tests/test_performance.py -v -m "not slow" --tb=short

echo ""
echo "🛡️ Running Filter Validation"
echo "---------------------------"

# Run filter tests
pytest tests/test_filters.py -v --tb=short

echo ""
echo "📊 Generating Coverage Report"
echo "----------------------------"

# Run all tests with coverage
pytest --cov=scripts --cov-report=term-missing --cov-report=html --cov-fail-under=80

echo ""
echo "📈 Test Summary"
echo "--------------"

# Check if htmlcov was generated
if [ -d "htmlcov" ]; then
    echo -e "${GREEN}✓ Coverage report generated in htmlcov/index.html${NC}"
    
    # Get coverage percentage
    coverage_percent=$(pytest --cov=scripts --cov-report=term | grep TOTAL | awk '{print $4}')
    echo "  Overall coverage: $coverage_percent"
fi

echo ""
echo "🔧 Running Script Help Tests"
echo "---------------------------"

# Test that all scripts have proper help
for script in scripts/*.py; do
    if [[ -f "$script" ]]; then
        script_name=$(basename "$script")
        echo -n "Testing $script_name: "
        if python "$script" --help >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
        fi
    fi
done

echo ""
echo "🎯 Test Data Generator Check"
echo "---------------------------"

# Run test data generator
echo "Running test data generator..."
python tests/test_data_generator.py

echo ""
echo "✅ Test Suite Complete!"
echo ""

# Deactivate virtual environment
deactivate

# Open coverage report if on macOS
if [[ "$OSTYPE" == "darwin"* ]] && [ -d "htmlcov" ]; then
    echo "Opening coverage report in browser..."
    open htmlcov/index.html
fi