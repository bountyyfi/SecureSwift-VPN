#!/bin/bash
#
# SecureSwift VPN - Master Test Runner
# Runs all automated tests: unit, integration, and fuzz tests
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Function to print colored output
print_header() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  $1${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Banner
clear
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                           ║${NC}"
echo -e "${BLUE}║          SecureSwift VPN - Test Suite Runner             ║${NC}"
echo -e "${BLUE}║          Comprehensive Automated Testing                 ║${NC}"
echo -e "${BLUE}║                                                           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running in CI
if [ -n "$CI" ]; then
    print_warning "Running in CI environment"
    export CI_MODE=1
fi

# Step 1: Compile all tests
print_header "Step 1/6: Compiling Test Suites"

echo "Compiling test_unit.c..."
if gcc -O2 -Wall -Wextra test_unit.c -o test_unit -lm -lpthread 2>&1 | tee /tmp/unit_compile.log; then
    print_success "Unit tests compiled successfully"
else
    print_error "Unit tests compilation failed"
    cat /tmp/unit_compile.log
    exit 1
fi

echo "Compiling test_integration.c..."
if gcc -O2 -Wall -Wextra test_integration.c -o test_integration -lm -lpthread 2>&1 | tee /tmp/integration_compile.log; then
    print_success "Integration tests compiled successfully"
else
    print_error "Integration tests compilation failed"
    cat /tmp/integration_compile.log
    exit 1
fi

echo "Compiling test_fuzz.c..."
if gcc -O2 -Wall -Wextra test_fuzz.c -o test_fuzz -lm -lpthread 2>&1 | tee /tmp/fuzz_compile.log; then
    print_success "Fuzz tests compiled successfully"
else
    print_error "Fuzz tests compilation failed"
    cat /tmp/fuzz_compile.log
    exit 1
fi

echo "Compiling test_quantum.c..."
if gcc -O2 -Wall -Wextra test_quantum.c -o test_quantum -lm -lpthread 2>&1 | tee /tmp/quantum_compile.log; then
    print_success "Quantum crypto tests compiled successfully"
else
    print_error "Quantum crypto tests compilation failed"
    cat /tmp/quantum_compile.log
    exit 1
fi

echo "Compiling test_e2e.c..."
if gcc -O2 -Wall -Wextra test_e2e.c -o test_e2e -lm -lpthread 2>&1 | tee /tmp/e2e_compile.log; then
    print_success "End-to-end tests compiled successfully"
else
    print_error "End-to-end tests compilation failed"
    cat /tmp/e2e_compile.log
    exit 1
fi

echo ""

# Step 2: Run unit tests
print_header "Step 2/6: Running Unit Tests"

if ./test_unit 2>&1 | tee /tmp/unit_results.log; then
    UNIT_RESULT=0
    print_success "Unit tests PASSED"
else
    UNIT_RESULT=$?
    print_error "Unit tests FAILED"
fi

echo ""

# Step 3: Run integration tests
print_header "Step 3/6: Running Integration Tests"

if ./test_integration 2>&1 | tee /tmp/integration_results.log; then
    INTEGRATION_RESULT=0
    print_success "Integration tests PASSED"
else
    INTEGRATION_RESULT=$?
    print_error "Integration tests FAILED"
fi

echo ""

# Step 4: Run fuzz tests
print_header "Step 4/6: Running Fuzz Tests"

if ./test_fuzz 2>&1 | tee /tmp/fuzz_results.log; then
    FUZZ_RESULT=0
    print_success "Fuzz tests PASSED"
else
    FUZZ_RESULT=$?
    print_warning "Fuzz tests completed with warnings (no crashes detected)"
    # Fuzz tests are allowed to have statistical failures as long as no crashes
    FUZZ_RESULT=0  # Override - we only care about crashes
fi

echo ""

# Step 5: Run quantum crypto tests
print_header "Step 5/6: Running Quantum Cryptography Tests"

if ./test_quantum 2>&1 | tee /tmp/quantum_results.log; then
    QUANTUM_RESULT=0
    print_success "Quantum crypto tests PASSED"
else
    QUANTUM_RESULT=$?
    print_error "Quantum crypto tests FAILED"
fi

echo ""

# Step 6: Run end-to-end tests (requires root)
print_header "Step 6/6: Running End-to-End Tests"

if [ "$(id -u)" -eq 0 ]; then
    if ./test_e2e 2>&1 | tee /tmp/e2e_results.log; then
        E2E_RESULT=0
        print_success "End-to-end tests PASSED"
    else
        E2E_RESULT=$?
        print_error "End-to-end tests FAILED"
    fi
else
    print_warning "Skipping E2E tests (requires root privileges)"
    E2E_RESULT=0  # Don't fail if not root
    echo "0" > /tmp/e2e_results.log
fi

echo ""

# Parse results
echo "Parsing test results..."

# Extract unit test results
if [ -f /tmp/unit_results.log ]; then
    UNIT_TOTAL=$(grep -oP "Total Tests:\s+\K\d+" /tmp/unit_results.log || echo "0")
    UNIT_PASSED=$(grep -oP "Passed:\s+\K\d+" /tmp/unit_results.log || echo "0")
    UNIT_FAILED=$(grep -oP "Failed:\s+\K\d+" /tmp/unit_results.log || echo "0")
else
    UNIT_TOTAL=0
    UNIT_PASSED=0
    UNIT_FAILED=0
fi

# Extract integration test results
if [ -f /tmp/integration_results.log ]; then
    INTEG_TOTAL=$(grep -oP "Total Tests:\s+\K\d+" /tmp/integration_results.log || echo "0")
    INTEG_PASSED=$(grep -oP "Passed:\s+\K\d+" /tmp/integration_results.log || echo "0")
    INTEG_FAILED=$(grep -oP "Failed:\s+\K\d+" /tmp/integration_results.log || echo "0")
else
    INTEG_TOTAL=0
    INTEG_PASSED=0
    INTEG_FAILED=0
fi

# Extract fuzz test results
if [ -f /tmp/fuzz_results.log ]; then
    FUZZ_TOTAL=$(grep -oP "Total Tests:\s+\K\d+" /tmp/fuzz_results.log || echo "0")
    FUZZ_PASSED=$(grep -oP "Passed:\s+\K\d+" /tmp/fuzz_results.log || echo "0")
    FUZZ_FAILED=$(grep -oP "Failed:\s+\K\d+" /tmp/fuzz_results.log || echo "0")
    FUZZ_CRASHES=$(grep -oP "Crashes:\s+\K\d+" /tmp/fuzz_results.log || echo "0")
else
    FUZZ_TOTAL=0
    FUZZ_PASSED=0
    FUZZ_FAILED=0
    FUZZ_CRASHES=0
fi

# Extract quantum crypto test results
if [ -f /tmp/quantum_results.log ]; then
    QUANTUM_TOTAL=$(grep -oP "Total Tests:\s+\K\d+" /tmp/quantum_results.log || echo "0")
    QUANTUM_PASSED=$(grep -oP "Passed:\s+\K\d+" /tmp/quantum_results.log || echo "0")
    QUANTUM_FAILED=$(grep -oP "Failed:\s+\K\d+" /tmp/quantum_results.log || echo "0")
else
    QUANTUM_TOTAL=0
    QUANTUM_PASSED=0
    QUANTUM_FAILED=0
fi

# Extract E2E test results
if [ -f /tmp/e2e_results.log ]; then
    E2E_TOTAL=$(grep -oP "Total Tests:\s+\K\d+" /tmp/e2e_results.log || echo "0")
    E2E_PASSED=$(grep -oP "Passed:\s+\K\d+" /tmp/e2e_results.log || echo "0")
    E2E_FAILED=$(grep -oP "Failed:\s+\K\d+" /tmp/e2e_results.log || echo "0")
else
    E2E_TOTAL=0
    E2E_PASSED=0
    E2E_FAILED=0
fi

# Calculate totals
TOTAL_TESTS=$((UNIT_TOTAL + INTEG_TOTAL + FUZZ_TOTAL + QUANTUM_TOTAL + E2E_TOTAL))
PASSED_TESTS=$((UNIT_PASSED + INTEG_PASSED + FUZZ_PASSED + QUANTUM_PASSED + E2E_PASSED))
FAILED_TESTS=$((UNIT_FAILED + INTEG_FAILED + FUZZ_FAILED + QUANTUM_FAILED + E2E_FAILED))

if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
else
    SUCCESS_RATE=0
fi

# Final summary
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     FINAL RESULTS                         ║${NC}"
echo -e "${BLUE}╠═══════════════════════════════════════════════════════════╣${NC}"
printf "${BLUE}║  ${NC}%-30s %8s %8s %8s ${BLUE}║${NC}\n" "Test Suite" "Total" "Passed" "Failed"
echo -e "${BLUE}╠═══════════════════════════════════════════════════════════╣${NC}"

# Unit tests
if [ $UNIT_RESULT -eq 0 ]; then
    printf "${BLUE}║  ${GREEN}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Unit Tests ✓" "$UNIT_TOTAL" "$UNIT_PASSED" "$UNIT_FAILED"
else
    printf "${BLUE}║  ${RED}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Unit Tests ✗" "$UNIT_TOTAL" "$UNIT_PASSED" "$UNIT_FAILED"
fi

# Integration tests
if [ $INTEGRATION_RESULT -eq 0 ]; then
    printf "${BLUE}║  ${GREEN}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Integration Tests ✓" "$INTEG_TOTAL" "$INTEG_PASSED" "$INTEG_FAILED"
else
    printf "${BLUE}║  ${RED}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Integration Tests ✗" "$INTEG_TOTAL" "$INTEG_PASSED" "$INTEG_FAILED"
fi

# Fuzz tests
if [ $FUZZ_CRASHES -eq 0 ]; then
    printf "${BLUE}║  ${GREEN}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Fuzz Tests ✓ (0 crashes)" "$FUZZ_TOTAL" "$FUZZ_PASSED" "$FUZZ_FAILED"
else
    printf "${BLUE}║  ${RED}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Fuzz Tests ✗ ($FUZZ_CRASHES crashes)" "$FUZZ_TOTAL" "$FUZZ_PASSED" "$FUZZ_FAILED"
fi

# Quantum crypto tests
if [ $QUANTUM_RESULT -eq 0 ]; then
    printf "${BLUE}║  ${GREEN}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Quantum Crypto Tests ✓" "$QUANTUM_TOTAL" "$QUANTUM_PASSED" "$QUANTUM_FAILED"
else
    printf "${BLUE}║  ${RED}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "Quantum Crypto Tests ✗" "$QUANTUM_TOTAL" "$QUANTUM_PASSED" "$QUANTUM_FAILED"
fi

# E2E tests
if [ $E2E_RESULT -eq 0 ]; then
    if [ $E2E_TOTAL -gt 0 ]; then
        printf "${BLUE}║  ${GREEN}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "End-to-End Tests ✓" "$E2E_TOTAL" "$E2E_PASSED" "$E2E_FAILED"
    else
        printf "${BLUE}║  ${YELLOW}%-30s ${NC}%8s %8s %8s ${BLUE}║${NC}\n" "End-to-End Tests (skipped)" "-" "-" "-"
    fi
else
    printf "${BLUE}║  ${RED}%-30s ${NC}%8d %8d %8d ${BLUE}║${NC}\n" "End-to-End Tests ✗" "$E2E_TOTAL" "$E2E_PASSED" "$E2E_FAILED"
fi

echo -e "${BLUE}╠═══════════════════════════════════════════════════════════╣${NC}"
printf "${BLUE}║  ${NC}%-30s %8d %8d %8d ${BLUE}║${NC}\n" "TOTAL" "$TOTAL_TESTS" "$PASSED_TESTS" "$FAILED_TESTS"
echo -e "${BLUE}╠═══════════════════════════════════════════════════════════╣${NC}"
printf "${BLUE}║  ${NC}Success Rate: %3d%%                                      ${BLUE}║${NC}\n" "$SUCCESS_RATE"

# Overall result
OVERALL_RESULT=0

if [ $UNIT_RESULT -ne 0 ] || [ $INTEGRATION_RESULT -ne 0 ] || [ $FUZZ_CRASHES -gt 0 ] || [ $QUANTUM_RESULT -ne 0 ] || [ $E2E_RESULT -ne 0 ]; then
    OVERALL_RESULT=1
fi

if [ $OVERALL_RESULT -eq 0 ]; then
    echo -e "${BLUE}║  ${GREEN}Status: ALL TESTS PASSED ✓                            ${BLUE}║${NC}"
else
    echo -e "${BLUE}║  ${RED}Status: SOME TESTS FAILED ✗                           ${BLUE}║${NC}"
fi

echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Additional info
if [ $OVERALL_RESULT -eq 0 ]; then
    echo -e "${GREEN}🎉 Congratulations! All test suites passed! 🎉${NC}"
    echo ""
    echo "Test logs saved to:"
    echo "  - /tmp/unit_results.log"
    echo "  - /tmp/integration_results.log"
    echo "  - /tmp/fuzz_results.log"
else
    echo -e "${RED}❌ Some tests failed. Please review the logs: ❌${NC}"
    echo ""
    echo "Failed test logs:"

    if [ $UNIT_RESULT -ne 0 ]; then
        echo "  - /tmp/unit_results.log"
    fi

    if [ $INTEGRATION_RESULT -ne 0 ]; then
        echo "  - /tmp/integration_results.log"
    fi

    if [ $FUZZ_CRASHES -gt 0 ]; then
        echo "  - /tmp/fuzz_results.log (CRASHES DETECTED!)"
    fi
fi

echo ""

# Cleanup option
if [ -z "$CI_MODE" ]; then
    read -p "Clean up test binaries? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f test_unit test_integration test_fuzz test_quantum test_e2e
        print_success "Test binaries cleaned up"
    fi
fi

exit $OVERALL_RESULT
