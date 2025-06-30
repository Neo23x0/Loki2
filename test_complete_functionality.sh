#!/bin/bash

# Test script for Loki2 complete functionality
# This script tests all the newly implemented features

echo "========================================================================="
echo "LOKI2 COMPLETE FUNCTIONALITY TEST"
echo "========================================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
    else
        echo -e "${RED}✗ $2${NC}"
    fi
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Cargo not found. Please install Rust and Cargo.${NC}"
    exit 1
fi

# Build the project
print_info "Building Loki2..."
cargo build --release
build_result=$?
print_status $build_result "Build completed"

if [ $build_result -ne 0 ]; then
    echo -e "${RED}Build failed. Exiting.${NC}"
    exit 1
fi

# Create test directory structure
print_info "Setting up test environment..."
mkdir -p test_env/suspicious_files
mkdir -p test_env/normal_files

# Create test files for filename IOC matching
echo "This is a test file" > test_env/suspicious_files/mimikatz.exe
echo "Normal content" > test_env/normal_files/document.txt
echo "Test script" > test_env/suspicious_files/temp123.exe

# Create symlink to test signatures
if [ ! -L signatures ]; then
    ln -s signatures-test signatures
    print_status 0 "Created symlink to test signatures"
fi

# Test 1: Basic functionality test
print_info "Test 1: Basic scan with all modules"
./target/release/loki --debug --folder test_env > test_output_1.log 2>&1
test1_result=$?
print_status $test1_result "Basic scan completed"

# Test 2: Scan without processes
print_info "Test 2: Scan without process checking"
./target/release/loki --debug --noprocs --folder test_env > test_output_2.log 2>&1
test2_result=$?
print_status $test2_result "Scan without processes completed"

# Test 3: Scan without network
print_info "Test 3: Scan without network checking"
./target/release/loki --debug --nonet --folder test_env > test_output_3.log 2>&1
test3_result=$?
print_status $test3_result "Scan without network completed"

# Test 4: Scan with trace output
print_info "Test 4: Scan with trace output"
./target/release/loki --trace --folder test_env/normal_files > test_output_4.log 2>&1
test4_result=$?
print_status $test4_result "Trace scan completed"

# Test 5: File system only scan
print_info "Test 5: File system only scan"
./target/release/loki --debug --noprocs --nonet --folder test_env > test_output_5.log 2>&1
test5_result=$?
print_status $test5_result "File system only scan completed"

# Analyze results
print_info "Analyzing test results..."

# Check if filename IOCs were detected
if grep -q "FILENAME IOC match" test_output_1.log; then
    print_status 0 "Filename IOC matching working"
else
    print_status 1 "Filename IOC matching not detected"
fi

# Check if hash IOCs were loaded
if grep -q "Successfully initialized.*hash values" test_output_1.log; then
    print_status 0 "Hash IOC loading working"
else
    print_status 1 "Hash IOC loading not detected"
fi

# Check if C2 IOCs were loaded
if grep -q "Successfully initialized.*C2 IOC values" test_output_1.log; then
    print_status 0 "C2 IOC loading working"
else
    print_status 1 "C2 IOC loading not detected"
fi

# Check if modules were properly configured
if grep -q "Active modules:" test_output_1.log; then
    print_status 0 "Module system working"
else
    print_status 1 "Module system not detected"
fi

# Check if custom exclusions were loaded
if grep -q "custom exclusion" test_output_1.log; then
    print_status 0 "Custom exclusions working"
else
    print_status 1 "Custom exclusions not detected (may be normal if no exclusions matched)"
fi

# Check if scan summary was printed
if grep -q "SCAN SUMMARY" test_output_1.log; then
    print_status 0 "Scan summary working"
else
    print_status 1 "Scan summary not detected"
fi

# Performance test
print_info "Performance test: Scanning larger directory"
time ./target/release/loki --debug --folder /usr/bin > test_output_perf.log 2>&1
perf_result=$?
print_status $perf_result "Performance test completed"

echo ""
echo "========================================================================="
echo "TEST SUMMARY"
echo "========================================================================="
echo "Test files created in: test_env/"
echo "Log files created: test_output_*.log"
echo "Main log file: loki_$(hostname).log"
echo ""
echo "To review detailed results:"
echo "  cat test_output_1.log | grep -E '(IOC|YARA|match|ERROR|WARN)'"
echo ""
echo "To clean up test files:"
echo "  rm -rf test_env/ test_output_*.log"
echo "========================================================================="

# Cleanup function
cleanup() {
    read -p "Do you want to clean up test files? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf test_env/
        rm -f test_output_*.log
        print_status 0 "Test files cleaned up"
    fi
}

# Ask for cleanup
cleanup
