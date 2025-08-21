#!/bin/bash
# Simple test script for Smart Contract Analyzer

echo "🧪 Smart Contract Analyzer Test Suite"
echo "====================================="

# Test cases
test_cases=(
    "test-contracts/vulnerable/reentrancy.sol:6:Critical"
    "test-contracts/vulnerable/integer-overflow.sol:5:High"
    "test-contracts/vulnerable/access-control.sol:8:High"
    "test-contracts/vulnerable/timestamp-dependence.sol:15:Critical"
    "test-contracts/vulnerable/unprotected-selfdestruct.sol:13:Critical"
    "test-contracts/secure/secure-bank.sol:0:Very Low"
)

passed=0
total=0

for test_case in "${test_cases[@]}"; do
    IFS=':' read -r file expected_issues expected_risk <<< "$test_case"
    
    echo ""
    echo "📋 Testing: $file"
    echo "   Expected issues: $expected_issues"
    
    # Run analyzer and capture output
    output=$(./target/release/smart-contract-analyzer.exe analyze -f "$file" --vulnerability-analysis 2>&1)
    
    # Extract issue count from output
    if echo "$output" | grep -q "Total Issues: "; then
        actual_issues=$(echo "$output" | grep "Total Issues:" | sed 's/.*Total Issues: \([0-9]*\).*/\1/')
        echo "   Actual issues: $actual_issues"
        
        if [ "$actual_issues" = "$expected_issues" ]; then
            echo "   ✅ PASSED"
            ((passed++))
        else
            echo "   ❌ FAILED (expected $expected_issues, got $actual_issues)"
        fi
    else
        echo "   ❌ FAILED (couldn't parse output)"
    fi
    
    ((total++))
done

echo ""
echo "📊 TEST SUMMARY"
echo "==============="
echo "Total Tests: $total"
echo "Passed: $passed"
echo "Failed: $((total - passed))"

if [ $passed -eq $total ]; then
    echo "🎉 ALL TESTS PASSED!"
    exit 0
else
    echo "⚠️  SOME TESTS FAILED!"
    exit 1
fi
