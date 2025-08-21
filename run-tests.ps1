#!/usr/bin/env powershell

# Smart Contract Analyzer Test Suite
# This script runs comprehensive tests on various contract types

param(
    [switch]$Verbose,
    [switch]$GenerateReports,
    [string]$OutputDir = "test-results"
)

Write-Host "🧪 Smart Contract Analyzer Test Suite" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Ensure the output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Test configurations
$TestCases = @(
    @{
        Name = "Reentrancy Vulnerabilities"
        File = "test-contracts/vulnerable/reentrancy.sol"
        ExpectedVulnerabilities = @("SWC-107", "SWC-105")
        ExpectedSeverity = "Critical"
    },
    @{
        Name = "Integer Overflow"
        File = "test-contracts/vulnerable/integer-overflow.sol"
        ExpectedVulnerabilities = @("SWC-101")
        ExpectedSeverity = "High"
    },
    @{
        Name = "Unchecked Return Values"
        File = "test-contracts/vulnerable/unchecked-returns.sol"
        ExpectedVulnerabilities = @("SWC-104")
        ExpectedSeverity = "Medium"
    },
    @{
        Name = "Access Control Issues"
        File = "test-contracts/vulnerable/access-control.sol"
        ExpectedVulnerabilities = @("SWC-115", "SWC-105")
        ExpectedSeverity = "High"
    },
    @{
        Name = "Timestamp Dependence"
        File = "test-contracts/vulnerable/timestamp-dependence.sol"
        ExpectedVulnerabilities = @("SWC-116")
        ExpectedSeverity = "High"
    },
    @{
        Name = "Unprotected Selfdestruct"
        File = "test-contracts/vulnerable/unprotected-selfdestruct.sol"
        ExpectedVulnerabilities = @("SWC-106")
        ExpectedSeverity = "Critical"
    },
    @{
        Name = "Secure Bank (No Vulnerabilities Expected)"
        File = "test-contracts/secure/secure-bank.sol"
        ExpectedVulnerabilities = @()
        ExpectedSeverity = "Very Low"
    }
)

# Function to run analyzer and parse results
function Test-Contract {
    param(
        [string]$ContractFile,
        [string]$TestName,
        [array]$ExpectedVulnerabilities,
        [string]$ExpectedSeverity
    )
    
    Write-Host "`n📋 Testing: $TestName" -ForegroundColor Yellow
    Write-Host "   File: $ContractFile" -ForegroundColor Gray
    
    # Run the analyzer
    $OutputFile = "$OutputDir/$($TestName -replace ' ', '_').json"
    $Command = ".\target\release\smart-contract-analyzer.exe analyze -f `"$ContractFile`" --vulnerability-analysis --output-format json -o `"$OutputFile`""
    
    if ($Verbose) {
        Write-Host "   Command: $Command" -ForegroundColor Gray
    }
    
    try {
        Invoke-Expression $Command | Out-Null
        
        if (Test-Path $OutputFile) {
            $Results = Get-Content $OutputFile | ConvertFrom-Json
            
            # Check results
            $VulnCount = $Results.security_analysis.total_issues
            $RiskLevel = $Results.overall_summary.risk_level
            
            Write-Host "   ✅ Vulnerabilities Found: $VulnCount" -ForegroundColor Green
            Write-Host "   ✅ Risk Level: $RiskLevel" -ForegroundColor Green
            
            # Detailed vulnerability check
            if ($ExpectedVulnerabilities.Count -eq 0) {
                if ($VulnCount -eq 0) {
                    Write-Host "   ✅ PASSED: No vulnerabilities found as expected" -ForegroundColor Green
                    return $true
                } else {
                    Write-Host "   ❌ FAILED: Expected no vulnerabilities but found $VulnCount" -ForegroundColor Red
                    return $false
                }
            } else {
                if ($VulnCount -gt 0) {
                    Write-Host "   ✅ PASSED: Vulnerabilities detected as expected" -ForegroundColor Green
                    
                    # List found vulnerabilities
                    if ($Results.vulnerability_details) {
                        Write-Host "   📊 Found vulnerabilities:" -ForegroundColor Cyan
                        foreach ($vuln in $Results.vulnerability_details) {
                            Write-Host "      - $($vuln.id): $($vuln.title) [$($vuln.severity)]" -ForegroundColor White
                        }
                    }
                    return $true
                } else {
                    Write-Host "   ❌ FAILED: Expected vulnerabilities but none found" -ForegroundColor Red
                    return $false
                }
            }
        } else {
            Write-Host "   ❌ FAILED: Output file not generated" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "   ❌ ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Run all tests
$PassedTests = 0
$TotalTests = $TestCases.Count

Write-Host "`n🚀 Running $TotalTests test cases..." -ForegroundColor Cyan

foreach ($Test in $TestCases) {
    $Result = Test-Contract -ContractFile $Test.File -TestName $Test.Name -ExpectedVulnerabilities $Test.ExpectedVulnerabilities -ExpectedSeverity $Test.ExpectedSeverity
    
    if ($Result) {
        $PassedTests++
    }
}

# Summary
Write-Host "`n📊 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "===============" -ForegroundColor Cyan
Write-Host "Total Tests: $TotalTests" -ForegroundColor White
Write-Host "Passed: $PassedTests" -ForegroundColor Green
Write-Host "Failed: $($TotalTests - $PassedTests)" -ForegroundColor Red

if ($PassedTests -eq $TotalTests) {
    Write-Host "`n🎉 ALL TESTS PASSED!" -ForegroundColor Green
    $ExitCode = 0
} else {
    Write-Host "`n⚠️  SOME TESTS FAILED!" -ForegroundColor Red
    $ExitCode = 1
}

# Generate test report if requested
if ($GenerateReports) {
    Write-Host "`n📝 Generating test reports..." -ForegroundColor Cyan
    
    $ReportPath = "$OutputDir/test-report.html"
    $HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Smart Contract Analyzer Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .test-case { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .passed { border-color: #27ae60; background: #d5f4e6; }
        .failed { border-color: #e74c3c; background: #fdf2f2; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧪 Smart Contract Analyzer Test Report</h1>
        <p>Generated: $(Get-Date)</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Tests:</strong> $TotalTests</p>
        <p><strong>Passed:</strong> $PassedTests</p>
        <p><strong>Failed:</strong> $($TotalTests - $PassedTests)</p>
        <p><strong>Success Rate:</strong> $([math]::Round(($PassedTests / $TotalTests) * 100, 2))%</p>
    </div>
    
    <h2>📋 Test Results</h2>
"@

    foreach ($Test in $TestCases) {
        $Status = if (Test-Path "$OutputDir/$($Test.Name -replace ' ', '_').json") { "passed" } else { "failed" }
        $HtmlReport += @"
    <div class="test-case $Status">
        <h3>$($Test.Name)</h3>
        <p><strong>File:</strong> $($Test.File)</p>
        <p><strong>Status:</strong> $(if($Status -eq 'passed'){'✅ PASSED'}else{'❌ FAILED'})</p>
    </div>
"@
    }
    
    $HtmlReport += @"
</body>
</html>
"@
    
    $HtmlReport | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "   📄 HTML report generated: $ReportPath" -ForegroundColor Green
}

Write-Host "`n🏁 Test suite completed!" -ForegroundColor Cyan

exit $ExitCode
