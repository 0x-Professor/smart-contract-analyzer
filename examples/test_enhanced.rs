/// Test the enhanced smart contract analyzer with a simple working example
use smart_contract_analyzer::{EnhancedSmartContractAnalyzer, AnalysisConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Testing Enhanced Smart Contract Analyzer");
    
    // Simple test contract
    let test_contract = r#"
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;
    
    function setValue(uint256 _value) public {
        value = _value;
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
}
"#;
    
    // Create analyzer with basic configuration
    let config = AnalysisConfig {
        enable_vulnerability_detection: false, // Disable for now
        enable_gas_analysis: false,           // Disable for now
        enable_code_quality_analysis: false,  // Disable for now
        enable_parallel_processing: false,
        max_analysis_time: Duration::from_secs(30),
        severity_threshold: smart_contract_analyzer::analyzer::enhanced_analyzer::SeverityLevel::Low,
        gas_optimization_threshold: 100,
        detailed_reports: true,
    };
    
    // Test the enhanced analyzer creation
    match EnhancedSmartContractAnalyzer::new(config.clone()).analyze_contract(test_contract, Some("TestContract")) {
        Ok(report) => {
            println!("✅ Analysis completed successfully!");
            println!("Contract: {}", report.contract_name);
            println!("Duration: {:?}", report.analysis_duration);
            println!("Functions found: {}", report.parsing_result.functions_analyzed);
        }
        Err(e) => {
            println!("❌ Analysis failed: {}", e);
            return Err(e.into());
        }
    }
    
    Ok(())
}
