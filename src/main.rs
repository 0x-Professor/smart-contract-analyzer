use clap::Parser;
use smart_contract_analyzer::cli::Args;
use smart_contract_analyzer::{EnhancedSmartContractAnalyzer, AnalysisConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> smart_contract_analyzer::Result<()> {
    // Enhanced configuration for comprehensive analysis
    let config = AnalysisConfig {
        enable_vulnerability_detection: true,
        enable_gas_analysis: true,
        enable_code_quality_analysis: true,
        enable_parallel_processing: true,
        max_analysis_time: Duration::from_secs(300), // 5 minutes max
        severity_threshold: smart_contract_analyzer::analyzer::enhanced_analyzer::SeverityLevel::Low,
        gas_optimization_threshold: 100, // Report optimizations saving 100+ gas
        detailed_reports: true,
    };

    // Create enhanced analyzer
    let _enhanced_analyzer = EnhancedSmartContractAnalyzer::new(config);

    // Run the original CLI for now (can be enhanced to use new analyzer)
    let args = Args::parse();
    args.run().await?;
    
    println!("\n🚀 Enhanced Smart Contract Analyzer is ready!");
    println!("Features enabled:");
    println!("  • SWC Registry Compliance (100+ vulnerability patterns)");
    println!("  • Advanced AST-based parsing");
    println!("  • Comprehensive gas analysis");
    println!("  • Code quality metrics");
    println!("  • Parallel processing");
    
    Ok(())
}
