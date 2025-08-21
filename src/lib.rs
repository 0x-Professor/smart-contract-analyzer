pub mod config;
pub mod parser;
pub mod detector;
pub mod analyzer;
pub mod blockchain;
pub mod cli;
pub mod utils;
pub mod types;

pub use config::*;
pub use parser::*;
pub use detector::*;
pub use analyzer::*;
pub use blockchain::*;
pub use cli::*;
pub use utils::*;
pub use types::*;

// Re-export error types and Result from utils
pub use utils::errors::{SmartContractAnalyzerError, Result};

// Re-export main types
pub use config::Settings;
pub use types::{Contract, AnalysisReport, Vulnerability};

// Re-export enhanced components for easier access
pub use analyzer::enhanced_analyzer::{EnhancedSmartContractAnalyzer, AnalysisConfig};
pub use parser::enhanced_solidity::EnhancedSolidityParser;
pub use detector::enhanced_detector::EnhancedVulnerabilityDetector;
pub use analyzer::gas_analyzer::GasAnalyzer;
