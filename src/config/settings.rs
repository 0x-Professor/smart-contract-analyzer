use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub general: GeneralSettings,
    pub analysis: AnalysisSettings,
    pub output: OutputSettings,
    pub blockchain: BlockchainSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralSettings {
    pub log_level: String,
    pub max_concurrent_analyses: usize,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSettings {
    pub enable_gas_analysis: bool,
    pub enable_vulnerability_detection: bool,
    pub enable_optimization_suggestions: bool,
    pub custom_rules_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSettings {
    pub format: String, // json, yaml, text
    pub output_dir: PathBuf,
    pub include_source_code: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainSettings {
    pub rpc_url: String,
    pub network_id: u64,
    pub gas_price: Option<u64>,
    pub block_confirmations: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            general: GeneralSettings {
                log_level: "info".to_string(),
                max_concurrent_analyses: 4,
                timeout_seconds: 300,
            },
            analysis: AnalysisSettings {
                enable_gas_analysis: true,
                enable_vulnerability_detection: true,
                enable_optimization_suggestions: true,
                custom_rules_path: None,
            },
            output: OutputSettings {
                format: "json".to_string(),
                output_dir: PathBuf::from("./reports"),
                include_source_code: false,
                verbose: false,
            },
            blockchain: BlockchainSettings {
                rpc_url: "http://localhost:8545".to_string(),
                network_id: 1337,
                gas_price: None,
                block_confirmations: 1,
            },
        }
    }
}

impl Settings {
    pub fn load_from_file(path: &PathBuf) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = toml::from_str(&content)?;
        Ok(settings)
    }

    pub fn save_to_file(&self, path: &PathBuf) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
