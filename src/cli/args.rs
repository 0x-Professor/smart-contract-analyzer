use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "smart-contract-analyzer")]
#[command(about = "A comprehensive Ethereum smart contract analyzer")]
#[command(version = "1.0")]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a smart contract
    Analyze {
        /// Path to the Solidity contract file
        #[arg(short, long)]
        file: PathBuf,

        /// Optional bytecode file path
        #[arg(short, long)]
        bytecode: Option<PathBuf>,

        /// Optional ABI file path
        #[arg(short, long)]
        abi: Option<PathBuf>,

        /// Output format (json, html, text, markdown)
        #[arg(short, long, default_value = "text")]
        output_format: String,

        /// Output file path
        #[arg(short = 'O', long)]
        output: Option<PathBuf>,

        /// Enable gas analysis
        #[arg(long, default_value = "true")]
        gas_analysis: bool,

        /// Enable vulnerability detection
        #[arg(long, default_value = "true")]
        vulnerability_analysis: bool,

        /// Custom rules file path
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Compare multiple contracts
    Compare {
        /// Contract files to compare
        #[arg(short, long, num_args = 1..)]
        files: Vec<PathBuf>,

        /// Output format
        #[arg(short, long, default_value = "text")]
        output_format: String,

        /// Output file path
        #[arg(short = 'O', long)]
        output: Option<PathBuf>,
    },

    /// Generate optimization suggestions
    Optimize {
        /// Path to the contract file
        #[arg(short, long)]
        file: PathBuf,

        /// Output file for optimized suggestions
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Focus on specific optimization categories
        #[arg(long)]
        categories: Option<Vec<String>>,
    },

    /// Simulate contract execution
    Simulate {
        /// Path to the contract file
        #[arg(short, long)]
        file: PathBuf,

        /// Simulation scenario file
        #[arg(short, long)]
        scenario: PathBuf,

        /// RPC endpoint for blockchain connection
        #[arg(long)]
        rpc_url: Option<String>,

        /// Network ID
        #[arg(long)]
        network_id: Option<u64>,

        /// Output simulation results
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Deploy contract (for testing)
    Deploy {
        /// Path to the contract file
        #[arg(short, long)]
        file: PathBuf,

        /// Constructor parameters
        #[arg(short, long)]
        params: Option<Vec<String>>,

        /// RPC endpoint
        #[arg(long)]
        rpc_url: Option<String>,

        /// Private key for deployment
        #[arg(long)]
        private_key: Option<String>,

        /// Gas limit
        #[arg(long)]
        gas_limit: Option<u64>,

        /// Gas price
        #[arg(long)]
        gas_price: Option<u64>,
    },

    /// Interactive mode
    Interactive {
        /// Configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Generate report templates
    Template {
        /// Template type (analysis, comparison, optimization)
        #[arg(short, long)]
        template_type: String,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Set configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
    /// Generate default configuration file
    Init {
        /// Configuration file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

impl Args {
    pub async fn run(&self) -> crate::Result<()> {
        match &self.command {
            Commands::Analyze { 
                file, 
                bytecode, 
                abi, 
                output_format, 
                output,
                gas_analysis,
                vulnerability_analysis,
                rules,
                verbose
            } => {
                crate::cli::commands::analyze_contract(
                    file,
                    bytecode.as_ref(),
                    abi.as_ref(),
                    output_format,
                    output.as_ref(),
                    *gas_analysis,
                    *vulnerability_analysis,
                    rules.as_ref(),
                    *verbose
                ).await
            },
            Commands::Compare { files, output_format, output } => {
                crate::cli::commands::compare_contracts(files, output_format, output.as_ref()).await
            },
            Commands::Optimize { file, output, categories } => {
                crate::cli::commands::optimize_contract(file, output.as_ref(), categories.as_ref()).await
            },
            Commands::Simulate { file, scenario, rpc_url, network_id, output } => {
                crate::cli::commands::simulate_contract(
                    file, 
                    scenario, 
                    rpc_url.as_ref(), 
                    *network_id, 
                    output.as_ref()
                ).await
            },
            Commands::Deploy { file, params, rpc_url, private_key, gas_limit, gas_price } => {
                crate::cli::commands::deploy_contract(
                    file,
                    params.as_ref(),
                    rpc_url.as_ref(),
                    private_key.as_ref(),
                    *gas_limit,
                    *gas_price
                ).await
            },
            Commands::Interactive { config } => {
                crate::cli::commands::interactive_mode(config.as_ref()).await
            },
            Commands::Template { template_type, output } => {
                crate::cli::commands::generate_template(template_type, output).await
            },
            Commands::Config { action } => {
                match action {
                    ConfigCommands::Show => crate::cli::commands::show_config().await,
                    ConfigCommands::Set { key, value } => {
                        crate::cli::commands::set_config(key, value).await
                    },
                    ConfigCommands::Init { output } => {
                        crate::cli::commands::init_config(output.as_ref()).await
                    },
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub gas_analysis: bool,
    pub vulnerability_analysis: bool,
    pub optimization_analysis: bool,
    pub custom_rules_path: Option<PathBuf>,
    pub output_format: String,
    pub output_path: Option<PathBuf>,
    pub verbose: bool,
    pub include_source: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            gas_analysis: true,
            vulnerability_analysis: true,
            optimization_analysis: true,
            custom_rules_path: None,
            output_format: "text".to_string(),
            output_path: None,
            verbose: false,
            include_source: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComparisonOptions {
    pub output_format: String,
    pub output_path: Option<PathBuf>,
    pub include_details: bool,
    pub sort_by: String, // "security", "gas", "name"
}

impl Default for ComparisonOptions {
    fn default() -> Self {
        Self {
            output_format: "text".to_string(),
            output_path: None,
            include_details: true,
            sort_by: "security".to_string(),
        }
    }
}
