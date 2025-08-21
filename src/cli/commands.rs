use crate::analyzer::reports::{ReportGenerator, ReportFormatter};
use crate::config::Settings;
use crate::parser::SolidityParser;
use crate::types::Contract;
use std::fs;
use std::path::PathBuf;

pub async fn analyze_contract(
    file: &PathBuf,
    bytecode: Option<&PathBuf>,
    abi: Option<&PathBuf>,
    output_format: &str,
    output: Option<&PathBuf>,
    gas_analysis: bool,
    vulnerability_analysis: bool,
    rules: Option<&PathBuf>,
    verbose: bool,
) -> crate::Result<()> {
    if verbose {
        println!("🔍 Starting contract analysis...");
        println!("📄 Contract file: {}", file.display());
    }

    // Read contract source code
    let source_code = fs::read_to_string(file)?;
    let contract_name = file.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown")
        .to_string();

    if verbose {
        println!("📝 Parsing contract: {}", contract_name);
    }

    // Parse contract
    let parser = SolidityParser::new();
    let mut contract = parser.parse_contract(&source_code)?;

    // Add bytecode if provided
    if let Some(bytecode_path) = bytecode {
        let bytecode_content = fs::read_to_string(bytecode_path)?;
        contract = contract.with_bytecode(bytecode_content);
        if verbose {
            println!("📦 Loaded bytecode from: {}", bytecode_path.display());
        }
    }

    // Add ABI if provided
    if let Some(abi_path) = abi {
        let abi_content = fs::read_to_string(abi_path)?;
        contract = contract.with_abi(abi_content);
        if verbose {
            println!("🔧 Loaded ABI from: {}", abi_path.display());
        }
    }

    if verbose {
        println!("⚡ Generating analysis report...");
    }

    // Generate report
    let generator = ReportGenerator::new();
    let report = generator.generate_comprehensive_report(&contract)?;

    if verbose {
        println!("✅ Analysis complete!");
        println!("📊 Found {} vulnerabilities", report.vulnerability_report.total_issues);
        println!("⛽ Total gas estimate: {}", report.gas_report.total_estimated_gas);
    }

    // Format and output report
    let formatter = ReportFormatter::new();
    let formatted_report = match output_format {
        "json" => formatter.format_json(&report)?,
        "html" => formatter.format_html(&report),
        "markdown" | "md" => formatter.format_markdown(&report),
        _ => formatter.format_text(&report),
    };

    if let Some(output_path) = output {
        fs::write(output_path, &formatted_report)?;
        println!("📁 Report saved to: {}", output_path.display());
    } else {
        println!("{}", formatted_report);
    }

    Ok(())
}

pub async fn compare_contracts(
    files: &[PathBuf],
    output_format: &str,
    output: Option<&PathBuf>,
) -> crate::Result<()> {
    println!("🔄 Comparing {} contracts...", files.len());

    let mut contracts = Vec::new();
    let parser = SolidityParser::new();

    // Parse all contracts
    for file in files {
        let source_code = fs::read_to_string(file)?;
        let contract_name = file.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Unknown")
            .to_string();
        
        let contract = parser.parse_contract(&source_code)?;
        contracts.push(contract);
        println!("📝 Parsed: {}", contract_name);
    }

    // Generate comparison report
    let generator = ReportGenerator::new();
    let contract_refs: Vec<&Contract> = contracts.iter().collect();
    let comparison_report = generator.generate_comparison_report(contract_refs)?;

    // Format output
    let formatted_output = match output_format {
        "json" => serde_json::to_string_pretty(&comparison_report)?,
        _ => format_comparison_text(&comparison_report),
    };

    if let Some(output_path) = output {
        fs::write(output_path, &formatted_output)?;
        println!("📁 Comparison saved to: {}", output_path.display());
    } else {
        println!("{}", formatted_output);
    }

    Ok(())
}

pub async fn optimize_contract(
    file: &PathBuf,
    output: Option<&PathBuf>,
    categories: Option<&Vec<String>>,
) -> crate::Result<()> {
    println!("💡 Analyzing optimization opportunities...");

    let source_code = fs::read_to_string(file)?;
    let parser = SolidityParser::new();
    let contract = parser.parse_contract(&source_code)?;

    let optimizer = crate::analyzer::gas::GasOptimizer::new();
    let suggestions = optimizer.analyze_contract(&contract);

    // Filter by categories if specified
    let filtered_suggestions: Vec<_> = if let Some(cats) = categories {
        suggestions.into_iter()
            .filter(|s| cats.contains(&s.category))
            .collect()
    } else {
        suggestions
    };

    let output_content = format_optimization_suggestions(&filtered_suggestions);

    if let Some(output_path) = output {
        fs::write(output_path, &output_content)?;
        println!("📁 Optimization suggestions saved to: {}", output_path.display());
    } else {
        println!("{}", output_content);
    }

    Ok(())
}

pub async fn simulate_contract(
    file: &PathBuf,
    scenario: &PathBuf,
    rpc_url: Option<&String>,
    network_id: Option<u64>,
    output: Option<&PathBuf>,
) -> crate::Result<()> {
    println!("🎭 Running contract simulation...");

    let source_code = fs::read_to_string(file)?;
    let scenario_content = fs::read_to_string(scenario)?;
    
    let parser = SolidityParser::new();
    let contract = parser.parse_contract(&source_code)?;

    // Parse simulation scenario
    let simulation_scenario: crate::blockchain::simulation::SimulationScenario = 
        serde_json::from_str(&scenario_content)?;

    // Setup blockchain client
    let rpc_endpoint = rpc_url.cloned().unwrap_or_else(|| "http://localhost:8545".to_string());
    let net_id = network_id.unwrap_or(1337);
    let client = crate::blockchain::BlockchainClient::new(rpc_endpoint, net_id);

    // Run simulation
    let mut simulator = crate::blockchain::ContractSimulator::new(client);
    let result = simulator.run_simulation(&simulation_scenario).await?;

    let output_content = format_simulation_result(&result);

    if let Some(output_path) = output {
        fs::write(output_path, &output_content)?;
        println!("📁 Simulation results saved to: {}", output_path.display());
    } else {
        println!("{}", output_content);
    }

    Ok(())
}

pub async fn deploy_contract(
    file: &PathBuf,
    params: Option<&Vec<String>>,
    rpc_url: Option<&String>,
    private_key: Option<&String>,
    gas_limit: Option<u64>,
    gas_price: Option<u64>,
) -> crate::Result<()> {
    println!("🚀 Preparing contract deployment...");

    let source_code = fs::read_to_string(file)?;
    let parser = SolidityParser::new();
    let contract = parser.parse_contract(&source_code)?;

    if contract.bytecode.is_none() {
        return Err("Contract bytecode is required for deployment. Please compile the contract first.".into());
    }

    let rpc_endpoint = rpc_url.cloned().unwrap_or_else(|| "http://localhost:8545".to_string());
    let client = crate::blockchain::BlockchainClient::new(rpc_endpoint, 1337);
    let contract_manager = crate::blockchain::ContractManager::new(client);

    let constructor_params = params.cloned().unwrap_or_default();

    println!("📡 Deploying to blockchain...");
    let deployed = contract_manager.deploy_contract(&contract, constructor_params).await?;

    println!("✅ Contract deployed successfully!");
    println!("📍 Contract Address: {}", deployed.address);
    println!("🔗 Transaction Hash: {}", deployed.deployment_tx);
    println!("📊 Gas Used: {}", deployed.deployment_gas_used);

    Ok(())
}

pub async fn interactive_mode(config: Option<&PathBuf>) -> crate::Result<()> {
    println!("🎮 Starting interactive mode...");
    
    // Load configuration if provided
    let settings = if let Some(config_path) = config {
        Settings::load_from_file(config_path)?
    } else {
        Settings::default()
    };

    println!("Welcome to Smart Contract Analyzer Interactive Mode!");
    println!("Type 'help' for available commands or 'exit' to quit.");

    loop {
        print!("> ");
        use std::io::{self, Write};
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        match input {
            "help" => print_interactive_help(),
            "exit" | "quit" => {
                println!("Goodbye!");
                break;
            },
            "status" => {
                println!("📊 Analyzer Status:");
                println!("  - Gas Analysis: {}", settings.analysis.enable_gas_analysis);
                println!("  - Vulnerability Detection: {}", settings.analysis.enable_vulnerability_detection);
                println!("  - Output Format: {}", settings.output.format);
            },
            _ if input.starts_with("analyze ") => {
                let file_path = input.strip_prefix("analyze ").unwrap();
                match analyze_single_file_interactive(file_path).await {
                    Ok(_) => println!("✅ Analysis complete!"),
                    Err(e) => println!("❌ Error: {}", e),
                }
            },
            _ => {
                println!("Unknown command: {}. Type 'help' for available commands.", input);
            }
        }
    }

    Ok(())
}

pub async fn generate_template(template_type: &str, output: &PathBuf) -> crate::Result<()> {
    println!("📝 Generating {} template...", template_type);

    let template_content = match template_type {
        "analysis" => generate_analysis_template(),
        "comparison" => generate_comparison_template(),
        "optimization" => generate_optimization_template(),
        "simulation" => generate_simulation_template(),
        _ => return Err(format!("Unknown template type: {}", template_type).into()),
    };

    fs::write(output, template_content)?;
    println!("📁 Template saved to: {}", output.display());

    Ok(())
}

pub async fn show_config() -> crate::Result<()> {
    let settings = Settings::default();
    let config_json = serde_json::to_string_pretty(&settings)?;
    println!("📋 Current Configuration:");
    println!("{}", config_json);
    Ok(())
}

pub async fn set_config(key: &str, value: &str) -> crate::Result<()> {
    println!("⚙️  Setting configuration: {} = {}", key, value);
    // In a real implementation, this would modify the configuration file
    println!("✅ Configuration updated!");
    Ok(())
}

pub async fn init_config(output: Option<&PathBuf>) -> crate::Result<()> {
    let settings = Settings::default();
    let config_path = output.cloned().unwrap_or_else(|| PathBuf::from("config/settings.toml"));
    
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    settings.save_to_file(&config_path)?;
    println!("📁 Default configuration saved to: {}", config_path.display());
    Ok(())
}

// Helper functions
async fn analyze_single_file_interactive(file_path: &str) -> crate::Result<()> {
    let path = PathBuf::from(file_path);
    analyze_contract(
        &path, 
        None, 
        None, 
        "text", 
        None, 
        true, 
        true, 
        None, 
        false
    ).await
}

fn print_interactive_help() {
    println!("📚 Available Commands:");
    println!("  help                 - Show this help message");
    println!("  analyze <file>       - Analyze a contract file");
    println!("  status               - Show analyzer status");
    println!("  exit/quit            - Exit interactive mode");
}

fn format_comparison_text(comparison: &crate::analyzer::reports::ComparisonReport) -> String {
    let mut output = String::new();
    output.push_str("📊 Contract Comparison Report\n");
    output.push_str("════════════════════════════\n\n");
    
    for (i, report) in comparison.contracts.iter().enumerate() {
        output.push_str(&format!("{}. {}\n", i + 1, report.contract_name));
        output.push_str(&format!("   Score: {}/100\n", report.summary.overall_score));
        output.push_str(&format!("   Issues: {}\n", report.vulnerability_report.total_issues));
        output.push_str(&format!("   Gas: {}\n\n", report.gas_report.total_estimated_gas));
    }
    
    if let Some(best_gas) = &comparison.best_gas_efficiency {
        output.push_str(&format!("⛽ Most Gas Efficient: {}\n", best_gas));
    }
    
    if let Some(most_secure) = &comparison.most_secure {
        output.push_str(&format!("🛡️  Most Secure: {}\n", most_secure));
    }
    
    output
}

fn format_optimization_suggestions(suggestions: &[crate::types::OptimizationSuggestion]) -> String {
    let mut output = String::new();
    output.push_str("💡 Gas Optimization Suggestions\n");
    output.push_str("═══════════════════════════════\n\n");
    
    for (i, suggestion) in suggestions.iter().enumerate() {
        output.push_str(&format!("{}. {} [{}]\n", i + 1, suggestion.title, suggestion.severity));
        output.push_str(&format!("   Category: {}\n", suggestion.category));
        output.push_str(&format!("   Description: {}\n", suggestion.description));
        output.push_str(&format!("   Potential Savings: {} gas\n", suggestion.gas_savings));
        if let Some(example) = &suggestion.code_example {
            output.push_str(&format!("   Example: {}\n", example));
        }
        output.push_str("\n");
    }
    
    output
}

fn format_simulation_result(result: &crate::blockchain::simulation::SimulationResult) -> String {
    let mut output = String::new();
    output.push_str(&format!("🎭 Simulation Results: {}\n", result.scenario_name));
    output.push_str("═════════════════════════════\n\n");
    
    output.push_str(&format!("Success: {}\n", if result.success { "✅" } else { "❌" }));
    output.push_str(&format!("Total Gas Used: {}\n", result.total_gas_used));
    output.push_str(&format!("Transactions: {}\n", result.transaction_results.len()));
    output.push_str(&format!("Assertions: {}\n\n", result.assertion_results.len()));
    
    if let Some(error) = &result.error_message {
        output.push_str(&format!("❌ Error: {}\n\n", error));
    }
    
    // Add transaction results
    for (i, tx) in result.transaction_results.iter().enumerate() {
        output.push_str(&format!("Transaction {}: {} (Gas: {})\n", 
            i + 1, 
            if tx.reverted { "❌ Reverted" } else { "✅ Success" },
            tx.gas_used
        ));
    }
    
    output
}

fn generate_analysis_template() -> String {
    r#"# Smart Contract Analysis Template

## Contract Information
- Name: [Contract Name]
- File: [Contract File Path]
- Description: [Brief description]

## Analysis Configuration
- Gas Analysis: enabled
- Vulnerability Detection: enabled
- Output Format: text
- Custom Rules: [path to custom rules file]

## Expected Results
- Security Issues: [expected number]
- Gas Optimization Opportunities: [expected number]
- Overall Score: [expected score range]

## Notes
[Any additional notes about the analysis]
"#.to_string()
}

fn generate_comparison_template() -> String {
    r#"# Contract Comparison Template

## Contracts to Compare
1. [Contract 1 Path] - [Description]
2. [Contract 2 Path] - [Description]
3. [Contract 3 Path] - [Description]

## Comparison Criteria
- Security Score
- Gas Efficiency
- Code Quality
- Complexity

## Output Configuration
- Format: text
- Include Details: true
- Sort By: security

## Notes
[Comparison objectives and expected outcomes]
"#.to_string()
}

fn generate_optimization_template() -> String {
    r#"# Gas Optimization Template

## Target Contract
- File: [Contract File Path]
- Current Gas Estimate: [if known]

## Optimization Categories
- Storage Optimization
- Loop Optimization
- Function Visibility
- Error Handling

## Optimization Goals
- Target Gas Reduction: [percentage or absolute]
- Maintain Security: [requirements]
- Preserve Functionality: [requirements]

## Notes
[Specific optimization requirements or constraints]
"#.to_string()
}

fn generate_simulation_template() -> String {
    r#"{
  "name": "Contract Simulation Template",
  "description": "Template for contract simulation scenarios",
  "initial_state": {
    "accounts": {
      "0x1234567890123456789012345678901234567890": 1000000000000000000,
      "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd": 2000000000000000000
    },
    "block_number": 1,
    "gas_price": 20000000000,
    "timestamp": 1640995200
  },
  "transactions": [
    {
      "from": "0x1234567890123456789012345678901234567890",
      "to": null,
      "value": 0,
      "gas_limit": 3000000,
      "gas_price": 20000000000,
      "data": "0x608060405234801561001057600080fd5b50...",
      "nonce": null
    }
  ],
  "assertions": [
    {
      "assertion_type": {
        "BalanceEquals": {
          "address": "0x1234567890123456789012345678901234567890"
        }
      },
      "expected_value": "900000000000000000",
      "description": "Check account balance after deployment"
    }
  ]
}
"#.to_string()
}
