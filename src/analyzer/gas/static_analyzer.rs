use crate::parser::{BytecodeParser, Instruction};
use crate::types::{Contract, GasReport};
use std::collections::HashMap;

pub struct StaticGasAnalyzer {
    bytecode_parser: BytecodeParser,
}

impl Default for StaticGasAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StaticGasAnalyzer {
    pub fn new() -> Self {
        Self {
            bytecode_parser: BytecodeParser::new(),
        }
    }

    pub fn analyze_contract(&self, contract: &Contract) -> crate::Result<GasReport> {
        let mut total_estimated_gas = 0;
        let mut function_gas_costs = HashMap::new();
        let mut optimization_suggestions = Vec::new();

        // Analyze bytecode if available
        if let Some(bytecode) = &contract.bytecode {
            let instructions = self.bytecode_parser.parse(bytecode)?;
            let gas_analysis = self.bytecode_parser.analyze_gas_usage(&instructions);
            
            total_estimated_gas = gas_analysis.total_estimated_gas;
            optimization_suggestions.extend(gas_analysis.optimization_suggestions);
        }

        // Analyze functions from source code
        for function in &contract.functions {
            let estimated_gas = self.estimate_function_gas(&function.name, &function.body);
            function_gas_costs.insert(function.name.clone(), estimated_gas);
        }

        // Add static analysis suggestions
        optimization_suggestions.extend(self.generate_static_suggestions(contract));

        Ok(GasReport {
            contract_name: contract.name.clone(),
            total_estimated_gas,
            function_gas_costs,
            optimization_suggestions,
            expensive_operations: Vec::new(),
            storage_operations: 0,
            external_calls: 0,
        })
    }

    fn estimate_function_gas(&self, _function_name: &str, function_body: &str) -> u32 {
        let mut gas_cost = 21000; // Base transaction cost

        // Simple heuristics for gas estimation
        gas_cost += function_body.matches("SSTORE").count() as u32 * 20000;
        gas_cost += function_body.matches("SLOAD").count() as u32 * 800;
        gas_cost += function_body.matches("CALL").count() as u32 * 700;
        gas_cost += function_body.matches("CREATE").count() as u32 * 32000;
        gas_cost += function_body.matches("SHA3").count() as u32 * 30;

        gas_cost
    }

    fn generate_static_suggestions(&self, contract: &Contract) -> Vec<String> {
        let mut suggestions = Vec::new();

        // Check for common gas optimization patterns
        let source = &contract.source_code;

        if source.contains("for (uint256 i = 0;") {
            suggestions.push("Consider using unchecked arithmetic in for loops when overflow is not possible".to_string());
        }

        if source.contains("string memory") || source.contains("string storage") {
            suggestions.push("Consider using bytes32 instead of string for fixed-length strings".to_string());
        }

        if source.contains("public") && source.contains("constant") {
            suggestions.push("Consider using private visibility for constants when possible".to_string());
        }

        if source.matches("require(").count() > 5 {
            suggestions.push("Consider using custom errors instead of require strings to save gas".to_string());
        }

        suggestions
    }

    pub fn analyze_loop_gas(&self, source_code: &str) -> Vec<LoopGasIssue> {
        let mut issues = Vec::new();
        
        // Simple regex-based detection of potential gas issues in loops
        if source_code.contains("for") && source_code.contains("SSTORE") {
            issues.push(LoopGasIssue {
                issue_type: "Storage write in loop".to_string(),
                description: "Writing to storage in a loop can be expensive".to_string(),
                severity: "High".to_string(),
                suggestion: "Consider batching storage writes or using memory".to_string(),
            });
        }

        if source_code.contains("while") && source_code.contains("external") {
            issues.push(LoopGasIssue {
                issue_type: "External call in loop".to_string(),
                description: "External calls in loops can lead to DoS attacks".to_string(),
                severity: "High".to_string(),
                suggestion: "Avoid external calls in loops or implement proper gas limits".to_string(),
            });
        }

        issues
    }

    pub fn calculate_deployment_gas(&self, contract: &Contract) -> u32 {
        let mut deployment_gas = 21000; // Base cost

        if let Some(bytecode) = &contract.bytecode {
            // Approximate deployment cost based on bytecode size
            let bytecode_size = bytecode.len() / 2; // Assuming hex encoding
            deployment_gas += (bytecode_size as u32) * 200; // Approximate cost per byte
        }

        // Add constructor gas if present
        if contract.functions.iter().any(|f| f.name == "constructor") {
            deployment_gas += 50000; // Estimated constructor execution cost
        }

        deployment_gas
    }
}

#[derive(Debug, Clone)]
pub struct LoopGasIssue {
    pub issue_type: String,
    pub description: String,
    pub severity: String,
    pub suggestion: String,
}
