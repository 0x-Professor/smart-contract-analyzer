use crate::types::{Contract, OptimizationSuggestion};
use std::collections::HashSet;

pub struct GasOptimizer {
    optimization_rules: Vec<OptimizationRule>,
}

impl Default for GasOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl GasOptimizer {
    pub fn new() -> Self {
        Self {
            optimization_rules: Self::load_default_rules(),
        }
    }

    pub fn analyze_contract(&self, contract: &Contract) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        for rule in &self.optimization_rules {
            suggestions.extend((rule.analyzer)(contract));
        }

        suggestions
    }

    fn load_default_rules() -> Vec<OptimizationRule> {
        vec![
            OptimizationRule {
                name: "Storage Packing".to_string(),
                category: "Storage".to_string(),
                analyzer: Box::new(Self::analyze_storage_packing),
            },
            OptimizationRule {
                name: "Loop Optimization".to_string(),
                category: "Computation".to_string(),
                analyzer: Box::new(Self::analyze_loop_optimization),
            },
            OptimizationRule {
                name: "Function Visibility".to_string(),
                category: "Access".to_string(),
                analyzer: Box::new(Self::analyze_function_visibility),
            },
            OptimizationRule {
                name: "Constant Usage".to_string(),
                category: "Storage".to_string(),
                analyzer: Box::new(Self::analyze_constant_usage),
            },
            OptimizationRule {
                name: "Error Handling".to_string(),
                category: "ErrorHandling".to_string(),
                analyzer: Box::new(Self::analyze_error_handling),
            },
        ]
    }

    fn analyze_storage_packing(contract: &Contract) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();
        let source = &contract.source_code;

        // Check for potential storage packing opportunities
        if source.contains("bool") && (source.contains("uint256") || source.contains("address")) {
            suggestions.push(OptimizationSuggestion {
                title: "Storage Packing Opportunity".to_string(),
                description: "Consider packing boolean and smaller types together to save storage slots".to_string(),
                category: "Storage".to_string(),
                severity: "Medium".to_string(),
                gas_savings: 20000,
                code_example: Some("struct Packed { bool flag; uint248 value; }".to_string()),
            });
        }

        if source.matches("uint256").count() > 3 {
            suggestions.push(OptimizationSuggestion {
                title: "Consider Smaller Integer Types".to_string(),
                description: "If values don't need full uint256 range, use smaller types for packing".to_string(),
                category: "Storage".to_string(),
                severity: "Low".to_string(),
                gas_savings: 10000,
                code_example: Some("uint128 instead of uint256 when possible".to_string()),
            });
        }

        suggestions
    }

    fn analyze_loop_optimization(contract: &Contract) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();
        let source = &contract.source_code;

        if source.contains("for (uint256 i = 0;") && source.contains("i++") {
            suggestions.push(OptimizationSuggestion {
                title: "Optimize Loop Increment".to_string(),
                description: "Use ++i instead of i++ and consider unchecked arithmetic".to_string(),
                category: "Computation".to_string(),
                severity: "Low".to_string(),
                gas_savings: 5,
                code_example: Some("for (uint256 i = 0; i < length; ++i) { unchecked { ++i; } }".to_string()),
            });
        }

        if source.contains("for") && source.contains(".length") {
            suggestions.push(OptimizationSuggestion {
                title: "Cache Array Length".to_string(),
                description: "Cache array length outside the loop to avoid repeated SLOAD operations".to_string(),
                category: "Computation".to_string(),
                severity: "Medium".to_string(),
                gas_savings: 100,
                code_example: Some("uint256 length = array.length; for(uint256 i = 0; i < length; ++i)".to_string()),
            });
        }

        suggestions
    }

    fn analyze_function_visibility(contract: &Contract) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        for function in &contract.functions {
            if function.visibility == "public" && !contract.source_code.contains(&format!("{}(", function.name)) {
                // Function is public but might not need to be
                suggestions.push(OptimizationSuggestion {
                    title: format!("Consider making function '{}' external", function.name),
                    description: "Functions only called externally should be marked as external".to_string(),
                    category: "Access".to_string(),
                    severity: "Low".to_string(),
                    gas_savings: 20,
                    code_example: Some(format!("function {}(...) external", function.name)),
                });
            }
        }

        suggestions
    }

    fn analyze_constant_usage(contract: &Contract) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();
        let source = &contract.source_code;

        // Look for hardcoded values that could be constants
        let number_pattern = regex::Regex::new(r"\b\d{4,}\b").unwrap();
        let numbers: HashSet<_> = number_pattern.find_iter(source)
            .map(|m| m.as_str())
            .collect();

        if numbers.len() > 3 {
            suggestions.push(OptimizationSuggestion {
                title: "Use Constants for Magic Numbers".to_string(),
                description: "Replace magic numbers with named constants for better readability and gas efficiency".to_string(),
                category: "Storage".to_string(),
                severity: "Low".to_string(),
                gas_savings: 50,
                code_example: Some("uint256 constant MAGIC_NUMBER = 12345;".to_string()),
            });
        }

        suggestions
    }

    fn analyze_error_handling(contract: &Contract) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();
        let source = &contract.source_code;

        let require_count = source.matches("require(").count();
        if require_count > 3 {
            suggestions.push(OptimizationSuggestion {
                title: "Use Custom Errors".to_string(),
                description: "Replace require statements with custom errors to save gas".to_string(),
                category: "ErrorHandling".to_string(),
                severity: "Medium".to_string(),
                gas_savings: require_count * 50,
                code_example: Some("error InvalidValue(); if (value == 0) revert InvalidValue();".to_string()),
            });
        }

        suggestions
    }

    pub fn suggest_storage_layout(&self, contract: &Contract) -> Vec<StorageLayoutSuggestion> {
        let mut suggestions = Vec::new();

        // Analyze variable declarations and suggest optimal layout
        for (i, variable) in contract.state_variables.iter().enumerate() {
            if variable.var_type == "bool" || variable.var_type.starts_with("uint8") {
                if i > 0 && contract.state_variables[i-1].var_type == "uint256" {
                    suggestions.push(StorageLayoutSuggestion {
                        variable_name: variable.name.clone(),
                        current_position: i,
                        suggested_position: 0,
                        reason: "Move smaller types together for packing".to_string(),
                        gas_savings: 20000,
                    });
                }
            }
        }

        suggestions
    }

    pub fn analyze_function_optimization(&self, contract: &Contract) -> Vec<FunctionOptimization> {
        let mut optimizations = Vec::new();

        for function in &contract.functions {
            let mut function_opts = Vec::new();

            // Check for common optimization opportunities
            if function.body.contains("require") {
                function_opts.push("Consider using custom errors instead of require".to_string());
            }

            if function.body.contains("for") && function.body.contains("storage") {
                function_opts.push("Avoid storage operations in loops".to_string());
            }

            if function.visibility == "public" && function.parameters.is_empty() {
                function_opts.push("Consider making parameterless functions external".to_string());
            }

            if !function_opts.is_empty() {
                optimizations.push(FunctionOptimization {
                    function_name: function.name.clone(),
                    optimizations: function_opts,
                    estimated_savings: 100,
                });
            }
        }

        optimizations
    }
}

pub struct OptimizationRule {
    pub name: String,
    pub category: String,
    pub analyzer: Box<dyn Fn(&Contract) -> Vec<OptimizationSuggestion> + Send + Sync>,
}

#[derive(Debug, Clone)]
pub struct StorageLayoutSuggestion {
    pub variable_name: String,
    pub current_position: usize,
    pub suggested_position: usize,
    pub reason: String,
    pub gas_savings: usize,
}

#[derive(Debug, Clone)]
pub struct FunctionOptimization {
    pub function_name: String,
    pub optimizations: Vec<String>,
    pub estimated_savings: u32,
}
