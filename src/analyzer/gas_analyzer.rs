use crate::parser::enhanced_solidity::{EnhancedContract, EnhancedFunction, EnhancedVariable, StateMutability, Visibility};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::OnceLock;

/// Advanced gas analysis and optimization detector
pub struct GasAnalyzer {
    operation_costs: HashMap<String, u64>,
    optimization_patterns: HashMap<String, OptimizationPattern>,
}

#[derive(Debug, Clone)]
pub struct OptimizationPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern_type: OptimizationType,
    pub potential_savings: GasSavings,
    pub detection_rules: Vec<String>,
    pub recommendation: String,
    pub examples: Vec<OptimizationExample>,
}

#[derive(Debug, Clone)]
pub enum OptimizationType {
    Storage,
    Loop,
    Function,
    Variable,
    Arithmetic,
    External,
    Logic,
}

#[derive(Debug, Clone)]
pub struct GasSavings {
    pub min_savings: u64,
    pub max_savings: u64,
    pub per_operation_savings: Option<u64>,
    pub confidence_level: f32,
}

#[derive(Debug, Clone)]
pub struct OptimizationExample {
    pub before: String,
    pub after: String,
    pub savings_explanation: String,
}

#[derive(Debug, Clone)]
pub struct GasAnalysisReport {
    pub total_estimated_cost: u64,
    pub deployment_cost: u64,
    pub function_costs: BTreeMap<String, FunctionGasAnalysis>,
    pub optimizations: Vec<GasOptimization>,
    pub storage_analysis: StorageAnalysis,
    pub overall_efficiency: EfficiencyRating,
}

#[derive(Debug, Clone)]
pub struct FunctionGasAnalysis {
    pub function_name: String,
    pub estimated_cost: GasCostRange,
    pub complexity_score: u32,
    pub operations: Vec<GasOperation>,
    pub optimization_potential: u32, // 0-100 score
}

#[derive(Debug, Clone)]
pub struct GasCostRange {
    pub min: u64,
    pub max: u64,
    pub typical: u64,
}

#[derive(Debug, Clone)]
pub struct GasOperation {
    pub operation_type: String,
    pub cost: u64,
    pub count: u32,
    pub line_number: Option<usize>,
    pub optimization_note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GasOptimization {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: OptimizationSeverity,
    pub potential_savings: GasSavings,
    pub location: OptimizationLocation,
    pub recommendation: String,
    pub code_examples: Option<OptimizationExample>,
}

#[derive(Debug, Clone)]
pub enum OptimizationSeverity {
    Critical, // Major gas savings possible
    High,     // Significant savings
    Medium,   // Moderate savings
    Low,      // Minor savings
}

#[derive(Debug, Clone)]
pub struct OptimizationLocation {
    pub function_name: Option<String>,
    pub line_number: Option<usize>,
    pub code_snippet: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StorageAnalysis {
    pub total_slots_used: u32,
    pub wasted_storage: u32,
    pub packing_efficiency: f32, // 0-100%
    pub optimization_suggestions: Vec<StorageOptimization>,
}

#[derive(Debug, Clone)]
pub struct StorageOptimization {
    pub variable_name: String,
    pub current_slot: u32,
    pub suggested_slot: u32,
    pub savings: u64,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EfficiencyRating {
    Excellent, // <5% optimization potential
    Good,      // 5-15% optimization potential
    Fair,      // 15-30% optimization potential
    Poor,      // >30% optimization potential
}

static GAS_ANALYZER_INSTANCE: OnceLock<GasAnalyzer> = OnceLock::new();

impl GasAnalyzer {
    pub fn instance() -> &'static GasAnalyzer {
        GAS_ANALYZER_INSTANCE.get_or_init(|| Self::new())
    }

    pub fn new() -> Self {
        let mut analyzer = Self {
            operation_costs: HashMap::new(),
            optimization_patterns: HashMap::new(),
        };
        
        analyzer.initialize_gas_costs();
        analyzer.initialize_optimization_patterns();
        analyzer
    }

    fn initialize_gas_costs(&mut self) {
        // Basic operation costs (approximate values for latest EVM)
        self.operation_costs.insert("ADD".to_string(), 3);
        self.operation_costs.insert("MUL".to_string(), 5);
        self.operation_costs.insert("SUB".to_string(), 3);
        self.operation_costs.insert("DIV".to_string(), 5);
        self.operation_costs.insert("MOD".to_string(), 5);
        self.operation_costs.insert("EXP".to_string(), 10);
        
        // Memory operations
        self.operation_costs.insert("MLOAD".to_string(), 3);
        self.operation_costs.insert("MSTORE".to_string(), 3);
        self.operation_costs.insert("MSTORE8".to_string(), 3);
        
        // Storage operations (expensive!)
        self.operation_costs.insert("SLOAD".to_string(), 800);
        self.operation_costs.insert("SSTORE_NEW".to_string(), 20000);
        self.operation_costs.insert("SSTORE_UPDATE".to_string(), 5000);
        self.operation_costs.insert("SSTORE_REFUND".to_string(), 2900);
        
        // Call operations
        self.operation_costs.insert("CALL".to_string(), 2600);
        self.operation_costs.insert("DELEGATECALL".to_string(), 2600);
        self.operation_costs.insert("STATICCALL".to_string(), 2600);
        self.operation_costs.insert("CREATE".to_string(), 32000);
        self.operation_costs.insert("CREATE2".to_string(), 32000);
        
        // Logging
        self.operation_costs.insert("LOG0".to_string(), 375);
        self.operation_costs.insert("LOG1".to_string(), 750);
        self.operation_costs.insert("LOG2".to_string(), 1125);
        self.operation_costs.insert("LOG3".to_string(), 1500);
        self.operation_costs.insert("LOG4".to_string(), 1875);
        
        // Comparison and logical operations
        self.operation_costs.insert("LT".to_string(), 3);
        self.operation_costs.insert("GT".to_string(), 3);
        self.operation_costs.insert("SLT".to_string(), 3);
        self.operation_costs.insert("SGT".to_string(), 3);
        self.operation_costs.insert("EQ".to_string(), 3);
        self.operation_costs.insert("ISZERO".to_string(), 3);
        self.operation_costs.insert("AND".to_string(), 3);
        self.operation_costs.insert("OR".to_string(), 3);
        self.operation_costs.insert("XOR".to_string(), 3);
        self.operation_costs.insert("NOT".to_string(), 3);
        
        // Copying operations
        self.operation_costs.insert("CODECOPY".to_string(), 3);
        self.operation_costs.insert("EXTCODECOPY".to_string(), 2600);
        
        // Hashing
        self.operation_costs.insert("KECCAK256".to_string(), 30);
        
        // Control flow
        self.operation_costs.insert("JUMP".to_string(), 8);
        self.operation_costs.insert("JUMPI".to_string(), 10);
        
        // Block info
        self.operation_costs.insert("BLOCKHASH".to_string(), 800);
        
        // Others
        self.operation_costs.insert("BALANCE".to_string(), 2600);
        self.operation_costs.insert("EXTCODESIZE".to_string(), 2600);
        self.operation_costs.insert("EXTCODEHASH".to_string(), 2600);
        self.operation_costs.insert("SELFDESTRUCT".to_string(), 5000);
    }

    fn initialize_optimization_patterns(&mut self) {
        // Storage packing optimization
        self.optimization_patterns.insert("STORAGE_PACK".to_string(), OptimizationPattern {
            id: "STORAGE_PACK".to_string(),
            name: "Storage Variable Packing".to_string(),
            description: "Multiple variables can be packed into single storage slot".to_string(),
            pattern_type: OptimizationType::Storage,
            potential_savings: GasSavings {
                min_savings: 2000,
                max_savings: 20000,
                per_operation_savings: Some(2000),
                confidence_level: 0.9,
            },
            detection_rules: vec!["consecutive_small_vars".to_string()],
            recommendation: "Pack multiple variables smaller than 32 bytes into single storage slots".to_string(),
            examples: vec![OptimizationExample {
                before: "uint8 a;\nuint8 b;\nbool c;".to_string(),
                after: "struct PackedVars {\n    uint8 a;\n    uint8 b;\n    bool c;\n}".to_string(),
                savings_explanation: "Saves 2 storage slots (~40,000 gas for writes)".to_string(),
            }],
        });

        // Loop optimization
        self.optimization_patterns.insert("LOOP_OPT".to_string(), OptimizationPattern {
            id: "LOOP_OPT".to_string(),
            name: "Loop Optimization".to_string(),
            description: "Inefficient loop patterns that can be optimized".to_string(),
            pattern_type: OptimizationType::Loop,
            potential_savings: GasSavings {
                min_savings: 100,
                max_savings: 10000,
                per_operation_savings: Some(50),
                confidence_level: 0.8,
            },
            detection_rules: vec!["array_length_in_loop".to_string(), "storage_read_in_loop".to_string()],
            recommendation: "Cache array length and storage variables outside loops".to_string(),
            examples: vec![OptimizationExample {
                before: "for(uint i = 0; i < array.length; i++) { ... }".to_string(),
                after: "uint len = array.length;\nfor(uint i = 0; i < len; i++) { ... }".to_string(),
                savings_explanation: "Saves ~2100 gas per iteration".to_string(),
            }],
        });

        // External call optimization
        self.optimization_patterns.insert("EXTERNAL_CALL".to_string(), OptimizationPattern {
            id: "EXTERNAL_CALL".to_string(),
            name: "External Call Optimization".to_string(),
            description: "Multiple external calls that can be batched".to_string(),
            pattern_type: OptimizationType::External,
            potential_savings: GasSavings {
                min_savings: 2600,
                max_savings: 50000,
                per_operation_savings: Some(2600),
                confidence_level: 0.7,
            },
            detection_rules: vec!["multiple_external_calls".to_string()],
            recommendation: "Batch multiple external calls or use multicall pattern".to_string(),
            examples: vec![OptimizationExample {
                before: "token.transfer(addr1, amt1);\ntoken.transfer(addr2, amt2);".to_string(),
                after: "address[] memory recipients = [addr1, addr2];\nuint[] memory amounts = [amt1, amt2];\ntoken.batchTransfer(recipients, amounts);".to_string(),
                savings_explanation: "Saves base call cost (~2600 gas) per additional call".to_string(),
            }],
        });

        // Function visibility optimization
        self.optimization_patterns.insert("FUNC_VIS".to_string(), OptimizationPattern {
            id: "FUNC_VIS".to_string(),
            name: "Function Visibility Optimization".to_string(),
            description: "Public functions that can be external for gas savings".to_string(),
            pattern_type: OptimizationType::Function,
            potential_savings: GasSavings {
                min_savings: 24,
                max_savings: 100,
                per_operation_savings: Some(24),
                confidence_level: 0.95,
            },
            detection_rules: vec!["public_to_external".to_string()],
            recommendation: "Use external instead of public for functions not called internally".to_string(),
            examples: vec![OptimizationExample {
                before: "function withdraw(uint amount) public { ... }".to_string(),
                after: "function withdraw(uint amount) external { ... }".to_string(),
                savings_explanation: "Saves ~24 gas per call by avoiding memory copying".to_string(),
            }],
        });

        // Variable initialization optimization
        self.optimization_patterns.insert("VAR_INIT".to_string(), OptimizationPattern {
            id: "VAR_INIT".to_string(),
            name: "Variable Initialization Optimization".to_string(),
            description: "Unnecessary variable initializations to default values".to_string(),
            pattern_type: OptimizationType::Variable,
            potential_savings: GasSavings {
                min_savings: 3,
                max_savings: 50,
                per_operation_savings: Some(3),
                confidence_level: 0.9,
            },
            detection_rules: vec!["default_value_init".to_string()],
            recommendation: "Remove explicit initialization to default values".to_string(),
            examples: vec![OptimizationExample {
                before: "uint256 i = 0;\nbool flag = false;".to_string(),
                after: "uint256 i;\nbool flag;".to_string(),
                savings_explanation: "Variables are automatically initialized to default values".to_string(),
            }],
        });

        // Arithmetic optimization
        self.optimization_patterns.insert("ARITHMETIC_OPT".to_string(), OptimizationPattern {
            id: "ARITHMETIC_OPT".to_string(),
            name: "Arithmetic Optimization".to_string(),
            description: "Expensive arithmetic operations that can be optimized".to_string(),
            pattern_type: OptimizationType::Arithmetic,
            potential_savings: GasSavings {
                min_savings: 5,
                max_savings: 100,
                per_operation_savings: Some(10),
                confidence_level: 0.8,
            },
            detection_rules: vec!["div_by_power_of_two".to_string(), "mul_by_power_of_two".to_string()],
            recommendation: "Use bit shifting instead of multiplication/division by powers of 2".to_string(),
            examples: vec![OptimizationExample {
                before: "result = value * 8;\nresult2 = value / 4;".to_string(),
                after: "result = value << 3;\nresult2 = value >> 2;".to_string(),
                savings_explanation: "Bit operations are cheaper than multiplication/division".to_string(),
            }],
        });

        // Logic optimization
        self.optimization_patterns.insert("LOGIC_OPT".to_string(), OptimizationPattern {
            id: "LOGIC_OPT".to_string(),
            name: "Logic Optimization".to_string(),
            description: "Redundant or inefficient logical operations".to_string(),
            pattern_type: OptimizationType::Logic,
            potential_savings: GasSavings {
                min_savings: 3,
                max_savings: 30,
                per_operation_savings: Some(5),
                confidence_level: 0.85,
            },
            detection_rules: vec!["redundant_conditions".to_string(), "boolean_comparison".to_string()],
            recommendation: "Simplify logical expressions and avoid redundant conditions".to_string(),
            examples: vec![OptimizationExample {
                before: "if(flag == true) { ... }\nif(count > 0 && count > 0) { ... }".to_string(),
                after: "if(flag) { ... }\nif(count > 0) { ... }".to_string(),
                savings_explanation: "Direct boolean evaluation and removing redundant conditions".to_string(),
            }],
        });
    }

    /// Perform comprehensive gas analysis on an enhanced contract
    pub fn analyze_contract(&self, contract: &EnhancedContract) -> Result<GasAnalysisReport> {
        let mut function_costs = BTreeMap::new();
        let mut total_estimated_cost = 0u64;
        let mut optimizations = Vec::new();

        // Analyze each function
        for function in &contract.functions {
            let function_analysis = self.analyze_function(function)?;
            total_estimated_cost += function_analysis.estimated_cost.typical;
            function_costs.insert(function.name.clone(), function_analysis);

            // Check for function-level optimizations
            optimizations.extend(self.check_function_optimizations(function)?);
        }

        // Analyze storage layout
        let storage_analysis = self.analyze_storage_layout(&contract.state_variables)?;
        optimizations.extend(self.check_storage_optimizations(&storage_analysis)?);

        // Estimate deployment cost
        let deployment_cost = self.estimate_deployment_cost(contract)?;

        // Check contract-level optimizations
        optimizations.extend(self.check_contract_optimizations(contract)?);

        // Calculate overall efficiency
        let potential_savings: u64 = optimizations.iter()
            .map(|opt| opt.potential_savings.typical_savings())
            .sum();
        
        let optimization_percentage = if total_estimated_cost > 0 {
            (potential_savings as f32 / total_estimated_cost as f32) * 100.0
        } else {
            0.0
        };

        let overall_efficiency = match optimization_percentage {
            x if x < 5.0 => EfficiencyRating::Excellent,
            x if x < 15.0 => EfficiencyRating::Good,
            x if x < 30.0 => EfficiencyRating::Fair,
            _ => EfficiencyRating::Poor,
        };

        Ok(GasAnalysisReport {
            total_estimated_cost,
            deployment_cost,
            function_costs,
            optimizations,
            storage_analysis,
            overall_efficiency,
        })
    }

    fn analyze_function(&self, function: &EnhancedFunction) -> Result<FunctionGasAnalysis> {
        let mut operations = Vec::new();
        let mut estimated_cost = 0u64;

        // Analyze operations in the function body
        operations.extend(self.analyze_storage_operations(&function.body)?);
        operations.extend(self.analyze_arithmetic_operations(&function.body)?);
        operations.extend(self.analyze_external_calls(&function.body)?);
        operations.extend(self.analyze_control_flow(&function.body)?);
        operations.extend(self.analyze_memory_operations(&function.body)?);

        // Calculate total estimated cost
        for operation in &operations {
            estimated_cost += operation.cost * operation.count as u64;
        }

        // Add base function call cost
        let base_cost = match function.visibility {
            Visibility::External => 24,
            Visibility::Public => 48,
            _ => 0,
        };

        estimated_cost += base_cost;

        // Calculate optimization potential
        let optimization_potential = self.calculate_optimization_potential(function);

        Ok(FunctionGasAnalysis {
            function_name: function.name.clone(),
            estimated_cost: GasCostRange {
                min: estimated_cost / 2,     // Conservative estimate
                max: estimated_cost * 2,     // With loops/worst case
                typical: estimated_cost,
            },
            complexity_score: function.complexity,
            operations,
            optimization_potential,
        })
    }

    fn analyze_storage_operations(&self, body: &str) -> Result<Vec<GasOperation>> {
        let mut operations = Vec::new();

        // Count storage reads (SLOAD operations)
        let sload_patterns = [
            r"\w+\s*\.\s*\w+", // struct.field
            r"\w+\[.*\]",      // mapping/array access
        ];

        for pattern in &sload_patterns {
            let regex = Regex::new(pattern)?;
            let count = regex.find_iter(body).count() as u32;
            if count > 0 {
                operations.push(GasOperation {
                    operation_type: "Storage Read (SLOAD)".to_string(),
                    cost: *self.operation_costs.get("SLOAD").unwrap_or(&800),
                    count,
                    line_number: None,
                    optimization_note: Some("Consider caching in memory if accessed multiple times".to_string()),
                });
            }
        }

        // Count storage writes (SSTORE operations)
        let sstore_patterns = [
            r"\w+\s*=\s*[^=]", // assignment
            r"\w+\[.*\]\s*=", // array/mapping assignment
        ];

        for pattern in &sstore_patterns {
            let regex = Regex::new(pattern)?;
            let count = regex.find_iter(body).count() as u32;
            if count > 0 {
                operations.push(GasOperation {
                    operation_type: "Storage Write (SSTORE)".to_string(),
                    cost: *self.operation_costs.get("SSTORE_NEW").unwrap_or(&20000),
                    count,
                    line_number: None,
                    optimization_note: Some("New storage slots are expensive".to_string()),
                });
            }
        }

        Ok(operations)
    }

    fn analyze_arithmetic_operations(&self, body: &str) -> Result<Vec<GasOperation>> {
        let mut operations = Vec::new();

        let arithmetic_patterns = [
            ("+", "ADD", 3),
            ("-", "SUB", 3),
            ("*", "MUL", 5),
            ("/", "DIV", 5),
            ("%", "MOD", 5),
            ("**", "EXP", 10),
        ];

        for (symbol, op_name, cost) in &arithmetic_patterns {
            let count = body.matches(symbol).count() as u32;
            if count > 0 {
                operations.push(GasOperation {
                    operation_type: format!("Arithmetic ({})", op_name),
                    cost: *cost,
                    count,
                    line_number: None,
                    optimization_note: if *symbol == "**" {
                        Some("Exponentiation is expensive - consider alternatives".to_string())
                    } else if *symbol == "/" || *symbol == "%" {
                        Some("Division/modulo more expensive than addition/subtraction".to_string())
                    } else {
                        None
                    },
                });
            }
        }

        Ok(operations)
    }

    fn analyze_external_calls(&self, body: &str) -> Result<Vec<GasOperation>> {
        let mut operations = Vec::new();

        let call_patterns = [
            (".call(", "CALL"),
            (".delegatecall(", "DELEGATECALL"),
            (".staticcall(", "STATICCALL"),
            (".transfer(", "TRANSFER"),
            (".send(", "SEND"),
        ];

        for (pattern, call_type) in &call_patterns {
            let count = body.matches(pattern).count() as u32;
            if count > 0 {
                let base_cost = *self.operation_costs.get("CALL").unwrap_or(&2600);
                operations.push(GasOperation {
                    operation_type: format!("External Call ({})", call_type),
                    cost: base_cost,
                    count,
                    line_number: None,
                    optimization_note: Some("External calls are expensive - batch when possible".to_string()),
                });
            }
        }

        Ok(operations)
    }

    fn analyze_control_flow(&self, body: &str) -> Result<Vec<GasOperation>> {
        let mut operations = Vec::new();

        // Analyze loops
        let loop_patterns = ["for(", "while("];
        for pattern in &loop_patterns {
            let count = body.matches(pattern).count() as u32;
            if count > 0 {
                operations.push(GasOperation {
                    operation_type: "Loop".to_string(),
                    cost: 8, // Base jump cost
                    count,
                    line_number: None,
                    optimization_note: Some("Consider loop optimizations and gas limits".to_string()),
                });
            }
        }

        // Analyze conditionals
        let conditional_patterns = ["if(", "else if("];
        for pattern in &conditional_patterns {
            let count = body.matches(pattern).count() as u32;
            if count > 0 {
                operations.push(GasOperation {
                    operation_type: "Conditional".to_string(),
                    cost: 10, // JUMPI cost
                    count,
                    line_number: None,
                    optimization_note: None,
                });
            }
        }

        Ok(operations)
    }

    fn analyze_memory_operations(&self, body: &str) -> Result<Vec<GasOperation>> {
        let mut operations = Vec::new();

        // Analyze memory allocations (rough estimate)
        let memory_patterns = [
            ("new bytes(", "Memory Allocation"),
            ("new uint[](", "Array Allocation"),
            ("abi.encode(", "ABI Encoding"),
            ("abi.decode(", "ABI Decoding"),
            ("keccak256(", "Keccak256 Hash"),
        ];

        for (pattern, op_name) in &memory_patterns {
            let count = body.matches(pattern).len() as u32;
            if count > 0 {
                let cost = match op_name {
                    "Keccak256 Hash" => *self.operation_costs.get("KECCAK256").unwrap_or(&30),
                    _ => 100, // Rough estimate for memory operations
                };

                operations.push(GasOperation {
                    operation_type: op_name.to_string(),
                    cost,
                    count,
                    line_number: None,
                    optimization_note: if op_name.contains("ABI") {
                        Some("ABI encoding/decoding can be gas intensive".to_string())
                    } else {
                        None
                    },
                });
            }
        }

        Ok(operations)
    }

    fn calculate_optimization_potential(&self, function: &EnhancedFunction) -> u32 {
        let mut score = 0u32;

        // Check for common optimization opportunities
        if function.body.contains("for") && function.body.contains(".length") {
            score += 20; // Array length caching
        }

        if function.body.contains("public") && !function.body.contains("this.") {
            score += 10; // Public to external
        }

        if function.body.matches("storage").count() > 1 {
            score += 30; // Storage caching
        }

        if function.body.contains(".call(") || function.body.contains(".send(") {
            score += 15; // External call optimization
        }

        score.min(100)
    }

    fn analyze_storage_layout(&self, variables: &[EnhancedVariable]) -> Result<StorageAnalysis> {
        let mut current_slot = 0u32;
        let mut slot_usage = 0u32; // bytes used in current slot
        let mut total_slots = 0u32;
        let mut wasted_bytes = 0u32;

        for variable in variables {
            let var_size = self.estimate_variable_size(&variable.var_type);
            
            if slot_usage + var_size > 32 {
                // Start new slot
                wasted_bytes += 32 - slot_usage;
                current_slot += 1;
                slot_usage = var_size;
            } else {
                slot_usage += var_size;
            }

            if slot_usage == 32 || current_slot != total_slots {
                total_slots = current_slot + 1;
            }
        }

        // Calculate final waste
        if slot_usage < 32 && slot_usage > 0 {
            wasted_bytes += 32 - slot_usage;
        }

        let packing_efficiency = if total_slots > 0 {
            ((total_slots * 32 - wasted_bytes) as f32 / (total_slots * 32) as f32) * 100.0
        } else {
            100.0
        };

        Ok(StorageAnalysis {
            total_slots_used: total_slots,
            wasted_storage: wasted_bytes,
            packing_efficiency,
            optimization_suggestions: self.suggest_storage_optimizations(variables)?,
        })
    }

    fn estimate_variable_size(&self, var_type: &str) -> u32 {
        match var_type {
            t if t.starts_with("uint8") || t.starts_with("int8") => 1,
            t if t.starts_with("uint16") || t.starts_with("int16") => 2,
            t if t.starts_with("uint32") || t.starts_with("int32") => 4,
            t if t.starts_with("uint64") || t.starts_with("int64") => 8,
            t if t.starts_with("uint128") || t.starts_with("int128") => 16,
            t if t.starts_with("uint256") || t.starts_with("int256") => 32,
            t if t == "bool" => 1,
            t if t == "address" => 20,
            t if t.starts_with("bytes") && t.len() > 5 => {
                // bytesN type
                t[5..].parse().unwrap_or(32)
            }
            _ => 32, // Default to full slot
        }
    }

    fn suggest_storage_optimizations(&self, variables: &[EnhancedVariable]) -> Result<Vec<StorageOptimization>> {
        let mut suggestions = Vec::new();

        // Simple packing suggestions
        let mut small_vars = Vec::new();
        for (i, var) in variables.iter().enumerate() {
            let size = self.estimate_variable_size(&var.var_type);
            if size < 32 {
                small_vars.push((i, var, size));
            }
        }

        // Group small variables that can be packed together
        let mut packed_size = 0u32;
        let mut pack_group = Vec::new();

        for (i, var, size) in small_vars {
            if packed_size + size <= 32 {
                pack_group.push((i, var, size));
                packed_size += size;
            } else {
                if pack_group.len() > 1 {
                    // Suggest packing for this group
                    for (idx, v, _) in &pack_group {
                        suggestions.push(StorageOptimization {
                            variable_name: v.name.clone(),
                            current_slot: *idx as u32,
                            suggested_slot: suggestions.len() as u32 / 32,
                            savings: 20000, // Approximate SSTORE cost
                            explanation: format!("Pack with {} other small variables", pack_group.len() - 1),
                        });
                    }
                }
                pack_group.clear();
                pack_group.push((i, var, size));
                packed_size = size;
            }
        }

        Ok(suggestions)
    }

    fn check_function_optimizations(&self, function: &EnhancedFunction) -> Result<Vec<GasOptimization>> {
        let mut optimizations = Vec::new();

        // Check for public functions that can be external
        if function.visibility == Visibility::Public && 
           !function.body.contains("this.") {
            optimizations.push(GasOptimization {
                id: "FUNC_VIS".to_string(),
                title: "Change Public to External".to_string(),
                description: format!("Function '{}' can be external instead of public", function.name),
                severity: OptimizationSeverity::Low,
                potential_savings: GasSavings {
                    min_savings: 24,
                    max_savings: 48,
                    per_operation_savings: Some(24),
                    confidence_level: 0.95,
                },
                location: OptimizationLocation {
                    function_name: Some(function.name.clone()),
                    line_number: Some(function.line_start),
                    code_snippet: None,
                },
                recommendation: "Change visibility from public to external".to_string(),
                code_examples: Some(OptimizationExample {
                    before: format!("function {}(...) public", function.name),
                    after: format!("function {}(...) external", function.name),
                    savings_explanation: "Saves ~24 gas per call".to_string(),
                }),
            });
        }

        // Check for loops with array.length
        if function.body.contains("for") && function.body.contains(".length") {
            optimizations.push(GasOptimization {
                id: "LOOP_OPT".to_string(),
                title: "Cache Array Length in Loop".to_string(),
                description: format!("Function '{}' reads array length in loop condition", function.name),
                severity: OptimizationSeverity::Medium,
                potential_savings: GasSavings {
                    min_savings: 100,
                    max_savings: 2000,
                    per_operation_savings: Some(100),
                    confidence_level: 0.9,
                },
                location: OptimizationLocation {
                    function_name: Some(function.name.clone()),
                    line_number: Some(function.line_start),
                    code_snippet: None,
                },
                recommendation: "Cache array length before loop".to_string(),
                code_examples: self.optimization_patterns.get("LOOP_OPT")
                    .and_then(|p| p.examples.first().cloned()),
            });
        }

        // Check for multiple storage reads of same variable
        let storage_reads = self.count_storage_variable_reads(&function.body);
        for (var_name, count) in storage_reads {
            if count > 2 {
                optimizations.push(GasOptimization {
                    id: "STORAGE_CACHE".to_string(),
                    title: "Cache Storage Variable".to_string(),
                    description: format!("Variable '{}' read from storage {} times", var_name, count),
                    severity: OptimizationSeverity::High,
                    potential_savings: GasSavings {
                        min_savings: 800 * (count as u64 - 1),
                        max_savings: 2000 * (count as u64 - 1),
                        per_operation_savings: Some(800),
                        confidence_level: 0.95,
                    },
                    location: OptimizationLocation {
                        function_name: Some(function.name.clone()),
                        line_number: Some(function.line_start),
                        code_snippet: None,
                    },
                    recommendation: format!("Cache '{}' in memory variable", var_name),
                    code_examples: Some(OptimizationExample {
                        before: format!("function() {{ if({0} > 0) {{ {0} += 1; emit Event({0}); }} }}", var_name),
                        after: format!("function() {{ uint temp = {0}; if(temp > 0) {{ {0} = temp + 1; emit Event(temp + 1); }} }}", var_name),
                        savings_explanation: format!("Saves {} SLOAD operations", count - 1),
                    }),
                });
            }
        }

        Ok(optimizations)
    }

    fn count_storage_variable_reads(&self, body: &str) -> HashMap<String, u32> {
        let mut reads = HashMap::new();
        
        // Simple heuristic: count identifier occurrences that look like state variable reads
        let var_regex = Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b").unwrap();
        for cap in var_regex.captures_iter(body) {
            let var_name = cap[1].to_string();
            // Skip common keywords and local variables (this is a simplified heuristic)
            if !["if", "for", "while", "return", "require", "assert", "emit", "memory", "storage", "calldata", "uint", "bool", "address"].contains(&var_name.as_str()) {
                *reads.entry(var_name).or_insert(0) += 1;
            }
        }

        // Filter to only variables read more than once
        reads.into_iter().filter(|(_, count)| *count > 1).collect()
    }

    fn check_storage_optimizations(&self, storage_analysis: &StorageAnalysis) -> Result<Vec<GasOptimization>> {
        let mut optimizations = Vec::new();

        if storage_analysis.packing_efficiency < 80.0 {
            optimizations.push(GasOptimization {
                id: "STORAGE_PACK".to_string(),
                title: "Optimize Storage Packing".to_string(),
                description: format!("Storage packing efficiency is {:.1}%", storage_analysis.packing_efficiency),
                severity: OptimizationSeverity::High,
                potential_savings: GasSavings {
                    min_savings: storage_analysis.wasted_storage as u64 * 2000,
                    max_savings: storage_analysis.wasted_storage as u64 * 20000,
                    per_operation_savings: Some(20000),
                    confidence_level: 0.8,
                },
                location: OptimizationLocation {
                    function_name: None,
                    line_number: None,
                    code_snippet: None,
                },
                recommendation: "Reorder state variables to improve storage packing".to_string(),
                code_examples: self.optimization_patterns.get("STORAGE_PACK")
                    .and_then(|p| p.examples.first().cloned()),
            });
        }

        Ok(optimizations)
    }

    fn check_contract_optimizations(&self, contract: &EnhancedContract) -> Result<Vec<GasOptimization>> {
        let mut optimizations = Vec::new();

        // Check for redundant external calls
        let mut external_call_count = 0;
        for function in &contract.functions {
            external_call_count += function.body.matches(".call(").count();
            external_call_count += function.body.matches(".send(").count();
            external_call_count += function.body.matches(".transfer(").count();
        }

        if external_call_count > 5 {
            optimizations.push(GasOptimization {
                id: "BATCH_CALLS".to_string(),
                title: "Consider Batching External Calls".to_string(),
                description: format!("Contract makes {} external calls", external_call_count),
                severity: OptimizationSeverity::Medium,
                potential_savings: GasSavings {
                    min_savings: 2600 * (external_call_count as u64 / 2),
                    max_savings: 2600 * external_call_count as u64,
                    per_operation_savings: Some(2600),
                    confidence_level: 0.6,
                },
                location: OptimizationLocation {
                    function_name: None,
                    line_number: None,
                    code_snippet: None,
                },
                recommendation: "Consider implementing multicall or batch patterns".to_string(),
                code_examples: self.optimization_patterns.get("EXTERNAL_CALL")
                    .and_then(|p| p.examples.first().cloned()),
            });
        }

        Ok(optimizations)
    }

    fn estimate_deployment_cost(&self, contract: &EnhancedContract) -> Result<u64> {
        // Rough deployment cost estimation
        let base_cost = 32000u64; // CREATE operation
        let code_size_cost = contract.source_code.len() as u64 * 200; // Rough estimate
        let storage_init_cost = contract.state_variables.len() as u64 * 20000; // Storage initialization

        Ok(base_cost + code_size_cost + storage_init_cost)
    }
}

impl GasSavings {
    pub fn typical_savings(&self) -> u64 {
        (self.min_savings + self.max_savings) / 2
    }
}

impl Default for GasAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
