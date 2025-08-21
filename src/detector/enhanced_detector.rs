use crate::types::{Contract, Vulnerability, VulnerabilityReport};
use crate::parser::enhanced_solidity::{EnhancedContract, EnhancedFunction, EnhancedVariable, StateMutability, Visibility};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Enhanced comprehensive contract analysis
pub struct EnhancedVulnerabilityDetector {
    patterns: HashMap<String, VulnerabilityPattern>,
    severity_weights: HashMap<String, u8>,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub patterns: Vec<String>,
    pub exclusions: Vec<String>,
    pub recommendation: String,
    pub references: Vec<String>,
    pub confidence: u8, // 0-100
}

#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub function_name: String,
    pub line_number: usize,
    pub code_snippet: String,
    pub surrounding_context: String,
    pub call_stack: Vec<String>,
    pub state_changes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityAnalysis {
    pub vulnerabilities: Vec<Vulnerability>,
    pub gas_issues: Vec<GasIssue>,
    pub code_quality: CodeQualityReport,
    pub risk_score: u32,
}

#[derive(Debug, Clone)]
pub struct GasIssue {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub potential_savings: Option<u64>,
    pub line_number: Option<usize>,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub struct CodeQualityReport {
    pub complexity_score: u32,
    pub maintainability_index: f32,
    pub test_coverage_estimate: f32,
    pub documentation_score: u32,
    pub best_practice_violations: Vec<String>,
}

static DETECTOR_INSTANCE: OnceLock<EnhancedVulnerabilityDetector> = OnceLock::new();

impl EnhancedVulnerabilityDetector {
    pub fn instance() -> &'static EnhancedVulnerabilityDetector {
        DETECTOR_INSTANCE.get_or_init(|| Self::new())
    }

    pub fn new() -> Self {
        let mut detector = Self {
            patterns: HashMap::new(),
            severity_weights: HashMap::from([
                ("Critical".to_string(), 10),
                ("High".to_string(), 8),
                ("Medium".to_string(), 5),
                ("Low".to_string(), 2),
                ("Informational".to_string(), 1),
            ]),
        };
        
        detector.load_swc_patterns();
        detector
    }

    /// Analyze a contract for vulnerabilities (wrapper for enhanced analysis)
    pub fn analyze_contract(&self, contract: &EnhancedContract) -> Result<SecurityAnalysis> {
        self.analyze_enhanced_contract(contract)
    }

    /// Load comprehensive SWC registry patterns
    fn load_swc_patterns(&mut self) {
        // SWC-100: Function Default Visibility
        self.patterns.insert("SWC-100".to_string(), VulnerabilityPattern {
            id: "SWC-100".to_string(),
            name: "Function Default Visibility".to_string(),
            description: "Functions without explicit visibility specifier".to_string(),
            severity: "Medium".to_string(),
            category: "Security".to_string(),
            patterns: vec![r"function\s+\w+\s*\([^)]*\)\s*\{".to_string()],
            exclusions: vec![
                "public".to_string(), 
                "private".to_string(), 
                "internal".to_string(), 
                "external".to_string()
            ],
            recommendation: "Always specify function visibility explicitly".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-100".to_string()],
            confidence: 95,
        });

        // SWC-101: Integer Overflow and Underflow
        self.patterns.insert("SWC-101".to_string(), VulnerabilityPattern {
            id: "SWC-101".to_string(),
            name: "Integer Overflow and Underflow".to_string(),
            description: "Arithmetic operations without overflow protection".to_string(),
            severity: "High".to_string(),
            category: "Security".to_string(),
            patterns: vec![r"[+\-*/]".to_string(), r"\+\+".to_string(), r"--".to_string()],
            exclusions: vec![
                "SafeMath".to_string(),
                "checked".to_string(),
                "unchecked".to_string(),
                "require(".to_string(),
                "pragma solidity ^0.8".to_string(),
            ],
            recommendation: "Use SafeMath library, Solidity 0.8+ built-in checks, or explicit bounds checking".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-101".to_string()],
            confidence: 90,
        });

        // SWC-102: Outdated Compiler Version
        self.patterns.insert("SWC-102".to_string(), VulnerabilityPattern {
            id: "SWC-102".to_string(),
            name: "Outdated Compiler Version".to_string(),
            description: "Using outdated Solidity compiler version".to_string(),
            severity: "Medium".to_string(),
            category: "Security".to_string(),
            patterns: vec![r"pragma solidity".to_string()],
            exclusions: vec![],
            recommendation: "Use the latest stable Solidity compiler version".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-102".to_string()],
            confidence: 100,
        });

        // SWC-103: Floating Pragma
        self.patterns.insert("SWC-103".to_string(), VulnerabilityPattern {
            id: "SWC-103".to_string(),
            name: "Floating Pragma".to_string(),
            description: "Pragma statement not locked to specific compiler version".to_string(),
            severity: "Low".to_string(),
            category: "Best Practice".to_string(),
            patterns: vec![r"pragma solidity\s*[\^~><=]".to_string()],
            exclusions: vec![],
            recommendation: "Lock pragma to specific compiler version or narrow range".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-103".to_string()],
            confidence: 95,
        });

        // SWC-104: Unchecked Call Return Value
        self.patterns.insert("SWC-104".to_string(), VulnerabilityPattern {
            id: "SWC-104".to_string(),
            name: "Unchecked Call Return Value".to_string(),
            description: "Return value of low-level call not checked".to_string(),
            severity: "Medium".to_string(),
            category: "Security".to_string(),
            patterns: vec![
                r"\.call\(".to_string(),
                r"\.send\(".to_string(),
                r"\.delegatecall\(".to_string(),
            ],
            exclusions: vec!["require(".to_string(), "assert(".to_string(), "if(".to_string()],
            recommendation: "Check return value of low-level calls and handle failures appropriately".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-104".to_string()],
            confidence: 85,
        });

        // SWC-105: Unprotected Ether Withdrawal
        self.patterns.insert("SWC-105".to_string(), VulnerabilityPattern {
            id: "SWC-105".to_string(),
            name: "Unprotected Ether Withdrawal".to_string(),
            description: "Function allows withdrawal without proper access control".to_string(),
            severity: "High".to_string(),
            category: "Security".to_string(),
            patterns: vec![
                r"\.transfer\(".to_string(),
                r"\.send\(".to_string(),
                r"\.call\{value:".to_string(),
            ],
            exclusions: vec![
                "onlyOwner".to_string(),
                "require(".to_string(),
                "modifier".to_string(),
            ],
            recommendation: "Add proper access control to withdrawal functions".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
            confidence: 80,
        });

        // SWC-107: Reentrancy
        self.patterns.insert("SWC-107".to_string(), VulnerabilityPattern {
            id: "SWC-107".to_string(),
            name: "Reentrancy".to_string(),
            description: "Potential reentrancy vulnerability in external calls".to_string(),
            severity: "High".to_string(),
            category: "Security".to_string(),
            patterns: vec![
                r"\.call\(".to_string(),
                r"\.send\(".to_string(),
                r"\.transfer\(".to_string(),
                r"\.delegatecall\(".to_string(),
            ],
            exclusions: vec![
                "nonReentrant".to_string(),
                "ReentrancyGuard".to_string(),
                "mutex".to_string(),
            ],
            recommendation: "Use ReentrancyGuard or follow Checks-Effects-Interactions pattern".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-107".to_string()],
            confidence: 85,
        });

        // SWC-108: State Variable Default Visibility
        self.patterns.insert("SWC-108".to_string(), VulnerabilityPattern {
            id: "SWC-108".to_string(),
            name: "State Variable Default Visibility".to_string(),
            description: "State variables without explicit visibility specifier".to_string(),
            severity: "Low".to_string(),
            category: "Best Practice".to_string(),
            patterns: vec![r"\w+\s+\w+\s*[=;]".to_string()],
            exclusions: vec![
                "public".to_string(),
                "private".to_string(),
                "internal".to_string(),
            ],
            recommendation: "Always specify state variable visibility explicitly".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-108".to_string()],
            confidence: 90,
        });

        // SWC-109: Uninitialized Storage Pointer
        self.patterns.insert("SWC-109".to_string(), VulnerabilityPattern {
            id: "SWC-109".to_string(),
            name: "Uninitialized Storage Pointer".to_string(),
            description: "Uninitialized storage pointer can lead to data corruption".to_string(),
            severity: "High".to_string(),
            category: "Security".to_string(),
            patterns: vec![r"storage\s+\w+;".to_string()],
            exclusions: vec!["=".to_string()],
            recommendation: "Initialize storage pointers explicitly or use memory/calldata".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-109".to_string()],
            confidence: 95,
        });

        // SWC-110: Assert Violation
        self.patterns.insert("SWC-110".to_string(), VulnerabilityPattern {
            id: "SWC-110".to_string(),
            name: "Assert Violation".to_string(),
            description: "Assert statements can lead to stuck contracts".to_string(),
            severity: "Medium".to_string(),
            category: "Security".to_string(),
            patterns: vec![r"assert\(".to_string()],
            exclusions: vec![],
            recommendation: "Use require() for user input validation, reserve assert() for internal errors".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-110".to_string()],
            confidence: 85,
        });

        // SWC-115: Authorization through tx.origin
        self.patterns.insert("SWC-115".to_string(), VulnerabilityPattern {
            id: "SWC-115".to_string(),
            name: "Authorization through tx.origin".to_string(),
            description: "Using tx.origin for authorization is vulnerable to phishing attacks".to_string(),
            severity: "Medium".to_string(),
            category: "Security".to_string(),
            patterns: vec![r"tx\.origin".to_string()],
            exclusions: vec![],
            recommendation: "Use msg.sender instead of tx.origin for authorization".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-115".to_string()],
            confidence: 95,
        });

        // SWC-116: Block values as time proxy
        self.patterns.insert("SWC-116".to_string(), VulnerabilityPattern {
            id: "SWC-116".to_string(),
            name: "Block values as time proxy".to_string(),
            description: "Using block timestamp for critical logic is unreliable".to_string(),
            severity: "Medium".to_string(),
            category: "Security".to_string(),
            patterns: vec![
                r"block\.timestamp".to_string(),
                r"block\.number".to_string(),
                r"now".to_string(),
            ],
            exclusions: vec![],
            recommendation: "Avoid using block timestamp for critical logic or use with appropriate tolerance".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-116".to_string()],
            confidence: 80,
        });

        // SWC-120: Weak Sources of Randomness
        self.patterns.insert("SWC-120".to_string(), VulnerabilityPattern {
            id: "SWC-120".to_string(),
            name: "Weak Sources of Randomness".to_string(),
            description: "Using predictable values for randomness".to_string(),
            severity: "High".to_string(),
            category: "Security".to_string(),
            patterns: vec![
                r"keccak256\(.*block\.timestamp".to_string(),
                r"keccak256\(.*block\.number".to_string(),
                r"keccak256\(.*block\.difficulty".to_string(),
                r"blockhash\(".to_string(),
            ],
            exclusions: vec![],
            recommendation: "Use commit-reveal schemes or external oracles for randomness".to_string(),
            references: vec!["https://swcregistry.io/docs/SWC-120".to_string()],
            confidence: 90,
        });

        // Additional gas-related patterns
        self.add_gas_patterns();
        
        // Additional best practice patterns
        self.add_best_practice_patterns();
    }

    fn add_gas_patterns(&mut self) {
        // Gas: Loop with external calls
        self.patterns.insert("GAS-001".to_string(), VulnerabilityPattern {
            id: "GAS-001".to_string(),
            name: "Loops with External Calls".to_string(),
            description: "Loops containing external calls can cause DoS and high gas costs".to_string(),
            severity: "High".to_string(),
            category: "Gas".to_string(),
            patterns: vec![r"for\s*\([^)]*\)[^{]*\{[^}]*\.call".to_string()],
            exclusions: vec![],
            recommendation: "Avoid external calls in loops or implement pull-over-push pattern".to_string(),
            references: vec!["https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/".to_string()],
            confidence: 95,
        });

        // Gas: Inefficient storage packing
        self.patterns.insert("GAS-002".to_string(), VulnerabilityPattern {
            id: "GAS-002".to_string(),
            name: "Inefficient Storage Packing".to_string(),
            description: "State variables not optimally packed for storage".to_string(),
            severity: "Low".to_string(),
            category: "Gas".to_string(),
            patterns: vec![],
            exclusions: vec![],
            recommendation: "Pack variables smaller than 32 bytes together".to_string(),
            references: vec!["https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html".to_string()],
            confidence: 80,
        });

        // Gas: Unnecessary storage reads
        self.patterns.insert("GAS-003".to_string(), VulnerabilityPattern {
            id: "GAS-003".to_string(),
            name: "Unnecessary Storage Reads".to_string(),
            description: "Multiple reads of the same storage variable".to_string(),
            severity: "Low".to_string(),
            category: "Gas".to_string(),
            patterns: vec![],
            exclusions: vec![],
            recommendation: "Cache storage variables in memory when used multiple times".to_string(),
            references: vec![],
            confidence: 75,
        });
    }

    fn add_best_practice_patterns(&mut self) {
        // Missing events for important state changes
        self.patterns.insert("BP-001".to_string(), VulnerabilityPattern {
            id: "BP-001".to_string(),
            name: "Missing Events".to_string(),
            description: "Important state changes not logged with events".to_string(),
            severity: "Low".to_string(),
            category: "Best Practice".to_string(),
            patterns: vec![],
            exclusions: vec![],
            recommendation: "Emit events for all important state changes".to_string(),
            references: vec![],
            confidence: 70,
        });

        // Missing input validation
        self.patterns.insert("BP-002".to_string(), VulnerabilityPattern {
            id: "BP-002".to_string(),
            name: "Missing Input Validation".to_string(),
            description: "Function parameters not validated".to_string(),
            severity: "Medium".to_string(),
            category: "Best Practice".to_string(),
            patterns: vec![],
            exclusions: vec!["require(".to_string(), "assert(".to_string(), "revert(".to_string()],
            recommendation: "Validate all function parameters with require statements".to_string(),
            references: vec![],
            confidence: 75,
        });
    }

    /// Analyze enhanced contract for vulnerabilities
    pub fn analyze_enhanced_contract(&self, contract: &EnhancedContract) -> Result<SecurityAnalysis> {
        let mut vulnerabilities = Vec::new();
        let mut gas_issues = Vec::new();

        // Pragma and compiler version checks
        vulnerabilities.extend(self.check_pragma_issues(contract)?);

        // Function-level analysis
        for function in &contract.functions {
            vulnerabilities.extend(self.analyze_function(function, contract)?);
            gas_issues.extend(self.analyze_gas_patterns(function)?);
        }

        // State variable analysis
        vulnerabilities.extend(self.analyze_state_variables(&contract.state_variables)?);

        // Cross-function analysis
        vulnerabilities.extend(self.analyze_access_patterns(contract)?);
        vulnerabilities.extend(self.analyze_reentrancy_patterns(contract)?);

        // Code quality analysis
        let code_quality = self.analyze_code_quality(contract)?;

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&vulnerabilities);

        Ok(SecurityAnalysis {
            vulnerabilities,
            gas_issues,
            code_quality,
            risk_score,
        })
    }

    fn check_pragma_issues(&self, contract: &EnhancedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for floating pragma (SWC-103)
        if let Some(pattern) = self.patterns.get("SWC-103") {
            if pattern.patterns.iter().any(|p| {
                Regex::new(p).map(|regex| regex.is_match(&contract.pragma_version)).unwrap_or(false)
            }) {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-103".to_string(),
                    title: "Floating Pragma".to_string(),
                    description: format!("Pragma not locked: {}", contract.pragma_version),
                    severity: "Low".to_string(),
                    category: "Best Practice".to_string(),
                    line_number: Some(1),
                    code_snippet: Some(format!("pragma solidity {};", contract.pragma_version)),
                    recommendation: pattern.recommendation.clone(),
                    references: pattern.references.clone(),
                });
            }
        }

        // Check for outdated compiler version (SWC-102)
        if self.is_outdated_compiler(&contract.pragma_version) {
            if let Some(pattern) = self.patterns.get("SWC-102") {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-102".to_string(),
                    title: "Outdated Compiler Version".to_string(),
                    description: format!("Using potentially outdated compiler: {}", contract.pragma_version),
                    severity: "Medium".to_string(),
                    category: "Security".to_string(),
                    line_number: Some(1),
                    code_snippet: Some(format!("pragma solidity {};", contract.pragma_version)),
                    recommendation: pattern.recommendation.clone(),
                    references: pattern.references.clone(),
                });
            }
        }

        Ok(vulnerabilities)
    }

    fn analyze_function(&self, function: &EnhancedFunction, contract: &EnhancedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check visibility issues
        vulnerabilities.extend(self.check_function_visibility(function)?);

        // Check for reentrancy (SWC-107)
        vulnerabilities.extend(self.check_reentrancy_advanced(function, contract)?);

        // Check for integer overflow (SWC-101)
        vulnerabilities.extend(self.check_integer_overflow_advanced(function, contract)?);

        // Check for unchecked calls (SWC-104)
        vulnerabilities.extend(self.check_unchecked_calls(function)?);

        // Check tx.origin usage (SWC-115)
        vulnerabilities.extend(self.check_tx_origin_usage(function)?);

        // Check timestamp dependence (SWC-116)
        vulnerabilities.extend(self.check_timestamp_dependence(function)?);

        // Check weak randomness (SWC-120)
        vulnerabilities.extend(self.check_weak_randomness(function)?);

        // Check access control
        vulnerabilities.extend(self.check_access_control_advanced(function, contract)?);

        // Check for assert violations (SWC-110)
        vulnerabilities.extend(self.check_assert_usage(function)?);

        Ok(vulnerabilities)
    }

    fn check_function_visibility(&self, function: &EnhancedFunction) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // SWC-100: Check for functions that should be external
        if function.visibility == Visibility::Public && 
           !function.body.contains("this.") &&
           function.parameters.iter().all(|p| !p.storage_location.as_ref().map_or(false, |s| s == "storage")) {
            
            vulnerabilities.push(Vulnerability {
                id: "SWC-100-EXT".to_string(),
                title: "Function Should Be External".to_string(),
                description: format!("Function '{}' is public but could be external for gas savings", function.name),
                severity: "Low".to_string(),
                category: "Gas".to_string(),
                line_number: Some(function.line_start),
                code_snippet: Some(function.body[..std::cmp::min(100, function.body.len())].to_string()),
                recommendation: "Consider making this function external if it's not called internally".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-100".to_string()],
            });
        }

        Ok(vulnerabilities)
    }

    fn check_reentrancy_advanced(&self, function: &EnhancedFunction, contract: &EnhancedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        if !function.modifiers.iter().any(|m| m.contains("nonReentrant")) &&
           !contract.source_code.contains("ReentrancyGuard") {
            
            let external_call_patterns = [".call(", ".call{", ".send(", ".transfer(", ".delegatecall("];
            let has_external_calls = external_call_patterns.iter()
                .any(|pattern| function.body.contains(pattern));

            if has_external_calls {
                let lines: Vec<&str> = function.body.lines().collect();
                let mut state_change_after_call = false;
                let mut found_external_call = false;

                for line in &lines {
                    if external_call_patterns.iter().any(|pattern| line.contains(pattern)) {
                        found_external_call = true;
                    } else if found_external_call && 
                             (line.contains(" = ") || line.contains("++") || line.contains("--") || 
                              line.contains("push(") || line.contains("pop()")) {
                        state_change_after_call = true;
                        break;
                    }
                }

                let severity = if state_change_after_call { "Critical" } else { "High" };

                vulnerabilities.push(Vulnerability {
                    id: "SWC-107".to_string(),
                    title: "Reentrancy Vulnerability".to_string(),
                    description: format!(
                        "Function '{}' contains external calls without reentrancy protection{}",
                        function.name,
                        if state_change_after_call { " and modifies state after external calls" } else { "" }
                    ),
                    severity: severity.to_string(),
                    category: "Security".to_string(),
                    line_number: Some(function.line_start),
                    code_snippet: Some(function.body[..std::cmp::min(200, function.body.len())].to_string()),
                    recommendation: "Use ReentrancyGuard modifier or follow Checks-Effects-Interactions pattern".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-107".to_string()],
                });
            }
        }

        Ok(vulnerabilities)
    }

    fn check_integer_overflow_advanced(&self, function: &EnhancedFunction, contract: &EnhancedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Skip if using Solidity 0.8+ which has built-in overflow protection
        if contract.pragma_version.contains("0.8") || contract.pragma_version.contains("^0.8") {
            return Ok(vulnerabilities);
        }

        let arithmetic_patterns = ["+", "-", "*", "/", "++", "--"];
        let has_arithmetic = arithmetic_patterns.iter()
            .any(|pattern| function.body.contains(pattern));

        let has_protection = function.body.contains("SafeMath") ||
                           function.body.contains("require(") ||
                           function.body.contains("assert(") ||
                           contract.source_code.contains("using SafeMath");

        if has_arithmetic && !has_protection {
            let severity = if function.body.contains("*") || function.body.contains("**") {
                "High"
            } else {
                "Medium"
            };

            vulnerabilities.push(Vulnerability {
                id: "SWC-101".to_string(),
                title: "Integer Overflow/Underflow".to_string(),
                description: format!("Function '{}' contains arithmetic operations without overflow protection", function.name),
                severity: severity.to_string(),
                category: "Security".to_string(),
                line_number: Some(function.line_start),
                code_snippet: Some(function.body[..std::cmp::min(200, function.body.len())].to_string()),
                recommendation: "Use SafeMath library or upgrade to Solidity 0.8+ for built-in overflow protection".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-101".to_string()],
            });
        }

        Ok(vulnerabilities)
    }

    fn check_unchecked_calls(&self, function: &EnhancedFunction) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        let low_level_calls = [".call(", ".send(", ".delegatecall("];
        
        for pattern in &low_level_calls {
            if function.body.contains(pattern) {
                // Check if return value is handled
                let lines: Vec<&str> = function.body.lines().collect();
                for line in &lines {
                    if line.contains(pattern) && 
                       !line.contains("require(") &&
                       !line.contains("assert(") &&
                       !line.contains("if") &&
                       !line.trim_start().starts_with("(bool") &&
                       !line.trim_start().starts_with("bool") {
                        
                        vulnerabilities.push(Vulnerability {
                            id: "SWC-104".to_string(),
                            title: "Unchecked Call Return Value".to_string(),
                            description: format!("Low-level call in function '{}' does not check return value", function.name),
                            severity: "Medium".to_string(),
                            category: "Security".to_string(),
                            line_number: Some(function.line_start),
                            code_snippet: Some(line.to_string()),
                            recommendation: "Check the return value and handle call failures appropriately".to_string(),
                            references: vec!["https://swcregistry.io/docs/SWC-104".to_string()],
                        });
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn check_tx_origin_usage(&self, function: &EnhancedFunction) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        if function.body.contains("tx.origin") {
            vulnerabilities.push(Vulnerability {
                id: "SWC-115".to_string(),
                title: "Authorization through tx.origin".to_string(),
                description: format!("Function '{}' uses tx.origin for authorization", function.name),
                severity: "Medium".to_string(),
                category: "Security".to_string(),
                line_number: Some(function.line_start),
                code_snippet: Some(function.body[..std::cmp::min(200, function.body.len())].to_string()),
                recommendation: "Use msg.sender instead of tx.origin for authorization checks".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-115".to_string()],
            });
        }

        Ok(vulnerabilities)
    }

    fn check_timestamp_dependence(&self, function: &EnhancedFunction) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        let timestamp_patterns = ["block.timestamp", "block.number", "now"];
        let critical_patterns = ["require(", "if(", "modifier", "random", "lottery"];

        for timestamp_pattern in &timestamp_patterns {
            if function.body.contains(timestamp_pattern) {
                let is_critical = critical_patterns.iter()
                    .any(|pattern| function.body.contains(pattern));

                let severity = if is_critical { "High" } else { "Medium" };

                vulnerabilities.push(Vulnerability {
                    id: "SWC-116".to_string(),
                    title: "Block values as time proxy".to_string(),
                    description: format!("Function '{}' uses {} for logic", function.name, timestamp_pattern),
                    severity: severity.to_string(),
                    category: "Security".to_string(),
                    line_number: Some(function.line_start),
                    code_snippet: Some(function.body[..std::cmp::min(200, function.body.len())].to_string()),
                    recommendation: "Avoid using block timestamp for critical logic or use with appropriate tolerance".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-116".to_string()],
                });
            }
        }

        Ok(vulnerabilities)
    }

    fn check_weak_randomness(&self, function: &EnhancedFunction) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        let weak_randomness_patterns = [
            "keccak256(abi.encodePacked(block.timestamp",
            "keccak256(abi.encodePacked(block.number",
            "keccak256(abi.encodePacked(block.difficulty",
            "blockhash(",
            "block.timestamp % ",
            "block.number % ",
        ];

        for pattern in &weak_randomness_patterns {
            if function.body.contains(pattern) {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-120".to_string(),
                    title: "Weak Sources of Randomness".to_string(),
                    description: format!("Function '{}' uses predictable values for randomness", function.name),
                    severity: "High".to_string(),
                    category: "Security".to_string(),
                    line_number: Some(function.line_start),
                    code_snippet: Some(function.body[..std::cmp::min(200, function.body.len())].to_string()),
                    recommendation: "Use commit-reveal schemes, VRF, or external randomness oracles".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-120".to_string()],
                });
            }
        }

        Ok(vulnerabilities)
    }

    fn check_access_control_advanced(&self, function: &EnhancedFunction, contract: &EnhancedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for functions that modify state without access control
        let state_changing_patterns = [".transfer(", ".send(", ".call{value:", "selfdestruct(", " = ", "push(", "pop()"];
        let access_control_patterns = ["onlyOwner", "require(msg.sender", "modifier", "_msgSender()"];

        let modifies_state = state_changing_patterns.iter()
            .any(|pattern| function.body.contains(pattern));

        let has_access_control = access_control_patterns.iter()
            .any(|pattern| function.body.contains(pattern) || function.modifiers.iter().any(|m| m.contains(&pattern.replace("(", ""))));

        if modifies_state && !has_access_control && 
           function.visibility == Visibility::Public &&
           function.state_mutability != StateMutability::View &&
           function.state_mutability != StateMutability::Pure {
            
            let severity = if function.body.contains("selfdestruct") || 
                             function.body.contains(".transfer(") || 
                             function.body.contains(".call{value:") {
                "High"
            } else {
                "Medium"
            };

            vulnerabilities.push(Vulnerability {
                id: "SWC-105".to_string(),
                title: "Missing Access Control".to_string(),
                description: format!("Function '{}' modifies state without proper access control", function.name),
                severity: severity.to_string(),
                category: "Security".to_string(),
                line_number: Some(function.line_start),
                code_snippet: Some(function.body[..std::cmp::min(200, function.body.len())].to_string()),
                recommendation: "Add appropriate access control modifiers or require statements".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
            });
        }

        Ok(vulnerabilities)
    }

    fn check_assert_usage(&self, function: &EnhancedFunction) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        if function.body.contains("assert(") {
            vulnerabilities.push(Vulnerability {
                id: "SWC-110".to_string(),
                title: "Assert Violation".to_string(),
                description: format!("Function '{}' uses assert() which consumes all gas on failure", function.name),
                severity: "Medium".to_string(),
                category: "Security".to_string(),
                line_number: Some(function.line_start),
                code_snippet: Some(function.body[..std::cmp::min(200, function.body.len())].to_string()),
                recommendation: "Use require() for input validation and reserve assert() for internal errors".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-110".to_string()],
            });
        }

        Ok(vulnerabilities)
    }

    fn analyze_state_variables(&self, variables: &[EnhancedVariable]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        for variable in variables {
            // Check visibility issues (SWC-108)
            if matches!(variable.visibility, Visibility::Internal) && 
               !variable.name.starts_with("_") {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-108".to_string(),
                    title: "State Variable Default Visibility".to_string(),
                    description: format!("State variable '{}' has implicit internal visibility", variable.name),
                    severity: "Low".to_string(),
                    category: "Best Practice".to_string(),
                    line_number: Some(variable.line_number),
                    code_snippet: Some(format!("{} {}", variable.var_type, variable.name)),
                    recommendation: "Explicitly specify visibility for all state variables".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-108".to_string()],
                });
            }
        }

        Ok(vulnerabilities)
    }

    fn analyze_access_patterns(&self, contract: &EnhancedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Look for functions that should emit events
        for function in &contract.functions {
            if function.body.contains(" = ") && 
               function.visibility == Visibility::Public &&
               !function.body.contains("emit ") &&
               function.name != "constructor" {
                
                vulnerabilities.push(Vulnerability {
                    id: "BP-001".to_string(),
                    title: "Missing Event Emission".to_string(),
                    description: format!("Function '{}' modifies state but doesn't emit events", function.name),
                    severity: "Low".to_string(),
                    category: "Best Practice".to_string(),
                    line_number: Some(function.line_start),
                    code_snippet: Some(function.body[..std::cmp::min(100, function.body.len())].to_string()),
                    recommendation: "Emit events for important state changes to enable monitoring".to_string(),
                    references: vec![],
                });
            }
        }

        Ok(vulnerabilities)
    }

    fn analyze_reentrancy_patterns(&self, contract: &EnhancedContract) -> Result<Vec<Vulnerability>> {
        let vulnerabilities = Vec::new();
        // Advanced cross-function reentrancy analysis would go here
        // This is a placeholder for more sophisticated analysis
        Ok(vulnerabilities)
    }

    fn analyze_gas_patterns(&self, function: &EnhancedFunction) -> Result<Vec<GasIssue>> {
        let mut gas_issues = Vec::new();

        // Check for loops with external calls
        if function.body.contains("for") && 
           (function.body.contains(".call(") || function.body.contains(".send(") || function.body.contains(".transfer(")) {
            
            gas_issues.push(GasIssue {
                id: "GAS-001".to_string(),
                title: "External Calls in Loop".to_string(),
                description: format!("Function '{}' contains external calls within loops", function.name),
                severity: "High".to_string(),
                potential_savings: Some(50000), // Rough estimate
                line_number: Some(function.line_start),
                recommendation: "Avoid external calls in loops to prevent DoS and high gas costs".to_string(),
            });
        }

        // Check for inefficient array usage
        if function.body.contains("push(") && function.body.contains("for") {
            gas_issues.push(GasIssue {
                id: "GAS-004".to_string(),
                title: "Inefficient Array Operations".to_string(),
                description: format!("Function '{}' uses array push operations in loops", function.name),
                severity: "Medium".to_string(),
                potential_savings: Some(10000),
                line_number: Some(function.line_start),
                recommendation: "Consider batch operations or use mappings for better gas efficiency".to_string(),
            });
        }

        Ok(gas_issues)
    }

    fn analyze_code_quality(&self, contract: &EnhancedContract) -> Result<CodeQualityReport> {
        let complexity_score = contract.complexity_score;
        
        // Calculate maintainability index (simplified version)
        let line_count = contract.line_count as f32;
        let function_count = contract.functions.len() as f32;
        let avg_function_complexity = if function_count > 0.0 {
            contract.functions.iter().map(|f| f.complexity as f32).sum::<f32>() / function_count
        } else {
            1.0
        };

        let maintainability_index = 171.0 - 5.2 * (line_count / 1000.0).ln() 
                                   - 0.23 * avg_function_complexity
                                   - 16.2 * (line_count / function_count.max(1.0)).ln();

        // Estimate test coverage based on function complexity
        let test_coverage_estimate = if complexity_score < 50 { 80.0 } else { 60.0 };

        // Documentation score based on comments
        let comment_ratio = contract.source_code.matches("//").count() as f32 / line_count;
        let documentation_score = (comment_ratio * 100.0).min(100.0) as u32;

        let mut best_practice_violations = Vec::new();
        
        // Check for missing license
        if contract.license.is_none() {
            best_practice_violations.push("Missing SPDX license identifier".to_string());
        }

        // Check for magic numbers
        if contract.source_code.matches(char::is_numeric).count() > 10 {
            best_practice_violations.push("Consider using named constants instead of magic numbers".to_string());
        }

        Ok(CodeQualityReport {
            complexity_score,
            maintainability_index,
            test_coverage_estimate,
            documentation_score,
            best_practice_violations,
        })
    }

    fn calculate_risk_score(&self, vulnerabilities: &[Vulnerability]) -> u32 {
        vulnerabilities.iter()
            .map(|v| self.severity_weights.get(&v.severity).unwrap_or(&1) * 10)
            .sum::<u8>() as u32
    }

    fn is_outdated_compiler(&self, version: &str) -> bool {
        // Simple version check - in practice, this should be more sophisticated
        !version.contains("0.8") && !version.contains("0.7")
    }

    /// Convert to basic vulnerability report for backward compatibility
    pub fn to_basic_report(&self, analysis: &SecurityAnalysis, contract_name: &str) -> VulnerabilityReport {
        let vulnerabilities = analysis.vulnerabilities.clone();
        let total_issues = vulnerabilities.len();
        let critical_issues = vulnerabilities.iter().filter(|v| v.severity == "Critical").count();
        let high_issues = vulnerabilities.iter().filter(|v| v.severity == "High").count();
        let medium_issues = vulnerabilities.iter().filter(|v| v.severity == "Medium").count();
        let low_issues = vulnerabilities.iter().filter(|v| v.severity == "Low").count();

        VulnerabilityReport {
            contract_name: contract_name.to_string(),
            vulnerabilities,
            total_issues,
            critical_issues,
            high_issues,
            medium_issues,
            low_issues,
        }
    }
}

impl Default for EnhancedVulnerabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}
