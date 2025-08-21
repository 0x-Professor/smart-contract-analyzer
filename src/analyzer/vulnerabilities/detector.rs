use crate::types::{Contract, Vulnerability, VulnerabilityReport};

pub struct VulnerabilityDetector {
    patterns: Vec<VulnerabilityPattern>,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    pub recommendation: Option<String>,
    pub references: Vec<String>,
}

impl VulnerabilityDetector {
    pub fn new() -> Self {
        Self {
            patterns: Self::load_default_patterns(),
        }
    }

    pub fn analyze_contract(&self, contract: &Contract) -> crate::Result<VulnerabilityReport> {
        let mut vulnerabilities = Vec::new();

        // Check for common vulnerabilities
        vulnerabilities.extend(self.check_reentrancy(contract));
        vulnerabilities.extend(self.check_integer_overflow(contract));
        vulnerabilities.extend(self.check_unchecked_return_value(contract));
        vulnerabilities.extend(self.check_tx_origin_usage(contract));
        vulnerabilities.extend(self.check_timestamp_dependence(contract));
        vulnerabilities.extend(self.check_unprotected_selfdestruct(contract));

        let total_issues = vulnerabilities.len();
        let critical_issues = vulnerabilities.iter().filter(|v| v.severity == "Critical").count();
        let high_issues = vulnerabilities.iter().filter(|v| v.severity == "High").count();
        let medium_issues = vulnerabilities.iter().filter(|v| v.severity == "Medium").count();
        let low_issues = vulnerabilities.iter().filter(|v| v.severity == "Low").count();

        Ok(VulnerabilityReport {
            contract_name: contract.name.clone(),
            vulnerabilities,
            total_issues,
            critical_issues,
            high_issues,
            medium_issues,
            low_issues,
        })
    }

    fn load_default_patterns() -> Vec<VulnerabilityPattern> {
        vec![
            VulnerabilityPattern {
                id: "SWC-107".to_string(),
                name: "Reentrancy".to_string(),
                description: "Potential reentrancy vulnerability".to_string(),
                severity: "High".to_string(),
                pattern: r"\.call\(|\.send\(|\.transfer\(".to_string(),
                recommendation: Some("Follow the checks-effects-interactions pattern".to_string()),
                references: vec!["https://swcregistry.io/docs/SWC-107".to_string()],
            },
            VulnerabilityPattern {
                id: "SWC-101".to_string(),
                name: "Integer Overflow and Underflow".to_string(),
                description: "Potential integer overflow/underflow".to_string(),
                severity: "High".to_string(),
                pattern: r"\+|\-|\*|\/".to_string(),
                recommendation: Some("Use SafeMath library or add appropriate checks".to_string()),
                references: vec!["https://swcregistry.io/docs/SWC-101".to_string()],
            },
        ]
    }

    fn check_reentrancy(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            let mut has_external_call = false;
            let mut has_state_change_after = false;
            
            // Check for external calls
            if function.body.contains(".call(") ||
               function.body.contains(".call{") ||
               function.body.contains(".send(") ||
               function.body.contains(".transfer(") ||
               function.body.contains(".delegatecall(") {
                has_external_call = true;
            }
            
            if has_external_call {
                // Check for state changes after external calls (simple heuristic)
                let lines: Vec<&str> = function.body.lines().collect();
                let mut found_call = false;
                
                for line in &lines {
                    if line.contains(".call(") || line.contains(".send(") || line.contains(".transfer(") {
                        found_call = true;
                    } else if found_call && (line.contains("=") || line.contains("++") || line.contains("--")) {
                        has_state_change_after = true;
                        break;
                    }
                }
                
                // Also check if function lacks reentrancy protection
                let has_reentrancy_guard = function.modifiers.contains(&"nonReentrant".to_string()) ||
                                         function.body.contains("nonReentrant") ||
                                         contract.source_code.contains("ReentrancyGuard");
                
                if !has_reentrancy_guard {
                    let severity = if has_state_change_after { "Critical" } else { "High" };
                    
                    vulnerabilities.push(Vulnerability {
                        id: "SWC-107".to_string(),
                        title: "Reentrancy".to_string(),
                        description: format!(
                            "Function '{}' contains external calls without reentrancy protection. {}",
                            function.name,
                            if has_state_change_after {
                                "State changes occur after external calls."
                            } else {
                                "Consider adding reentrancy guards."
                            }
                        ),
                        severity: severity.to_string(),
                        category: "Security".to_string(),
                        line_number: None,
                        code_snippet: Some(function.body.clone()),
                        recommendation: "Use ReentrancyGuard or follow the Checks-Effects-Interactions pattern. Update state before making external calls.".to_string(),
                        references: vec!["https://swcregistry.io/docs/SWC-107".to_string()],
                    });
                }
            }
        }
        
        vulnerabilities
    }

    fn check_integer_overflow(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            let mut has_arithmetic = false;
            let mut has_safe_math = false;
            
            // Check for arithmetic operations
            if function.body.contains("+") || 
               function.body.contains("-") || 
               function.body.contains("*") || 
               function.body.contains("/") {
                has_arithmetic = true;
            }
            
            // Check for safety measures
            if function.body.contains("SafeMath") ||
               function.body.contains("checked") ||
               function.body.contains("unchecked") ||
               contract.source_code.contains("pragma solidity ^0.8") ||
               function.body.contains("require(") ||
               function.body.contains("assert(") {
                has_safe_math = true;
            }
            
            if has_arithmetic && !has_safe_math {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-101".to_string(),
                    title: "Integer Overflow and Underflow".to_string(),
                    description: format!(
                        "Function '{}' contains arithmetic operations without overflow protection",
                        function.name
                    ),
                    severity: "High".to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: Some(function.body.clone()),
                    recommendation: "Use SafeMath library, Solidity 0.8+ built-in checks, or add explicit overflow checks with require() statements.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-101".to_string()],
                });
            }
            
            // Check for specific dangerous patterns
            if function.body.contains("++") || function.body.contains("--") {
                if !function.body.contains("require(") && !function.body.contains("SafeMath") {
                    vulnerabilities.push(Vulnerability {
                        id: "SWC-101-INCREMENT".to_string(),
                        title: "Unsafe Increment/Decrement".to_string(),
                        description: format!(
                            "Function '{}' uses increment/decrement operators without bounds checking",
                            function.name
                        ),
                        severity: "Medium".to_string(),
                        category: "Security".to_string(),
                        line_number: None,
                        code_snippet: Some(function.body.clone()),
                        recommendation: "Add bounds checking before increment/decrement operations.".to_string(),
                        references: vec!["https://swcregistry.io/docs/SWC-101".to_string()],
                    });
                }
            }
        }
        
        vulnerabilities
    }

    fn check_unchecked_return_value(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            if (function.body.contains(".call(") ||
                function.body.contains(".send(") ||
                function.body.contains(".delegatecall(")) &&
               !function.body.contains("require(") &&
               !function.body.contains("assert(") {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-104".to_string(),
                    title: "Unchecked Call Return Value".to_string(),
                    description: format!("Unchecked return value in function '{}'", function.name),
                    severity: "Medium".to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: Some(function.body.clone()),
                    recommendation: "Check the return value of external calls with require() or handle the failure case.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-104".to_string()],
                });
            }
        }
        
        vulnerabilities
    }

    fn check_tx_origin_usage(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if contract.source_code.contains("tx.origin") {
            vulnerabilities.push(Vulnerability {
                id: "SWC-115".to_string(),
                title: "Authorization through tx.origin".to_string(),
                description: "Use of tx.origin for authorization is vulnerable to phishing attacks".to_string(),
                severity: "Medium".to_string(),
                category: "Security".to_string(),
                line_number: None,
                code_snippet: None,
                recommendation: "Use msg.sender instead of tx.origin for authorization checks.".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-115".to_string()],
            });
        }
        
        vulnerabilities
    }

    fn check_timestamp_dependence(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            if function.body.contains("block.timestamp") ||
               function.body.contains("now") ||
               function.body.contains("block.number") {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-116".to_string(),
                    title: "Block values as a proxy for time".to_string(),
                    description: format!("Function '{}' uses block timestamp which can be manipulated by miners", function.name),
                    severity: "Low".to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: Some(function.body.clone()),
                    recommendation: "Avoid using block.timestamp for critical logic. Consider using block numbers or external time oracles.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-116".to_string()],
                });
            }
        }
        
        vulnerabilities
    }

    fn check_unprotected_selfdestruct(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            if (function.body.contains("selfdestruct") || 
                function.body.contains("suicide")) &&
               !function.body.contains("onlyOwner") &&
               !function.body.contains("require(msg.sender") {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-106".to_string(),
                    title: "Unprotected SELFDESTRUCT Instruction".to_string(),
                    description: format!("Function '{}' contains selfdestruct without proper access controls", function.name),
                    severity: "High".to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: Some(function.body.clone()),
                    recommendation: "Add proper access controls (like onlyOwner modifier) to functions containing selfdestruct.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-106".to_string()],
                });
            }
        }
        
        vulnerabilities
    }
}
