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
        vulnerabilities.extend(self.check_access_control_issues(contract));
        vulnerabilities.extend(self.check_denial_of_service(contract));
        vulnerabilities.extend(self.check_front_running(contract));

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
            let has_external_calls = function.body.contains(".call(") ||
                function.body.contains(".call{") ||
                function.body.contains(".send(") ||
                function.body.contains(".delegatecall(") ||
                function.body.contains(".staticcall(");
                
            if has_external_calls {
                let lines: Vec<&str> = function.body.lines().collect();
                
                for (i, line) in lines.iter().enumerate() {
                    if line.contains(".call(") || line.contains(".send(") || line.contains(".delegatecall(") {
                        // Check if return value is handled
                        let has_return_check = line.contains("require(") ||
                            line.contains("assert(") ||
                            line.contains("(bool") ||
                            line.contains("if(") ||
                            line.contains("if (");
                        
                        // Check next few lines for return value handling
                        let mut has_subsequent_check = false;
                        for j in 1..=3 {
                            if i + j < lines.len() {
                                let next_line = lines[i + j];
                                if next_line.contains("require(") || 
                                   next_line.contains("assert(") ||
                                   next_line.contains("success") {
                                    has_subsequent_check = true;
                                    break;
                                }
                            }
                        }
                        
                        if !has_return_check && !has_subsequent_check {
                            let call_type = if line.contains(".call(") {
                                "call"
                            } else if line.contains(".send(") {
                                "send"
                            } else if line.contains(".delegatecall(") {
                                "delegatecall"
                            } else {
                                "external call"
                            };
                            
                            vulnerabilities.push(Vulnerability {
                                id: "SWC-104".to_string(),
                                title: "Unchecked Call Return Value".to_string(),
                                description: format!(
                                    "Function '{}' contains unchecked {} return value",
                                    function.name, call_type
                                ),
                                severity: if call_type == "delegatecall" { "High".to_string() } else { "Medium".to_string() },
                                category: "Security".to_string(),
                                line_number: None,
                                code_snippet: Some(line.to_string()),
                                recommendation: format!(
                                    "Check the return value of {} with require() or handle the failure case appropriately.",
                                    call_type
                                ),
                                references: vec!["https://swcregistry.io/docs/SWC-104".to_string()],
                            });
                        }
                    }
                }
            }
        }
        
        vulnerabilities
    }

    fn check_tx_origin_usage(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check global contract for tx.origin usage
        if contract.source_code.contains("tx.origin") {
            // Find specific functions using tx.origin
            for function in &contract.functions {
                if function.body.contains("tx.origin") {
                    let lines: Vec<&str> = function.body.lines().collect();
                    
                    for line in &lines {
                        if line.contains("tx.origin") {
                            let severity = if line.contains("require(") || line.contains("assert(") {
                                "High"  // Used in authorization checks
                            } else {
                                "Medium"  // Used elsewhere
                            };
                            
                            vulnerabilities.push(Vulnerability {
                                id: "SWC-115".to_string(),
                                title: "Authorization through tx.origin".to_string(),
                                description: format!(
                                    "Function '{}' uses tx.origin for authorization, which is vulnerable to phishing attacks",
                                    function.name
                                ),
                                severity: severity.to_string(),
                                category: "Security".to_string(),
                                line_number: None,
                                code_snippet: Some(line.to_string()),
                                recommendation: "Use msg.sender instead of tx.origin for authorization checks. tx.origin can be manipulated in phishing attacks.".to_string(),
                                references: vec!["https://swcregistry.io/docs/SWC-115".to_string()],
                            });
                            break; // Only report once per function
                        }
                    }
                }
            }
            
            // If no specific function found but contract contains tx.origin
            if vulnerabilities.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-115".to_string(),
                    title: "Authorization through tx.origin".to_string(),
                    description: "Contract uses tx.origin which is vulnerable to phishing attacks".to_string(),
                    severity: "Medium".to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: "Replace tx.origin with msg.sender for all authorization checks.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-115".to_string()],
                });
            }
        }
        
        vulnerabilities
    }

    fn check_timestamp_dependence(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            let mut issues = Vec::new();
            
            if function.body.contains("block.timestamp") {
                issues.push("block.timestamp");
            }
            if function.body.contains("now") {
                issues.push("now");
            }
            if function.body.contains("block.number") {
                issues.push("block.number");
            }
            
            if !issues.is_empty() {
                // Determine severity based on usage context
                let lines: Vec<&str> = function.body.lines().collect();
                let mut severity = "Low";
                let mut risky_patterns = Vec::new();
                
                for line in &lines {
                    if line.contains("block.timestamp") || line.contains("now") || line.contains("block.number") {
                        if line.contains("random") || line.contains("Random") {
                            severity = "High";
                            risky_patterns.push("randomness generation");
                        } else if line.contains("require(") || line.contains("assert(") {
                            if severity != "High" { severity = "Medium"; }
                            risky_patterns.push("conditional logic");
                        } else if line.contains("=") && (line.contains("reward") || line.contains("bonus") || line.contains("payment")) {
                            if severity != "High" { severity = "Medium"; }
                            risky_patterns.push("payment calculation");
                        }
                    }
                }
                
                let description = if !risky_patterns.is_empty() {
                    format!(
                        "Function '{}' uses {} for {}, which can be manipulated by miners",
                        function.name,
                        issues.join(", "),
                        risky_patterns.join(" and ")
                    )
                } else {
                    format!(
                        "Function '{}' relies on {} which can be manipulated by miners",
                        function.name,
                        issues.join(", ")
                    )
                };
                
                vulnerabilities.push(Vulnerability {
                    id: "SWC-116".to_string(),
                    title: "Block values as a proxy for time".to_string(),
                    description,
                    severity: severity.to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: Some(function.body.clone()),
                    recommendation: "Avoid using block timestamp for critical logic. Consider using block numbers with appropriate delays, external time oracles, or commit-reveal schemes for randomness.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-116".to_string()],
                });
            }
        }
        
        vulnerabilities
    }

    fn check_unprotected_selfdestruct(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            let has_selfdestruct = function.body.contains("selfdestruct") || function.body.contains("suicide");
            
            if has_selfdestruct {
                let mut has_proper_access_control = false;
                let mut access_control_issues = Vec::new();
                
                // Check for proper access control modifiers
                if function.modifiers.contains(&"onlyOwner".to_string()) ||
                   function.modifiers.contains(&"onlyAdmin".to_string()) ||
                   function.modifiers.iter().any(|m| m.contains("only")) {
                    has_proper_access_control = true;
                }
                
                // Check for access control in function body
                if function.body.contains("require(msg.sender == owner") ||
                   function.body.contains("require(msg.sender == admin") ||
                   function.body.contains("require(owner == msg.sender") ||
                   function.body.contains("onlyOwner") {
                    has_proper_access_control = true;
                }
                
                // Check for problematic access control patterns
                if function.body.contains("require(tx.origin") {
                    access_control_issues.push("uses tx.origin for authorization");
                }
                
                if function.body.contains("require(msg.sender != address(0)") && !has_proper_access_control {
                    access_control_issues.push("only checks for zero address");
                }
                
                // Check for weak conditions
                let lines: Vec<&str> = function.body.lines().collect();
                for line in &lines {
                    if line.contains("selfdestruct") || line.contains("suicide") {
                        if line.contains("if") && (line.contains("==") || line.contains("!=")) {
                            // Simple conditional check might be weak
                            if line.contains("12345") || line.contains("code") || line.contains("password") {
                                access_control_issues.push("uses weak conditional checks");
                            }
                        }
                    }
                }
                
                if !has_proper_access_control || !access_control_issues.is_empty() {
                    let severity = if access_control_issues.is_empty() { "High" } else { "Critical" };
                    
                    let mut description = format!(
                        "Function '{}' contains selfdestruct without proper access controls",
                        function.name
                    );
                    
                    if !access_control_issues.is_empty() {
                        description.push_str(&format!(" and {}", access_control_issues.join(", ")));
                    }
                    
                    vulnerabilities.push(Vulnerability {
                        id: "SWC-106".to_string(),
                        title: "Unprotected SELFDESTRUCT Instruction".to_string(),
                        description,
                        severity: severity.to_string(),
                        category: "Security".to_string(),
                        line_number: None,
                        code_snippet: Some(function.body.clone()),
                        recommendation: "Add proper access controls (like onlyOwner modifier) to functions containing selfdestruct. Consider using a two-step process with time delays for critical operations.".to_string(),
                        references: vec!["https://swcregistry.io/docs/SWC-106".to_string()],
                    });
                }
            }
        }
        
        vulnerabilities
    }

    fn check_access_control_issues(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            // Check for functions that should have access control
            let is_sensitive = function.name.contains("admin") ||
                function.name.contains("owner") ||
                function.name.contains("withdraw") ||
                function.name.contains("transfer") ||
                function.name.contains("mint") ||
                function.name.contains("burn") ||
                function.name.contains("destroy") ||
                function.name.contains("emergency") ||
                function.name.contains("pause") ||
                function.visibility == "external" && function.body.contains("=");
            
            if is_sensitive {
                let has_access_control = !function.modifiers.is_empty() ||
                    function.body.contains("require(msg.sender") ||
                    function.body.contains("onlyOwner") ||
                    function.body.contains("onlyAdmin");
                
                if !has_access_control {
                    vulnerabilities.push(Vulnerability {
                        id: "SWC-105".to_string(),
                        title: "Unprotected Ether Withdrawal".to_string(),
                        description: format!(
                            "Function '{}' appears to be sensitive but lacks proper access control",
                            function.name
                        ),
                        severity: "High".to_string(),
                        category: "Security".to_string(),
                        line_number: None,
                        code_snippet: Some(function.body.clone()),
                        recommendation: "Add proper access control modifiers or require statements to restrict access to sensitive functions.".to_string(),
                        references: vec!["https://swcregistry.io/docs/SWC-105".to_string()],
                    });
                }
            }
        }
        
        vulnerabilities
    }

    fn check_denial_of_service(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            // Check for unbounded loops
            if function.body.contains("for") || function.body.contains("while") {
                let has_array_iteration = function.body.contains(".length") ||
                    function.body.contains("array") ||
                    function.body.contains("mapping");
                
                if has_array_iteration && !function.body.contains("require(") {
                    vulnerabilities.push(Vulnerability {
                        id: "SWC-128".to_string(),
                        title: "DoS With Block Gas Limit".to_string(),
                        description: format!(
                            "Function '{}' contains unbounded loops that may cause denial of service",
                            function.name
                        ),
                        severity: "Medium".to_string(),
                        category: "Security".to_string(),
                        line_number: None,
                        code_snippet: Some(function.body.clone()),
                        recommendation: "Add bounds checking or use pagination patterns to prevent gas limit issues.".to_string(),
                        references: vec!["https://swcregistry.io/docs/SWC-128".to_string()],
                    });
                }
            }
            
            // Check for external calls in loops
            if function.body.contains("for") && 
               (function.body.contains(".call(") || function.body.contains(".send(") || function.body.contains(".transfer(")) {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-113".to_string(),
                    title: "DoS with Failed Call".to_string(),
                    description: format!(
                        "Function '{}' makes external calls in loops which can cause denial of service",
                        function.name
                    ),
                    severity: "High".to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: Some(function.body.clone()),
                    recommendation: "Avoid external calls in loops. Use pull payment patterns instead.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-113".to_string()],
                });
            }
        }
        
        vulnerabilities
    }

    fn check_front_running(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for function in &contract.functions {
            // Check for price/value sensitive operations
            if (function.body.contains("price") || function.body.contains("amount") || function.body.contains("bid")) &&
               !function.body.contains("commit") &&
               !function.body.contains("hash") {
                vulnerabilities.push(Vulnerability {
                    id: "SWC-114".to_string(),
                    title: "Transaction Order Dependence".to_string(),
                    description: format!(
                        "Function '{}' may be vulnerable to front-running attacks due to price/value dependencies",
                        function.name
                    ),
                    severity: "Medium".to_string(),
                    category: "Security".to_string(),
                    line_number: None,
                    code_snippet: Some(function.body.clone()),
                    recommendation: "Consider using commit-reveal schemes or other mechanisms to prevent front-running.".to_string(),
                    references: vec!["https://swcregistry.io/docs/SWC-114".to_string()],
                });
            }
        }
        
        vulnerabilities
    }
}
