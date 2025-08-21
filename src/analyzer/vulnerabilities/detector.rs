use crate::types::{Contract, Vulnerabi        let total_issues = vulnerabilities.len();

        VulnerabilityReport {
            contract_name: contract.name.clone(),
            vulnerabilities,
            total_issues,, VulnerabilityReport};
use crate::analyzer::vulnerabilities::{VulnerabilityPattern, VulnerabilityRule};
use regex::Regex;

pub struct VulnerabilityDetector {
    patterns: Vec<VulnerabilityPattern>,
    rules: Vec<VulnerabilityRule>,
}

impl Default for VulnerabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnerabilityDetector {
    pub fn new() -> Self {
        Self {
            patterns: Self::load_default_patterns(),
            rules: Self::load_default_rules(),
        }
    }

    pub fn analyze_contract(&self, contract: &Contract) -> crate::Result<VulnerabilityReport> {
        let mut vulnerabilities = Vec::new();

        // Pattern-based detection
        for pattern in &self.patterns {
            vulnerabilities.extend(self.check_pattern(contract, pattern));
        }

        // Rule-based detection
        for rule in &self.rules {
            if let Some(vulnerability) = self.check_rule(contract, rule) {
                vulnerabilities.push(vulnerability);
            }
        }

        Ok(VulnerabilityReport {
            contract_name: contract.name.clone(),
            vulnerabilities,
            total_issues: vulnerabilities.len(),
            critical_issues: vulnerabilities.iter().filter(|v| v.severity == "Critical").count(),
            high_issues: vulnerabilities.iter().filter(|v| v.severity == "High").count(),
            medium_issues: vulnerabilities.iter().filter(|v| v.severity == "Medium").count(),
            low_issues: vulnerabilities.iter().filter(|v| v.severity == "Low").count(),
        })
    }

    fn check_pattern(&self, contract: &Contract, pattern: &VulnerabilityPattern) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if let Ok(regex) = Regex::new(&pattern.regex_pattern) {
            for mat in regex.find_iter(&contract.source_code) {
                vulnerabilities.push(Vulnerability {
                    id: format!("{}_{}", pattern.id, vulnerabilities.len()),
                    title: pattern.title.clone(),
                    description: pattern.description.clone(),
                    severity: pattern.severity.clone(),
                    category: pattern.category.clone(),
                    line_number: Some(self.get_line_number(&contract.source_code, mat.start())),
                    code_snippet: Some(mat.as_str().to_string()),
                    recommendation: pattern.recommendation.clone(),
                    references: pattern.references.clone(),
                });
            }
        }

        vulnerabilities
    }

    fn check_rule(&self, contract: &Contract, rule: &VulnerabilityRule) -> Option<Vulnerability> {
        if (rule.checker)(contract) {
            Some(Vulnerability {
                id: rule.id.clone(),
                title: rule.title.clone(),
                description: rule.description.clone(),
                severity: rule.severity.clone(),
                category: rule.category.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: rule.recommendation.clone(),
                references: rule.references.clone(),
            })
        } else {
            None
        }
    }

    fn get_line_number(&self, source: &str, position: usize) -> usize {
        source[..position].matches('\n').count() + 1
    }

    fn load_default_patterns() -> Vec<VulnerabilityPattern> {
        vec![
            VulnerabilityPattern {
                id: "REENTRANCY_CALL".to_string(),
                title: "Potential Reentrancy".to_string(),
                description: "External call followed by state changes".to_string(),
                category: "Reentrancy".to_string(),
                severity: "Critical".to_string(),
                regex_pattern: r"\.call\{[^}]*\}\([^)]*\)[\s\S]*?=[\s\S]*?;".to_string(),
                recommendation: "Use the checks-effects-interactions pattern or reentrancy guards".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/".to_string()],
            },
            VulnerabilityPattern {
                id: "UNCHECKED_CALL".to_string(),
                title: "Unchecked External Call".to_string(),
                description: "External call without checking return value".to_string(),
                category: "External Calls".to_string(),
                severity: "High".to_string(),
                regex_pattern: r"\.call\([^)]*\);(?!\s*require)".to_string(),
                recommendation: "Always check the return value of external calls".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/".to_string()],
            },
            VulnerabilityPattern {
                id: "TX_ORIGIN".to_string(),
                title: "Use of tx.origin".to_string(),
                description: "Using tx.origin for authorization".to_string(),
                category: "Authorization".to_string(),
                severity: "Medium".to_string(),
                regex_pattern: r"tx\.origin\s*==".to_string(),
                recommendation: "Use msg.sender instead of tx.origin for authorization".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/".to_string()],
            },
            VulnerabilityPattern {
                id: "TIMESTAMP_DEPENDENCE".to_string(),
                title: "Timestamp Dependence".to_string(),
                description: "Using block.timestamp for critical logic".to_string(),
                category: "Timestamp".to_string(),
                severity: "Medium".to_string(),
                regex_pattern: r"block\.timestamp|now\b".to_string(),
                recommendation: "Avoid using timestamps for critical contract logic".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/".to_string()],
            },
            VulnerabilityPattern {
                id: "UNINITIALIZED_STORAGE".to_string(),
                title: "Uninitialized Storage Variable".to_string(),
                description: "Storage variable declared but not initialized".to_string(),
                category: "Initialization".to_string(),
                severity: "Low".to_string(),
                regex_pattern: r"storage\s+\w+\s+\w+;".to_string(),
                recommendation: "Initialize all storage variables explicitly".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/uninitialized-storage/".to_string()],
            },
        ]
    }

    fn load_default_rules() -> Vec<VulnerabilityRule> {
        vec![
            VulnerabilityRule {
                id: "NO_CONSTRUCTOR".to_string(),
                title: "Missing Constructor".to_string(),
                description: "Contract has no constructor for initialization".to_string(),
                category: "Initialization".to_string(),
                severity: "Low".to_string(),
                checker: Box::new(|contract| {
                    !contract.functions.iter().any(|f| f.name == "constructor")
                        && !contract.source_code.contains("constructor(")
                }),
                recommendation: "Consider adding a constructor for proper initialization".to_string(),
                references: vec!["https://docs.soliditylang.org/en/latest/contracts.html#constructors".to_string()],
            },
            VulnerabilityRule {
                id: "PUBLIC_BURN".to_string(),
                title: "Public Burn Function".to_string(),
                description: "Burn function is publicly accessible".to_string(),
                category: "Access Control".to_string(),
                severity: "High".to_string(),
                checker: Box::new(|contract| {
                    contract.functions.iter().any(|f| 
                        f.name.to_lowercase().contains("burn") && f.visibility == "public"
                    )
                }),
                recommendation: "Restrict access to burn functions or add proper access controls".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-vs-external/".to_string()],
            },
            VulnerabilityRule {
                id: "MULTIPLE_INHERITANCE".to_string(),
                title: "Complex Inheritance".to_string(),
                description: "Contract uses multiple inheritance which may lead to conflicts".to_string(),
                category: "Design".to_string(),
                severity: "Medium".to_string(),
                checker: Box::new(|contract| contract.inheritance.len() > 2),
                recommendation: "Simplify inheritance hierarchy to reduce complexity".to_string(),
                references: vec!["https://docs.soliditylang.org/en/latest/contracts.html#inheritance".to_string()],
            },
        ]
    }

    pub fn check_specific_vulnerability(&self, contract: &Contract, vuln_type: &str) -> Vec<Vulnerability> {
        match vuln_type {
            "reentrancy" => self.check_reentrancy(contract),
            "integer_overflow" => self.check_integer_overflow(contract),
            "access_control" => self.check_access_control(contract),
            "front_running" => self.check_front_running(contract),
            "dos" => self.check_dos_vulnerabilities(contract),
            _ => Vec::new(),
        }
    }

    fn check_reentrancy(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let source = &contract.source_code;

        // Look for external calls followed by state changes
        let call_pattern = Regex::new(r"\.call\{[^}]*\}\([^)]*\)").unwrap();
        let state_change_pattern = Regex::new(r"\w+\s*=\s*[^;]+;").unwrap();

        for call_match in call_pattern.find_iter(source) {
            let after_call = &source[call_match.end()..];
            if let Some(next_semicolon) = after_call.find(';') {
                let code_after = &after_call[..next_semicolon + 100.min(after_call.len() - next_semicolon)];
                if state_change_pattern.is_match(code_after) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("REENTRANCY_{}", vulnerabilities.len()),
                        title: "Potential Reentrancy Vulnerability".to_string(),
                        description: "State changes after external calls may be vulnerable to reentrancy".to_string(),
                        severity: "Critical".to_string(),
                        category: "Reentrancy".to_string(),
                        line_number: Some(self.get_line_number(source, call_match.start())),
                        code_snippet: Some(call_match.as_str().to_string()),
                        recommendation: "Use checks-effects-interactions pattern or add reentrancy guards".to_string(),
                        references: vec!["https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/".to_string()],
                    });
                }
            }
        }

        vulnerabilities
    }

    fn check_integer_overflow(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let source = &contract.source_code;

        // Check for pragma version that might be vulnerable to integer overflow
        if !source.contains("pragma solidity ^0.8") && !source.contains("pragma solidity >=0.8") {
            if source.contains('+') || source.contains('-') || source.contains('*') {
                vulnerabilities.push(Vulnerability {
                    id: "INTEGER_OVERFLOW".to_string(),
                    title: "Potential Integer Overflow".to_string(),
                    description: "Arithmetic operations without SafeMath in older Solidity versions".to_string(),
                    severity: "High".to_string(),
                    category: "Integer Overflow".to_string(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: "Upgrade to Solidity 0.8+ or use SafeMath library".to_string(),
                    references: vec!["https://consensys.github.io/smart-contract-best-practices/attacks/insecure-arithmetic/".to_string()],
                });
            }
        }

        vulnerabilities
    }

    fn check_access_control(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check for functions without proper access control
        for function in &contract.functions {
            if function.visibility == "public" && 
               !function.modifiers.iter().any(|m| m.contains("only")) &&
               !function.name.starts_with("get") &&
               !function.name.starts_with("view") {
                
                vulnerabilities.push(Vulnerability {
                    id: format!("ACCESS_CONTROL_{}", function.name),
                    title: format!("Missing Access Control for {}", function.name),
                    description: "Public function without access control modifiers".to_string(),
                    severity: "Medium".to_string(),
                    category: "Access Control".to_string(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: "Add appropriate access control modifiers".to_string(),
                    references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-vs-external/".to_string()],
                });
            }
        }

        vulnerabilities
    }

    fn check_front_running(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let source = &contract.source_code;

        // Look for potential front-running vulnerabilities
        if source.contains("block.timestamp") && source.contains("require") {
            vulnerabilities.push(Vulnerability {
                id: "FRONT_RUNNING".to_string(),
                title: "Potential Front-running Vulnerability".to_string(),
                description: "Time-dependent conditions may be exploitable".to_string(),
                severity: "Medium".to_string(),
                category: "Front-running".to_string(),
                line_number: None,
                code_snippet: None,
                recommendation: "Use commit-reveal schemes or other front-running protection".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/attacks/frontrunning/".to_string()],
            });
        }

        vulnerabilities
    }

    fn check_dos_vulnerabilities(&self, contract: &Contract) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let source = &contract.source_code;

        // Look for unbounded loops
        if source.contains("for") && source.contains("length") && !source.contains("require(") {
            vulnerabilities.push(Vulnerability {
                id: "DOS_UNBOUNDED_LOOP".to_string(),
                title: "Potential DoS via Unbounded Loop".to_string(),
                description: "Loop without gas limit checks may cause DoS".to_string(),
                severity: "Medium".to_string(),
                category: "DoS".to_string(),
                line_number: None,
                code_snippet: None,
                recommendation: "Add gas limit checks or bounds to loops".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/".to_string()],
            });
        }

        vulnerabilities
    }
}
