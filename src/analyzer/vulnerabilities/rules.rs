use crate::types::Contract;

pub type RuleChecker = Box<dyn Fn(&Contract) -> bool + Send + Sync>;

pub struct VulnerabilityRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub checker: RuleChecker,
    pub recommendation: String,
    pub references: Vec<String>,
}

pub struct RuleEngine {
    rules: Vec<VulnerabilityRule>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Self::load_default_rules(),
        }
    }

    pub fn get_rules(&self) -> &Vec<VulnerabilityRule> {
        &self.rules
    }

    pub fn add_rule(&mut self, rule: VulnerabilityRule) {
        self.rules.push(rule);
    }

    fn load_default_rules() -> Vec<VulnerabilityRule> {
        vec![
            VulnerabilityRule {
                id: "MISSING_CONSTRUCTOR".to_string(),
                title: "Missing Constructor".to_string(),
                description: "Contract lacks proper initialization via constructor".to_string(),
                category: "Initialization".to_string(),
                severity: "Low".to_string(),
                checker: Box::new(|contract| {
                    !contract.functions.iter().any(|f| f.name == "constructor") &&
                    contract.state_variables.len() > 0
                }),
                recommendation: "Add a constructor to properly initialize state variables".to_string(),
                references: vec!["https://docs.soliditylang.org/en/latest/contracts.html#constructors".to_string()],
            },
            VulnerabilityRule {
                id: "PUBLIC_BURN_FUNCTION".to_string(),
                title: "Unrestricted Burn Function".to_string(),
                description: "Burn function is publicly accessible without restrictions".to_string(),
                category: "Access Control".to_string(),
                severity: "Critical".to_string(),
                checker: Box::new(|contract| {
                    contract.functions.iter().any(|f| {
                        f.name.to_lowercase().contains("burn") && 
                        f.visibility == "public" &&
                        !f.modifiers.iter().any(|m| m.contains("only"))
                    })
                }),
                recommendation: "Restrict burn function access to authorized users only".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-vs-external/".to_string()],
            },
            VulnerabilityRule {
                id: "COMPLEX_INHERITANCE".to_string(),
                title: "Complex Inheritance Chain".to_string(),
                description: "Contract has complex multiple inheritance that may cause issues".to_string(),
                category: "Design".to_string(),
                severity: "Medium".to_string(),
                checker: Box::new(|contract| contract.inheritance.len() > 3),
                recommendation: "Simplify inheritance chain to reduce complexity and potential conflicts".to_string(),
                references: vec!["https://docs.soliditylang.org/en/latest/contracts.html#inheritance".to_string()],
            },
            VulnerabilityRule {
                id: "NO_FALLBACK_PAYABLE".to_string(),
                title: "Missing Payable Fallback".to_string(),
                description: "Contract can receive Ether but lacks proper fallback handling".to_string(),
                category: "Ether Handling".to_string(),
                severity: "Medium".to_string(),
                checker: Box::new(|contract| {
                    contract.functions.iter().any(|f| f.state_mutability == "payable") &&
                    !contract.source_code.contains("fallback()") &&
                    !contract.source_code.contains("receive()")
                }),
                recommendation: "Implement fallback() or receive() functions for proper Ether handling".to_string(),
                references: vec!["https://docs.soliditylang.org/en/latest/contracts.html#receive-ether-function".to_string()],
            },
            VulnerabilityRule {
                id: "UNUSED_STATE_VARIABLES".to_string(),
                title: "Unused State Variables".to_string(),
                description: "Contract contains state variables that are never used".to_string(),
                category: "Code Quality".to_string(),
                severity: "Low".to_string(),
                checker: Box::new(|contract| {
                    contract.state_variables.iter().any(|var| {
                        !contract.source_code.contains(&var.name) ||
                        contract.source_code.matches(&var.name).count() == 1 // Only declaration
                    })
                }),
                recommendation: "Remove unused state variables to save gas and improve code clarity".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/".to_string()],
            },
            VulnerabilityRule {
                id: "FLOATING_PRAGMA".to_string(),
                title: "Floating Pragma Version".to_string(),
                description: "Contract uses floating pragma which may cause compilation issues".to_string(),
                category: "Compiler".to_string(),
                severity: "Low".to_string(),
                checker: Box::new(|contract| {
                    contract.pragma_version.contains('^') || contract.pragma_version.contains('>')
                }),
                recommendation: "Use a fixed pragma version for consistent compilation".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/".to_string()],
            },
            VulnerabilityRule {
                id: "LARGE_NUMBER_OF_FUNCTIONS".to_string(),
                title: "Contract Too Complex".to_string(),
                description: "Contract has too many functions, indicating high complexity".to_string(),
                category: "Design".to_string(),
                severity: "Medium".to_string(),
                checker: Box::new(|contract| contract.functions.len() > 20),
                recommendation: "Consider breaking down the contract into smaller, focused contracts".to_string(),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/".to_string()],
            },
            VulnerabilityRule {
                id: "MISSING_NATSPEC".to_string(),
                title: "Missing Documentation".to_string(),
                description: "Contract functions lack proper NatSpec documentation".to_string(),
                category: "Documentation".to_string(),
                severity: "Low".to_string(),
                checker: Box::new(|contract| {
                    !contract.source_code.contains("@param") && 
                    !contract.source_code.contains("@return") &&
                    contract.functions.len() > 3
                }),
                recommendation: "Add NatSpec documentation to improve code maintainability".to_string(),
                references: vec!["https://docs.soliditylang.org/en/latest/natspec-format.html".to_string()],
            },
            VulnerabilityRule {
                id: "OUTDATED_COMPILER_VERSION".to_string(),
                title: "Outdated Compiler Version".to_string(),
                description: "Contract uses an outdated Solidity compiler version".to_string(),
                category: "Compiler".to_string(),
                severity: "Medium".to_string(),
                checker: Box::new(|contract| {
                    let version = &contract.pragma_version;
                    version.contains("0.6") || version.contains("0.7") || 
                    (version.contains("0.8") && !version.contains("0.8.2"))
                }),
                recommendation: "Update to the latest stable Solidity compiler version".to_string(),
                references: vec!["https://docs.soliditylang.org/en/latest/".to_string()],
            },
        ]
    }

    pub fn evaluate_rules(&self, contract: &Contract) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for rule in &self.rules {
            if (rule.checker)(contract) {
                violations.push(RuleViolation {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    description: rule.description.clone(),
                    category: rule.category.clone(),
                    severity: rule.severity.clone(),
                    recommendation: rule.recommendation.clone(),
                    references: rule.references.clone(),
                });
            }
        }

        violations
    }

    pub fn add_custom_rule<F>(&mut self, 
        id: String,
        title: String,
        description: String,
        category: String,
        severity: String,
        checker: F,
        recommendation: String,
        references: Vec<String>
    ) 
    where F: Fn(&Contract) -> bool + Send + Sync + 'static 
    {
        self.rules.push(VulnerabilityRule {
            id,
            title,
            description,
            category,
            severity,
            checker: Box::new(checker),
            recommendation,
            references,
        });
    }

    pub fn load_rules_from_config(&mut self, config_path: &str) -> crate::Result<()> {
        // Load additional rules from configuration file
        // This would parse a JSON/YAML file with rule definitions
        // For now, just return Ok
        println!("Loading rules from: {}", config_path);
        Ok(())
    }

    pub fn get_rules_by_category(&self, category: &str) -> Vec<&VulnerabilityRule> {
        self.rules.iter()
            .filter(|rule| rule.category == category)
            .collect()
    }

    pub fn get_rules_by_severity(&self, severity: &str) -> Vec<&VulnerabilityRule> {
        self.rules.iter()
            .filter(|rule| rule.severity == severity)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct RuleViolation {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub recommendation: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
}
