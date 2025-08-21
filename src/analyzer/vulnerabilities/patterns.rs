use crate::types::Contract;

#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub regex_pattern: String,
    pub recommendation: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DetectionPattern {
    pub name: String,
    pub pattern_type: PatternType,
    pub regex: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum PatternType {
    Regex,
    Semantic,
    Structural,
}

pub struct PatternMatcher {
    patterns: Vec<VulnerabilityPattern>,
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternMatcher {
    pub fn new() -> Self {
        Self {
            patterns: Self::load_patterns(),
        }
    }

    pub fn get_patterns(&self) -> &Vec<VulnerabilityPattern> {
        &self.patterns
    }

    fn load_patterns() -> Vec<VulnerabilityPattern> {
        vec![
            VulnerabilityPattern {
                id: "REENTRANCY_EXTERNAL_CALL".to_string(),
                title: "Reentrancy via External Call".to_string(),
                description: "External call that may allow reentrancy attacks".to_string(),
                category: "Reentrancy".to_string(),
                severity: "Critical".to_string(),
                regex_pattern: r"\.call\{[^}]*\}|\.\w+\.call\(|\w+\.transfer\(|\w+\.send\(".to_string(),
                recommendation: "Use reentrancy guards or checks-effects-interactions pattern".to_string(),
                references: vec![
                    "https://swcregistry.io/docs/SWC-107".to_string(),
                    "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/".to_string(),
                ],
            },
            VulnerabilityPattern {
                id: "UNCHECKED_LOW_LEVEL_CALL".to_string(),
                title: "Unchecked Low-level Call".to_string(),
                description: "Low-level call without checking return value".to_string(),
                category: "Unchecked Return Values".to_string(),
                severity: "High".to_string(),
                regex_pattern: r"\.call\([^)]*\)(?!\s*;?\s*(?:require|assert|\|\|))".to_string(),
                recommendation: "Always check the return value of low-level calls".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-104".to_string()],
            },
            VulnerabilityPattern {
                id: "TX_ORIGIN_AUTHENTICATION".to_string(),
                title: "tx.origin Authentication".to_string(),
                description: "Using tx.origin for authentication is vulnerable".to_string(),
                category: "Authorization".to_string(),
                severity: "Medium".to_string(),
                regex_pattern: r"tx\.origin\s*[=!<>]".to_string(),
                recommendation: "Use msg.sender instead of tx.origin for authentication".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-115".to_string()],
            },
            VulnerabilityPattern {
                id: "BLOCKHASH_WEAKNESS".to_string(),
                title: "Weak Randomness from Blockhash".to_string(),
                description: "Using blockhash for randomness is predictable".to_string(),
                category: "Randomness".to_string(),
                severity: "Medium".to_string(),
                regex_pattern: r"blockhash\(|block\.hash".to_string(),
                recommendation: "Use a secure randomness source like Chainlink VRF".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-120".to_string()],
            },
            VulnerabilityPattern {
                id: "TIMESTAMP_DEPENDENCE".to_string(),
                title: "Block Timestamp Manipulation".to_string(),
                description: "Relying on block.timestamp for critical logic".to_string(),
                category: "Timestamp".to_string(),
                severity: "Medium".to_string(),
                regex_pattern: r"block\.timestamp|now\b".to_string(),
                recommendation: "Avoid using timestamps for critical contract logic".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-116".to_string()],
            },
            VulnerabilityPattern {
                id: "SUICIDE_SELFDESTRUCT".to_string(),
                title: "Use of Deprecated suicide/selfdestruct".to_string(),
                description: "Contract uses deprecated suicide or risky selfdestruct".to_string(),
                category: "Deprecated".to_string(),
                severity: "High".to_string(),
                regex_pattern: r"\bsuicide\(|\bselfdestruct\(".to_string(),
                recommendation: "Avoid using selfdestruct or implement proper access controls".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-106".to_string()],
            },
            VulnerabilityPattern {
                id: "UNINITIALIZED_STORAGE_POINTER".to_string(),
                title: "Uninitialized Storage Pointer".to_string(),
                description: "Storage pointer without initialization".to_string(),
                category: "Uninitialized Storage".to_string(),
                severity: "High".to_string(),
                regex_pattern: r"storage\s+\w+\s+\w+(?!\s*=)".to_string(),
                recommendation: "Always initialize storage pointers".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-109".to_string()],
            },
            VulnerabilityPattern {
                id: "DELEGATECALL_TO_UNTRUSTED".to_string(),
                title: "Delegatecall to Untrusted Contract".to_string(),
                description: "Delegatecall to user-controlled addresses".to_string(),
                category: "Delegatecall".to_string(),
                severity: "Critical".to_string(),
                regex_pattern: r"\.delegatecall\(".to_string(),
                recommendation: "Avoid delegatecall to untrusted contracts".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-112".to_string()],
            },
            VulnerabilityPattern {
                id: "INSUFFICIENT_GAS_GRIEFING".to_string(),
                title: "Insufficient Gas Griefing".to_string(),
                description: "External call without gas stipend may fail".to_string(),
                category: "Gas".to_string(),
                severity: "Medium".to_string(),
                regex_pattern: r"\.call\([^}]*\)\s*(?!\{gas:)".to_string(),
                recommendation: "Specify gas limits for external calls".to_string(),
                references: vec!["https://swcregistry.io/docs/SWC-126".to_string()],
            },
        ]
    }

    pub fn match_patterns(&self, source_code: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            if let Ok(regex) = regex::Regex::new(&pattern.regex_pattern) {
                for mat in regex.find_iter(source_code) {
                    matches.push(PatternMatch {
                        pattern_id: pattern.id.clone(),
                        start: mat.start(),
                        end: mat.end(),
                        matched_text: mat.as_str().to_string(),
                        line_number: self.get_line_number(source_code, mat.start()),
                    });
                }
            }
        }

        matches
    }

    fn get_line_number(&self, source: &str, position: usize) -> usize {
        source[..position].matches('\n').count() + 1
    }

    pub fn check_semantic_patterns(&self, contract: &Contract) -> Vec<SemanticMatch> {
        let mut matches = Vec::new();

        // Check for complex semantic patterns that regex can't catch
        
        // Check for reentrancy patterns
        if self.has_external_call_before_state_change(contract) {
            matches.push(SemanticMatch {
                pattern_name: "Complex Reentrancy".to_string(),
                description: "External call followed by state changes".to_string(),
                severity: "Critical".to_string(),
                functions_affected: self.get_affected_functions(contract),
            });
        }

        // Check for access control issues
        if self.has_missing_access_control(contract) {
            matches.push(SemanticMatch {
                pattern_name: "Missing Access Control".to_string(),
                description: "Critical functions without proper access control".to_string(),
                severity: "High".to_string(),
                functions_affected: self.get_unprotected_functions(contract),
            });
        }

        matches
    }

    fn has_external_call_before_state_change(&self, contract: &Contract) -> bool {
        // Simplified check - in reality this would need more sophisticated analysis
        contract.source_code.contains(".call") && contract.source_code.contains("=")
    }

    fn has_missing_access_control(&self, contract: &Contract) -> bool {
        contract.functions.iter().any(|f| {
            f.visibility == "public" && 
            !f.modifiers.iter().any(|m| m.contains("only")) &&
            (f.name.contains("withdraw") || f.name.contains("transfer") || f.name.contains("burn"))
        })
    }

    fn get_affected_functions(&self, contract: &Contract) -> Vec<String> {
        contract.functions.iter()
            .filter(|f| f.body.contains(".call"))
            .map(|f| f.name.clone())
            .collect()
    }

    fn get_unprotected_functions(&self, contract: &Contract) -> Vec<String> {
        contract.functions.iter()
            .filter(|f| {
                f.visibility == "public" && 
                !f.modifiers.iter().any(|m| m.contains("only")) &&
                (f.name.contains("withdraw") || f.name.contains("transfer") || f.name.contains("burn"))
            })
            .map(|f| f.name.clone())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub start: usize,
    pub end: usize,
    pub matched_text: String,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub struct SemanticMatch {
    pub pattern_name: String,
    pub description: String,
    pub severity: String,
    pub functions_affected: Vec<String>,
}
