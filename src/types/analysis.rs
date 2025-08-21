use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::analyzer::reports::{ReportSummary, SecurityIssueSummary};
use crate::types::vulnerability::Vulnerability;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub contract_name: String,
    pub analysis_timestamp: String,
    pub gas_report: GasReport,
    pub vulnerability_report: VulnerabilityReport,
    pub summary: ReportSummary,
    pub recommendations: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasReport {
    pub contract_name: String,
    pub total_estimated_gas: u32,
    pub function_gas_costs: HashMap<String, u32>,
    pub optimization_suggestions: Vec<String>,
    pub expensive_operations: Vec<String>,
    pub storage_operations: u32,
    pub external_calls: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    pub contract_name: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub total_issues: usize,
    pub critical_issues: usize,
    pub high_issues: usize,
    pub medium_issues: usize,
    pub low_issues: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub gas_savings: usize,
    pub code_example: Option<String>,
}

impl AnalysisReport {
    pub fn new(contract_name: String) -> Self {
        Self {
            contract_name: contract_name.clone(),
            analysis_timestamp: chrono::Utc::now().to_string(),
            gas_report: GasReport::new(contract_name.clone()),
            vulnerability_report: VulnerabilityReport::new(contract_name.clone()),
            summary: ReportSummary {
                overall_score: 0,
                risk_level: "Unknown".to_string(),
                total_issues: 0,
                gas_efficiency: "Unknown".to_string(),
                security_issues: SecurityIssueSummary {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                },
                optimization_potential: 0,
            },
            recommendations: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn default_for_contract(contract_name: &str) -> Self {
        Self::new(contract_name.to_string())
    }

    pub fn is_secure(&self) -> bool {
        self.vulnerability_report.critical_issues == 0 && 
        self.vulnerability_report.high_issues == 0
    }

    pub fn is_gas_efficient(&self) -> bool {
        self.gas_report.total_estimated_gas < 1_000_000
    }

    pub fn get_severity_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        counts.insert("Critical".to_string(), self.vulnerability_report.critical_issues);
        counts.insert("High".to_string(), self.vulnerability_report.high_issues);
        counts.insert("Medium".to_string(), self.vulnerability_report.medium_issues);
        counts.insert("Low".to_string(), self.vulnerability_report.low_issues);
        counts
    }

    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

impl GasReport {
    pub fn new(contract_name: String) -> Self {
        Self {
            contract_name,
            total_estimated_gas: 0,
            function_gas_costs: HashMap::new(),
            optimization_suggestions: Vec::new(),
            expensive_operations: Vec::new(),
            storage_operations: 0,
            external_calls: 0,
        }
    }

    pub fn add_function_gas_cost(&mut self, function: String, cost: u32) {
        self.function_gas_costs.insert(function, cost);
    }

    pub fn add_optimization_suggestion(&mut self, suggestion: String) {
        self.optimization_suggestions.push(suggestion);
    }

    pub fn get_most_expensive_function(&self) -> Option<(&String, &u32)> {
        self.function_gas_costs.iter().max_by_key(|(_, &cost)| cost)
    }

    pub fn get_average_function_gas_cost(&self) -> u32 {
        if self.function_gas_costs.is_empty() {
            0
        } else {
            self.function_gas_costs.values().sum::<u32>() / self.function_gas_costs.len() as u32
        }
    }
}

impl VulnerabilityReport {
    pub fn new(contract_name: String) -> Self {
        Self {
            contract_name,
            vulnerabilities: Vec::new(),
            total_issues: 0,
            critical_issues: 0,
            high_issues: 0,
            medium_issues: 0,
            low_issues: 0,
        }
    }

    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        match vulnerability.severity.as_str() {
            "Critical" => self.critical_issues += 1,
            "High" => self.high_issues += 1,
            "Medium" => self.medium_issues += 1,
            "Low" => self.low_issues += 1,
            _ => {}
        }
        self.vulnerabilities.push(vulnerability);
        self.total_issues = self.vulnerabilities.len();
    }

    pub fn get_vulnerabilities_by_severity(&self, severity: &str) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == severity)
            .collect()
    }

    pub fn get_vulnerabilities_by_category(&self, category: &str) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.category == category)
            .collect()
    }

    pub fn has_critical_issues(&self) -> bool {
        self.critical_issues > 0
    }

    pub fn has_high_issues(&self) -> bool {
        self.high_issues > 0
    }

    pub fn get_unique_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self.vulnerabilities
            .iter()
            .map(|v| v.category.clone())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }
}

impl OptimizationSuggestion {
    pub fn new(title: String, description: String, gas_savings: usize) -> Self {
        Self {
            title,
            description,
            category: "General".to_string(),
            severity: "Medium".to_string(),
            gas_savings,
            code_example: None,
        }
    }

    pub fn with_category(mut self, category: String) -> Self {
        self.category = category;
        self
    }

    pub fn with_severity(mut self, severity: String) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_code_example(mut self, code_example: String) -> Self {
        self.code_example = Some(code_example);
        self
    }
}

// Additional analysis types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractComplexity {
    pub cyclomatic_complexity: u32,
    pub lines_of_code: usize,
    pub number_of_functions: usize,
    pub number_of_variables: usize,
    pub inheritance_depth: usize,
    pub complexity_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    pub overall_score: u8,
    pub vulnerability_score: u8,
    pub access_control_score: u8,
    pub input_validation_score: u8,
    pub error_handling_score: u8,
    pub best_practices_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasOptimizationReport {
    pub original_gas_estimate: u32,
    pub optimized_gas_estimate: u32,
    pub potential_savings: u32,
    pub savings_percentage: f64,
    pub optimizations_applied: Vec<OptimizationSuggestion>,
}

impl Default for AnalysisReport {
    fn default() -> Self {
        Self::new("Unknown".to_string())
    }
}
