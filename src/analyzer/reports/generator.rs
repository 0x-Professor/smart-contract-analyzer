use crate::types::{AnalysisReport, Contract, GasReport, VulnerabilityReport};
use crate::analyzer::gas::StaticGasAnalyzer;
use crate::analyzer::vulnerabilities::VulnerabilityDetector;
use std::collections::HashMap;

pub struct ReportGenerator {
    gas_analyzer: StaticGasAnalyzer,
    vulnerability_detector: VulnerabilityDetector,
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator {
    pub fn new() -> Self {
        Self {
            gas_analyzer: StaticGasAnalyzer::new(),
            vulnerability_detector: VulnerabilityDetector::new(),
        }
    }

    pub fn generate_comprehensive_report(&self, contract: &Contract) -> crate::Result<AnalysisReport> {
        let gas_report = self.gas_analyzer.analyze_contract(contract)?;
        let vulnerability_report = self.vulnerability_detector.analyze_contract(contract)?;
        
        let summary = self.generate_summary(&gas_report, &vulnerability_report);
        let recommendations = self.generate_recommendations(&gas_report, &vulnerability_report);

        Ok(AnalysisReport {
            contract_name: contract.name.clone(),
            analysis_timestamp: chrono::Utc::now().to_string(),
            gas_report,
            vulnerability_report,
            summary,
            recommendations,
            metadata: self.generate_metadata(contract),
        })
    }

    pub fn generate_gas_only_report(&self, contract: &Contract) -> crate::Result<GasReport> {
        self.gas_analyzer.analyze_contract(contract)
    }

    pub fn generate_security_only_report(&self, contract: &Contract) -> crate::Result<VulnerabilityReport> {
        self.vulnerability_detector.analyze_contract(contract)
    }

    fn generate_summary(&self, gas_report: &GasReport, vuln_report: &VulnerabilityReport) -> ReportSummary {
        let overall_score = self.calculate_overall_score(gas_report, vuln_report);
        let risk_level = self.determine_risk_level(vuln_report);

        ReportSummary {
            overall_score,
            risk_level,
            total_issues: vuln_report.total_issues,
            gas_efficiency: self.calculate_gas_efficiency(gas_report),
            security_issues: SecurityIssueSummary {
                critical: vuln_report.critical_issues,
                high: vuln_report.high_issues,
                medium: vuln_report.medium_issues,
                low: vuln_report.low_issues,
            },
            optimization_potential: gas_report.optimization_suggestions.len(),
        }
    }

    fn generate_recommendations(&self, gas_report: &GasReport, vuln_report: &VulnerabilityReport) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Security recommendations
        if vuln_report.critical_issues > 0 {
            recommendations.push("🚨 CRITICAL: Address critical security vulnerabilities immediately".to_string());
        }
        if vuln_report.high_issues > 0 {
            recommendations.push("⚠️  HIGH: Fix high-priority security issues before deployment".to_string());
        }

        // Gas optimization recommendations
        if gas_report.total_estimated_gas > 1_000_000 {
            recommendations.push("⛽ Consider gas optimization - deployment cost is high".to_string());
        }
        
        if gas_report.optimization_suggestions.len() > 5 {
            recommendations.push("💡 Multiple gas optimization opportunities identified".to_string());
        }

        // General recommendations
        if vuln_report.total_issues == 0 && gas_report.optimization_suggestions.len() < 3 {
            recommendations.push("✅ Contract appears to be well-optimized and secure".to_string());
        }

        recommendations
    }

    fn generate_metadata(&self, contract: &Contract) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        
        metadata.insert("pragma_version".to_string(), contract.pragma_version.clone());
        metadata.insert("functions_count".to_string(), contract.functions.len().to_string());
        metadata.insert("state_variables_count".to_string(), contract.state_variables.len().to_string());
        metadata.insert("inheritance_count".to_string(), contract.inheritance.len().to_string());
        metadata.insert("events_count".to_string(), contract.events.len().to_string());
        metadata.insert("source_lines".to_string(), contract.source_code.lines().count().to_string());
        metadata.insert("has_bytecode".to_string(), contract.bytecode.is_some().to_string());
        metadata.insert("has_abi".to_string(), contract.abi.is_some().to_string());

        metadata
    }

    fn calculate_overall_score(&self, gas_report: &GasReport, vuln_report: &VulnerabilityReport) -> u8 {
        let mut score = 100u8;

        // Deduct points for vulnerabilities
        score = score.saturating_sub(vuln_report.critical_issues as u8 * 30);
        score = score.saturating_sub(vuln_report.high_issues as u8 * 20);
        score = score.saturating_sub(vuln_report.medium_issues as u8 * 10);
        score = score.saturating_sub(vuln_report.low_issues as u8 * 5);

        // Deduct points for gas inefficiency
        if gas_report.total_estimated_gas > 2_000_000 {
            score = score.saturating_sub(10);
        }
        if gas_report.optimization_suggestions.len() > 10 {
            score = score.saturating_sub(5);
        }

        score.max(0)
    }

    fn determine_risk_level(&self, vuln_report: &VulnerabilityReport) -> String {
        if vuln_report.critical_issues > 0 {
            "Critical".to_string()
        } else if vuln_report.high_issues > 0 {
            "High".to_string()
        } else if vuln_report.medium_issues > 3 {
            "Medium".to_string()
        } else if vuln_report.total_issues > 0 {
            "Low".to_string()
        } else {
            "Very Low".to_string()
        }
    }

    fn calculate_gas_efficiency(&self, gas_report: &GasReport) -> String {
        match gas_report.total_estimated_gas {
            0..=500_000 => "Excellent".to_string(),
            500_001..=1_000_000 => "Good".to_string(),
            1_000_001..=2_000_000 => "Fair".to_string(),
            _ => "Poor".to_string(),
        }
    }

    pub fn generate_comparison_report(&self, contracts: Vec<&Contract>) -> crate::Result<ComparisonReport> {
        let mut contract_reports = Vec::new();

        for contract in contracts {
            let report = self.generate_comprehensive_report(contract)?;
            contract_reports.push(report);
        }

        let best_gas_efficiency = contract_reports.iter()
            .min_by_key(|r| r.gas_report.total_estimated_gas)
            .map(|r| r.contract_name.clone());

        let most_secure = contract_reports.iter()
            .min_by_key(|r| r.vulnerability_report.total_issues)
            .map(|r| r.contract_name.clone());

        Ok(ComparisonReport {
            contracts: contract_reports,
            best_gas_efficiency,
            most_secure,
            analysis_timestamp: chrono::Utc::now().to_string(),
        })
    }

    pub fn generate_trend_report(&self, contract: &Contract, historical_reports: Vec<AnalysisReport>) -> TrendReport {
        let current_report = self.generate_comprehensive_report(contract).unwrap_or_else(|_| {
            // Fallback report if analysis fails
            AnalysisReport::default_for_contract(&contract.name)
        });

        let vulnerability_trend = self.calculate_vulnerability_trend(&historical_reports);
        let gas_trend = self.calculate_gas_trend(&historical_reports);

        TrendReport {
            contract_name: contract.name.clone(),
            current_report,
            historical_reports,
            vulnerability_trend,
            gas_trend,
            improvement_suggestions: self.generate_trend_based_suggestions(&vulnerability_trend, &gas_trend),
        }
    }

    fn calculate_vulnerability_trend(&self, reports: &[AnalysisReport]) -> TrendData {
        if reports.len() < 2 {
            return TrendData {
                direction: "Stable".to_string(),
                change_percentage: 0.0,
                improvement: true,
            };
        }

        let latest = reports.last().unwrap();
        let previous = &reports[reports.len() - 2];

        let latest_issues = latest.vulnerability_report.total_issues as f64;
        let previous_issues = previous.vulnerability_report.total_issues as f64;

        let change = if previous_issues == 0.0 {
            0.0
        } else {
            ((latest_issues - previous_issues) / previous_issues) * 100.0
        };

        TrendData {
            direction: if change > 5.0 {
                "Worsening".to_string()
            } else if change < -5.0 {
                "Improving".to_string()
            } else {
                "Stable".to_string()
            },
            change_percentage: change.abs(),
            improvement: change < 0.0,
        }
    }

    fn calculate_gas_trend(&self, reports: &[AnalysisReport]) -> TrendData {
        if reports.len() < 2 {
            return TrendData {
                direction: "Stable".to_string(),
                change_percentage: 0.0,
                improvement: true,
            };
        }

        let latest = reports.last().unwrap();
        let previous = &reports[reports.len() - 2];

        let latest_gas = latest.gas_report.total_estimated_gas as f64;
        let previous_gas = previous.gas_report.total_estimated_gas as f64;

        let change = if previous_gas == 0.0 {
            0.0
        } else {
            ((latest_gas - previous_gas) / previous_gas) * 100.0
        };

        TrendData {
            direction: if change > 10.0 {
                "Worsening".to_string()
            } else if change < -10.0 {
                "Improving".to_string()
            } else {
                "Stable".to_string()
            },
            change_percentage: change.abs(),
            improvement: change < 0.0,
        }
    }

    fn generate_trend_based_suggestions(&self, vuln_trend: &TrendData, gas_trend: &TrendData) -> Vec<String> {
        let mut suggestions = Vec::new();

        if !vuln_trend.improvement {
            suggestions.push("🔍 Security posture is declining - review recent changes".to_string());
        }

        if !gas_trend.improvement {
            suggestions.push("⛽ Gas efficiency is declining - consider optimization review".to_string());
        }

        if vuln_trend.improvement && gas_trend.improvement {
            suggestions.push("📈 Good progress on both security and gas efficiency".to_string());
        }

        suggestions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub overall_score: u8,
    pub risk_level: String,
    pub total_issues: usize,
    pub gas_efficiency: String,
    pub security_issues: SecurityIssueSummary,
    pub optimization_potential: usize,
}

#[derive(Debug, Clone)]
pub struct SecurityIssueSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone)]
pub struct ComparisonReport {
    pub contracts: Vec<AnalysisReport>,
    pub best_gas_efficiency: Option<String>,
    pub most_secure: Option<String>,
    pub analysis_timestamp: String,
}

#[derive(Debug, Clone)]
pub struct TrendReport {
    pub contract_name: String,
    pub current_report: AnalysisReport,
    pub historical_reports: Vec<AnalysisReport>,
    pub vulnerability_trend: TrendData,
    pub gas_trend: TrendData,
    pub improvement_suggestions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrendData {
    pub direction: String,
    pub change_percentage: f64,
    pub improvement: bool,
}
