use crate::types::AnalysisReport;
use serde_json;
use std::fs;

pub struct ReportFormatter;

impl ReportFormatter {
    pub fn new() -> Self {
        Self
    }

    pub fn format_json(&self, report: &AnalysisReport) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(report)?)
    }

    pub fn format_text(&self, report: &AnalysisReport) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("🔍 Smart Contract Analysis Report\n"));
        output.push_str(&format!("══════════════════════════════════\n\n"));
        
        output.push_str(&format!("Contract: {}\n", report.contract_name));
        output.push_str(&format!("Analysis Date: {}\n\n", report.analysis_timestamp));
        
        // Overall Summary
        output.push_str(&format!("📊 OVERALL SUMMARY\n"));
        output.push_str(&format!("─────────────────\n"));
        output.push_str(&format!("Overall Score: {}/100\n", report.summary.overall_score));
        output.push_str(&format!("Risk Level: {}\n", report.summary.risk_level));
        output.push_str(&format!("Gas Efficiency: {}\n\n", report.summary.gas_efficiency));
        
        // Security Issues
        output.push_str(&format!("🛡️  SECURITY ANALYSIS\n"));
        output.push_str(&format!("────────────────────\n"));
        output.push_str(&format!("Total Issues: {}\n", report.vulnerability_report.total_issues));
        output.push_str(&format!("  • Critical: {}\n", report.summary.security_issues.critical));
        output.push_str(&format!("  • High:     {}\n", report.summary.security_issues.high));
        output.push_str(&format!("  • Medium:   {}\n", report.summary.security_issues.medium));
        output.push_str(&format!("  • Low:      {}\n\n", report.summary.security_issues.low));
        
        // Vulnerabilities Details
        if !report.vulnerability_report.vulnerabilities.is_empty() {
            output.push_str(&format!("🚨 VULNERABILITY DETAILS\n"));
            output.push_str(&format!("───────────────────────\n"));
            for (i, vuln) in report.vulnerability_report.vulnerabilities.iter().enumerate() {
                output.push_str(&format!("{}. {} [{}]\n", i + 1, vuln.title, vuln.severity));
                output.push_str(&format!("   Category: {}\n", vuln.category));
                output.push_str(&format!("   Description: {}\n", vuln.description));
                if let Some(line) = vuln.line_number {
                    output.push_str(&format!("   Line: {}\n", line));
                }
                output.push_str(&format!("   Recommendation: {}\n\n", vuln.recommendation));
            }
        }
        
        // Gas Analysis
        output.push_str(&format!("⛽ GAS ANALYSIS\n"));
        output.push_str(&format!("──────────────\n"));
        output.push_str(&format!("Total Estimated Gas: {}\n", report.gas_report.total_estimated_gas));
        output.push_str(&format!("Optimization Opportunities: {}\n\n", report.gas_report.optimization_suggestions.len()));
        
        // Function Gas Costs
        if !report.gas_report.function_gas_costs.is_empty() {
            output.push_str(&format!("Function Gas Costs:\n"));
            for (func, cost) in &report.gas_report.function_gas_costs {
                output.push_str(&format!("  • {}: {}\n", func, cost));
            }
            output.push_str("\n");
        }
        
        // Gas Optimization Suggestions
        if !report.gas_report.optimization_suggestions.is_empty() {
            output.push_str(&format!("💡 GAS OPTIMIZATION SUGGESTIONS\n"));
            output.push_str(&format!("──────────────────────────────\n"));
            for (i, suggestion) in report.gas_report.optimization_suggestions.iter().enumerate() {
                output.push_str(&format!("{}. {}\n", i + 1, suggestion));
            }
            output.push_str("\n");
        }
        
        // Recommendations
        if !report.recommendations.is_empty() {
            output.push_str(&format!("📋 RECOMMENDATIONS\n"));
            output.push_str(&format!("─────────────────\n"));
            for (i, rec) in report.recommendations.iter().enumerate() {
                output.push_str(&format!("{}. {}\n", i + 1, rec));
            }
            output.push_str("\n");
        }
        
        // Metadata
        output.push_str(&format!("📈 CONTRACT METADATA\n"));
        output.push_str(&format!("───────────────────\n"));
        for (key, value) in &report.metadata {
            output.push_str(&format!("{}: {}\n", key.replace('_', " ").to_uppercase(), value));
        }
        
        output
    }

    pub fn format_html(&self, report: &AnalysisReport) -> String {
        let mut html = String::new();
        
        html.push_str("<!DOCTYPE html>\n");
        html.push_str("<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str("<title>Smart Contract Analysis Report</title>\n");
        html.push_str("<style>\n");
        html.push_str(include_str!("../../../assets/report.css"));
        html.push_str("</style>\n</head>\n<body>\n");
        
        // Header
        html.push_str(&format!("<div class=\"header\">\n"));
        html.push_str(&format!("<h1>🔍 Smart Contract Analysis Report</h1>\n"));
        html.push_str(&format!("<h2>{}</h2>\n", report.contract_name));
        html.push_str(&format!("<p>Analysis Date: {}</p>\n", report.analysis_timestamp));
        html.push_str("</div>\n");
        
        // Summary
        html.push_str("<div class=\"summary\">\n");
        html.push_str("<h3>📊 Overall Summary</h3>\n");
        html.push_str(&format!("<div class=\"score-badge score-{}\">{}/100</div>\n", 
            Self::get_score_class(report.summary.overall_score), report.summary.overall_score));
        html.push_str(&format!("<p><strong>Risk Level:</strong> <span class=\"risk-{}\">{}</span></p>\n", 
            report.summary.risk_level.to_lowercase(), report.summary.risk_level));
        html.push_str(&format!("<p><strong>Gas Efficiency:</strong> {}</p>\n", report.summary.gas_efficiency));
        html.push_str("</div>\n");
        
        // Security Issues
        html.push_str("<div class=\"security\">\n");
        html.push_str("<h3>🛡️ Security Analysis</h3>\n");
        html.push_str(&format!("<div class=\"issue-summary\">\n"));
        html.push_str(&format!("<div class=\"issue-count critical\">Critical: {}</div>\n", report.summary.security_issues.critical));
        html.push_str(&format!("<div class=\"issue-count high\">High: {}</div>\n", report.summary.security_issues.high));
        html.push_str(&format!("<div class=\"issue-count medium\">Medium: {}</div>\n", report.summary.security_issues.medium));
        html.push_str(&format!("<div class=\"issue-count low\">Low: {}</div>\n", report.summary.security_issues.low));
        html.push_str("</div>\n");
        
        // Vulnerability details
        if !report.vulnerability_report.vulnerabilities.is_empty() {
            html.push_str("<div class=\"vulnerabilities\">\n");
            for vuln in &report.vulnerability_report.vulnerabilities {
                html.push_str(&format!("<div class=\"vulnerability {}\">\n", vuln.severity.to_lowercase()));
                html.push_str(&format!("<h4>{}</h4>\n", vuln.title));
                html.push_str(&format!("<p class=\"category\">{}</p>\n", vuln.category));
                html.push_str(&format!("<p>{}</p>\n", vuln.description));
                if let Some(line) = vuln.line_number {
                    html.push_str(&format!("<p class=\"line\">Line: {}</p>\n", line));
                }
                html.push_str(&format!("<p class=\"recommendation\"><strong>Recommendation:</strong> {}</p>\n", vuln.recommendation));
                html.push_str("</div>\n");
            }
            html.push_str("</div>\n");
        }
        html.push_str("</div>\n");
        
        // Gas Analysis
        html.push_str("<div class=\"gas-analysis\">\n");
        html.push_str("<h3>⛽ Gas Analysis</h3>\n");
        html.push_str(&format!("<p><strong>Total Estimated Gas:</strong> {}</p>\n", report.gas_report.total_estimated_gas));
        
        if !report.gas_report.function_gas_costs.is_empty() {
            html.push_str("<h4>Function Gas Costs</h4>\n");
            html.push_str("<ul>\n");
            for (func, cost) in &report.gas_report.function_gas_costs {
                html.push_str(&format!("<li>{}: {}</li>\n", func, cost));
            }
            html.push_str("</ul>\n");
        }
        
        if !report.gas_report.optimization_suggestions.is_empty() {
            html.push_str("<h4>💡 Optimization Suggestions</h4>\n");
            html.push_str("<ul>\n");
            for suggestion in &report.gas_report.optimization_suggestions {
                html.push_str(&format!("<li>{}</li>\n", suggestion));
            }
            html.push_str("</ul>\n");
        }
        html.push_str("</div>\n");
        
        html.push_str("</body>\n</html>");
        html
    }

    pub fn format_markdown(&self, report: &AnalysisReport) -> String {
        let mut md = String::new();
        
        md.push_str(&format!("# 🔍 Smart Contract Analysis Report\n\n"));
        md.push_str(&format!("**Contract:** {}\n", report.contract_name));
        md.push_str(&format!("**Analysis Date:** {}\n\n", report.analysis_timestamp));
        
        // Summary
        md.push_str("## 📊 Overall Summary\n\n");
        md.push_str(&format!("- **Overall Score:** {}/100\n", report.summary.overall_score));
        md.push_str(&format!("- **Risk Level:** {}\n", report.summary.risk_level));
        md.push_str(&format!("- **Gas Efficiency:** {}\n\n", report.summary.gas_efficiency));
        
        // Security Issues
        md.push_str("## 🛡️ Security Analysis\n\n");
        md.push_str(&format!("**Total Issues:** {}\n\n", report.vulnerability_report.total_issues));
        md.push_str(&format!("| Severity | Count |\n"));
        md.push_str(&format!("|----------|-------|\n"));
        md.push_str(&format!("| Critical | {} |\n", report.summary.security_issues.critical));
        md.push_str(&format!("| High     | {} |\n", report.summary.security_issues.high));
        md.push_str(&format!("| Medium   | {} |\n", report.summary.security_issues.medium));
        md.push_str(&format!("| Low      | {} |\n\n", report.summary.security_issues.low));
        
        // Vulnerabilities
        if !report.vulnerability_report.vulnerabilities.is_empty() {
            md.push_str("### 🚨 Vulnerability Details\n\n");
            for (i, vuln) in report.vulnerability_report.vulnerabilities.iter().enumerate() {
                md.push_str(&format!("#### {}. {} `[{}]`\n\n", i + 1, vuln.title, vuln.severity));
                md.push_str(&format!("**Category:** {}\n\n", vuln.category));
                md.push_str(&format!("{}\n\n", vuln.description));
                if let Some(line) = vuln.line_number {
                    md.push_str(&format!("**Line:** {}\n\n", line));
                }
                md.push_str(&format!("**Recommendation:** {}\n\n", vuln.recommendation));
                md.push_str("---\n\n");
            }
        }
        
        // Gas Analysis
        md.push_str("## ⛽ Gas Analysis\n\n");
        md.push_str(&format!("**Total Estimated Gas:** {}\n\n", report.gas_report.total_estimated_gas));
        
        if !report.gas_report.function_gas_costs.is_empty() {
            md.push_str("### Function Gas Costs\n\n");
            md.push_str("| Function | Gas Cost |\n");
            md.push_str("|----------|----------|\n");
            for (func, cost) in &report.gas_report.function_gas_costs {
                md.push_str(&format!("| {} | {} |\n", func, cost));
            }
            md.push_str("\n");
        }
        
        if !report.gas_report.optimization_suggestions.is_empty() {
            md.push_str("### 💡 Optimization Suggestions\n\n");
            for (i, suggestion) in report.gas_report.optimization_suggestions.iter().enumerate() {
                md.push_str(&format!("{}. {}\n", i + 1, suggestion));
            }
            md.push_str("\n");
        }
        
        md
    }

    pub fn save_report(&self, report: &AnalysisReport, format: &str, path: &str) -> crate::Result<()> {
        let content = match format.to_lowercase().as_str() {
            "json" => self.format_json(report)?,
            "html" => self.format_html(report),
            "markdown" | "md" => self.format_markdown(report),
            "text" | "txt" => self.format_text(report),
            _ => return Err("Unsupported format".into()),
        };

        fs::write(path, content)?;
        Ok(())
    }

    fn get_score_class(score: u8) -> &'static str {
        match score {
            90..=100 => "excellent",
            75..=89 => "good",
            60..=74 => "fair",
            _ => "poor",
        }
    }
}

impl Default for ReportFormatter {
    fn default() -> Self {
        Self::new()
    }
}
