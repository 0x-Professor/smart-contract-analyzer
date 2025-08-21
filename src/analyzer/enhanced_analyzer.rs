use crate::parser::enhanced_solidity::{EnhancedSolidityParser, EnhancedContract};
use crate::detector::enhanced_detector::{EnhancedVulnerabilityDetector, SecurityAnalysis, VulnerabilitySeverity};
use crate::analyzer::gas_analyzer::{GasAnalyzer, GasAnalysisReport};
use anyhow::{Result, Context};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Enhanced smart contract analyzer with comprehensive analysis capabilities
pub struct EnhancedSmartContractAnalyzer {
    parser: EnhancedSolidityParser,
    vulnerability_detector: EnhancedVulnerabilityDetector,
    gas_analyzer: &'static GasAnalyzer,
    config: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub enable_vulnerability_detection: bool,
    pub enable_gas_analysis: bool,
    pub enable_code_quality_analysis: bool,
    pub enable_parallel_processing: bool,
    pub max_analysis_time: Duration,
    pub severity_threshold: SeverityLevel,
    pub gas_optimization_threshold: u64, // Minimum gas savings to report
    pub detailed_reports: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveAnalysisReport {
    pub contract_name: String,
    pub analysis_timestamp: chrono::DateTime<chrono::Utc>,
    pub analysis_duration: Duration,
    pub parsing_result: ParsingResult,
    pub security_analysis: Option<SecurityAnalysis>,
    pub gas_analysis: Option<GasAnalysisReport>,
    pub code_quality_metrics: Option<CodeQualityMetrics>,
    pub summary: AnalysisSummary,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsingResult {
    pub success: bool,
    pub contracts_found: u32,
    pub functions_analyzed: u32,
    pub state_variables_found: u32,
    pub parsing_errors: Vec<ParsingError>,
    pub parsing_warnings: Vec<ParsingWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsingError {
    pub line: usize,
    pub column: Option<usize>,
    pub message: String,
    pub error_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsingWarning {
    pub line: usize,
    pub message: String,
    pub warning_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQualityMetrics {
    pub complexity_score: u32,
    pub maintainability_index: f32, // 0-100, higher is better
    pub code_duplication_percentage: f32,
    pub test_coverage_estimate: f32, // Based on assertions and require statements
    pub documentation_score: f32, // Based on comments
    pub best_practices_compliance: f32, // 0-100
    pub issues: Vec<CodeQualityIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQualityIssue {
    pub issue_type: String,
    pub severity: SeverityLevel,
    pub location: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub overall_security_score: f32, // 0-100, higher is better
    pub overall_gas_efficiency: f32, // 0-100, higher is better
    pub overall_code_quality: f32,   // 0-100, higher is better
    pub critical_issues_count: u32,
    pub high_issues_count: u32,
    pub medium_issues_count: u32,
    pub low_issues_count: u32,
    pub total_gas_savings_potential: u64,
    pub recommendation_priority: RecommendationPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Immediate,  // Critical security issues
    High,       // High security issues or significant gas savings
    Medium,     // Medium issues or code quality improvements
    Low,        // Minor optimizations
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: RecommendationPriority,
    pub category: RecommendationCategory,
    pub impact: String,
    pub effort: EffortLevel,
    pub implementation_steps: Vec<String>,
    pub code_examples: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationCategory {
    Security,
    GasOptimization,
    CodeQuality,
    BestPractices,
    Performance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EffortLevel {
    Minimal,    // <1 hour
    Low,        // 1-4 hours
    Medium,     // 4-16 hours
    High,       // 16+ hours
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAnalysisResult {
    pub total_contracts: u32,
    pub successful_analyses: u32,
    pub failed_analyses: u32,
    pub total_duration: Duration,
    pub reports: Vec<ComprehensiveAnalysisReport>,
    pub batch_summary: BatchSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    pub most_critical_contract: Option<String>,
    pub most_efficient_contract: Option<String>,
    pub highest_quality_contract: Option<String>,
    pub common_vulnerabilities: HashMap<String, u32>,
    pub common_gas_issues: HashMap<String, u32>,
    pub average_scores: AverageScores,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AverageScores {
    pub security: f32,
    pub gas_efficiency: f32,
    pub code_quality: f32,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_vulnerability_detection: true,
            enable_gas_analysis: true,
            enable_code_quality_analysis: true,
            enable_parallel_processing: true,
            max_analysis_time: Duration::from_secs(300), // 5 minutes
            severity_threshold: SeverityLevel::Low,
            gas_optimization_threshold: 100, // Report optimizations saving 100+ gas
            detailed_reports: true,
        }
    }
}

impl EnhancedSmartContractAnalyzer {
    pub fn new(config: AnalysisConfig) -> Self {
        Self {
            parser: EnhancedSolidityParser::new(),
            vulnerability_detector: EnhancedVulnerabilityDetector::new(),
            gas_analyzer: GasAnalyzer::instance(),
            config,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(AnalysisConfig::default())
    }

    /// Analyze a single Solidity contract from source code
    pub fn analyze_contract(&self, source_code: &str, contract_name: Option<&str>) -> Result<ComprehensiveAnalysisReport> {
        let start_time = Instant::now();
        let analysis_timestamp = chrono::Utc::now();

        // Set up timeout
        let timeout = self.config.max_analysis_time;

        // Parse the contract
        let parsing_start = Instant::now();
        let parsing_result = self.parse_contract_with_timeout(source_code, timeout)?;
        let parsing_duration = parsing_start.elapsed();

        if parsing_duration > timeout {
            anyhow::bail!("Analysis timeout exceeded during parsing phase");
        }

        let remaining_time = timeout.saturating_sub(parsing_duration);

        // Perform analyses based on configuration
        let (security_analysis, gas_analysis, code_quality_metrics) = if self.config.enable_parallel_processing {
            self.perform_parallel_analysis(&parsing_result.contracts, remaining_time)?
        } else {
            self.perform_sequential_analysis(&parsing_result.contracts, remaining_time)?
        };

        let analysis_duration = start_time.elapsed();

        // Generate summary and recommendations
        let summary = self.generate_summary(
            &security_analysis,
            &gas_analysis,
            &code_quality_metrics,
        );

        let recommendations = self.generate_recommendations(
            &security_analysis,
            &gas_analysis,
            &code_quality_metrics,
        );

        let contract_name = contract_name
            .map(|s| s.to_string())
            .or_else(|| parsing_result.contracts.first().map(|c| c.name.clone()))
            .unwrap_or_else(|| "Unknown".to_string());

        Ok(ComprehensiveAnalysisReport {
            contract_name,
            analysis_timestamp,
            analysis_duration,
            parsing_result: ParsingResult {
                success: !parsing_result.contracts.is_empty(),
                contracts_found: parsing_result.contracts.len() as u32,
                functions_analyzed: parsing_result.contracts.iter()
                    .map(|c| c.functions.len() as u32)
                    .sum(),
                state_variables_found: parsing_result.contracts.iter()
                    .map(|c| c.state_variables.len() as u32)
                    .sum(),
                parsing_errors: parsing_result.errors,
                parsing_warnings: parsing_result.warnings,
            },
            security_analysis,
            gas_analysis,
            code_quality_metrics,
            summary,
            recommendations,
        })
    }

    /// Analyze multiple contracts from a directory
    pub fn analyze_directory<P: AsRef<Path>>(&self, directory_path: P) -> Result<BatchAnalysisResult> {
        let start_time = Instant::now();
        let solidity_files = self.find_solidity_files(directory_path.as_ref())?;
        
        let reports = if self.config.enable_parallel_processing {
            solidity_files
                .par_iter()
                .map(|file_path| {
                    let source_code = std::fs::read_to_string(file_path)
                        .context(format!("Failed to read file: {:?}", file_path))?;
                    let contract_name = file_path.file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string());
                    
                    self.analyze_contract(&source_code, contract_name.as_deref())
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let mut reports = Vec::new();
            for file_path in solidity_files.iter() {
                let source_code = std::fs::read_to_string(file_path)
                    .context(format!("Failed to read file: {:?}", file_path))?;
                let contract_name = file_path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string());
                
                let report = self.analyze_contract(&source_code, contract_name.as_deref())?;
                reports.push(report);
            }
            reports
        };

        let total_duration = start_time.elapsed();
        let successful_analyses = reports.len() as u32;
        let failed_analyses = solidity_files.len() as u32 - successful_analyses;

        let batch_summary = self.generate_batch_summary(&reports);

        Ok(BatchAnalysisResult {
            total_contracts: solidity_files.len() as u32,
            successful_analyses,
            failed_analyses,
            total_duration,
            reports,
            batch_summary,
        })
    }

    fn parse_contract_with_timeout(&self, source_code: &str, _timeout: Duration) -> Result<ContractParsingResult> {
        // Parse contracts
        let contracts = self.parser.parse_contracts(source_code)?;
        
        // For now, we'll simulate parsing errors and warnings
        // In a real implementation, these would come from the parser
        let errors = Vec::new();
        let warnings = Vec::new();

        Ok(ContractParsingResult {
            contracts,
            errors,
            warnings,
        })
    }

    fn perform_parallel_analysis(
        &self,
        contracts: &[EnhancedContract],
        timeout: Duration,
    ) -> Result<(Option<SecurityAnalysis>, Option<GasAnalysisReport>, Option<CodeQualityMetrics>)> {
        let start_time = Instant::now();

        // Use the primary contract (first one) for analysis
        let primary_contract = contracts.first()
            .context("No contracts found for analysis")?;

        // Run analyses in parallel
        let results: Vec<Result<AnalysisType>> = vec![
            if self.config.enable_vulnerability_detection {
                Some(|| -> Result<AnalysisType> {
                    let analysis = self.vulnerability_detector.analyze_contract(primary_contract)?;
                    Ok(AnalysisType::Security(analysis))
                })
            } else {
                None
            },
            if self.config.enable_gas_analysis {
                Some(|| -> Result<AnalysisType> {
                    let analysis = self.gas_analyzer.analyze_contract(primary_contract)?;
                    Ok(AnalysisType::Gas(analysis))
                })
            } else {
                None
            },
            if self.config.enable_code_quality_analysis {
                Some(|| -> Result<AnalysisType> {
                    let analysis = self.analyze_code_quality(primary_contract)?;
                    Ok(AnalysisType::CodeQuality(analysis))
                })
            } else {
                None
            },
        ]
        .into_iter()
        .filter_map(|f| f)
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|f| f())
        .collect();

        // Check timeout
        if start_time.elapsed() > timeout {
            anyhow::bail!("Analysis timeout exceeded during parallel analysis");
        }

        // Process results
        let mut security_analysis = None;
        let mut gas_analysis = None;
        let mut code_quality_metrics = None;

        for result in results {
            match result? {
                AnalysisType::Security(analysis) => security_analysis = Some(analysis),
                AnalysisType::Gas(analysis) => gas_analysis = Some(analysis),
                AnalysisType::CodeQuality(analysis) => code_quality_metrics = Some(analysis),
            }
        }

        Ok((security_analysis, gas_analysis, code_quality_metrics))
    }

    fn perform_sequential_analysis(
        &self,
        contracts: &[EnhancedContract],
        timeout: Duration,
    ) -> Result<(Option<SecurityAnalysis>, Option<GasAnalysisReport>, Option<CodeQualityMetrics>)> {
        let start_time = Instant::now();

        let primary_contract = contracts.first()
            .context("No contracts found for analysis")?;

        let mut security_analysis = None;
        let mut gas_analysis = None;
        let mut code_quality_metrics = None;

        // Security analysis
        if self.config.enable_vulnerability_detection {
            if start_time.elapsed() < timeout {
                security_analysis = Some(self.vulnerability_detector.analyze_contract(primary_contract)?);
            } else {
                anyhow::bail!("Analysis timeout exceeded during security analysis");
            }
        }

        // Gas analysis
        if self.config.enable_gas_analysis {
            if start_time.elapsed() < timeout {
                gas_analysis = Some(self.gas_analyzer.analyze_contract(primary_contract)?);
            } else {
                anyhow::bail!("Analysis timeout exceeded during gas analysis");
            }
        }

        // Code quality analysis
        if self.config.enable_code_quality_analysis {
            if start_time.elapsed() < timeout {
                code_quality_metrics = Some(self.analyze_code_quality(primary_contract)?);
            } else {
                anyhow::bail!("Analysis timeout exceeded during code quality analysis");
            }
        }

        Ok((security_analysis, gas_analysis, code_quality_metrics))
    }

    fn analyze_code_quality(&self, contract: &EnhancedContract) -> Result<CodeQualityMetrics> {
        let mut complexity_score = 0u32;
        let mut issues = Vec::new();

        // Calculate complexity based on functions
        for function in &contract.functions {
            complexity_score += function.complexity;

            // Check for long functions
            let line_count = function.body.lines().count();
            if line_count > 50 {
                issues.push(CodeQualityIssue {
                    issue_type: "Long Function".to_string(),
                    severity: SeverityLevel::Medium,
                    location: format!("Function: {}", function.name),
                    description: format!("Function has {} lines, consider breaking it down", line_count),
                    recommendation: "Split into smaller, more focused functions".to_string(),
                });
            }

            // Check for missing documentation
            if function.documentation.is_empty() {
                issues.push(CodeQualityIssue {
                    issue_type: "Missing Documentation".to_string(),
                    severity: SeverityLevel::Low,
                    location: format!("Function: {}", function.name),
                    description: "Function lacks documentation".to_string(),
                    recommendation: "Add NatSpec documentation".to_string(),
                });
            }
        }

        // Calculate maintainability index (simplified)
        let maintainability_index = if complexity_score > 0 {
            (100.0 - (complexity_score as f32 / contract.functions.len() as f32 * 10.0)).max(0.0)
        } else {
            100.0
        };

        // Estimate documentation score
        let total_lines = contract.source_code.lines().count() as f32;
        let comment_lines = contract.source_code.lines()
            .filter(|line| line.trim_start().starts_with("//") || line.trim_start().starts_with("/*"))
            .count() as f32;
        let documentation_score = (comment_lines / total_lines * 100.0).min(100.0);

        // Calculate best practices compliance
        let mut best_practices_score = 100.0f32;
        
        // Deduct points for issues
        for issue in &issues {
            match issue.severity {
                SeverityLevel::Critical => best_practices_score -= 25.0,
                SeverityLevel::High => best_practices_score -= 15.0,
                SeverityLevel::Medium => best_practices_score -= 10.0,
                SeverityLevel::Low => best_practices_score -= 5.0,
            }
        }

        best_practices_score = best_practices_score.max(0.0);

        Ok(CodeQualityMetrics {
            complexity_score,
            maintainability_index,
            code_duplication_percentage: 0.0, // Would require more sophisticated analysis
            test_coverage_estimate: 0.0,       // Would require test files analysis
            documentation_score,
            best_practices_compliance: best_practices_score,
            issues,
        })
    }

    fn generate_summary(
        &self,
        security_analysis: &Option<SecurityAnalysis>,
        gas_analysis: &Option<GasAnalysisReport>,
        code_quality_metrics: &Option<CodeQualityMetrics>,
    ) -> AnalysisSummary {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        // Count security issues
        if let Some(security) = security_analysis {
            for vuln in &security.vulnerabilities {
                match vuln.severity {
                    crate::detector::enhanced_detector::VulnerabilitySeverity::Critical => critical_count += 1,
                    crate::detector::enhanced_detector::VulnerabilitySeverity::High => high_count += 1,
                    crate::detector::enhanced_detector::VulnerabilitySeverity::Medium => medium_count += 1,
                    crate::detector::enhanced_detector::VulnerabilitySeverity::Low => low_count += 1,
                }
            }
        }

        // Count code quality issues
        if let Some(quality) = code_quality_metrics {
            for issue in &quality.issues {
                match issue.severity {
                    SeverityLevel::Critical => critical_count += 1,
                    SeverityLevel::High => high_count += 1,
                    SeverityLevel::Medium => medium_count += 1,
                    SeverityLevel::Low => low_count += 1,
                }
            }
        }

        // Calculate scores
        let overall_security_score = security_analysis
            .as_ref()
            .map(|s| s.security_score)
            .unwrap_or(50.0);

        let overall_gas_efficiency = gas_analysis
            .as_ref()
            .map(|g| match g.overall_efficiency {
                crate::analyzer::gas_analyzer::EfficiencyRating::Excellent => 95.0,
                crate::analyzer::gas_analyzer::EfficiencyRating::Good => 80.0,
                crate::analyzer::gas_analyzer::EfficiencyRating::Fair => 60.0,
                crate::analyzer::gas_analyzer::EfficiencyRating::Poor => 40.0,
            })
            .unwrap_or(50.0);

        let overall_code_quality = code_quality_metrics
            .as_ref()
            .map(|q| (q.maintainability_index + q.best_practices_compliance + q.documentation_score) / 3.0)
            .unwrap_or(50.0);

        let total_gas_savings_potential = gas_analysis
            .as_ref()
            .map(|g| g.optimizations.iter().map(|o| o.potential_savings.typical_savings()).sum())
            .unwrap_or(0);

        let recommendation_priority = if critical_count > 0 {
            RecommendationPriority::Immediate
        } else if high_count > 0 || total_gas_savings_potential > 10000 {
            RecommendationPriority::High
        } else if medium_count > 0 || total_gas_savings_potential > 1000 {
            RecommendationPriority::Medium
        } else {
            RecommendationPriority::Low
        };

        AnalysisSummary {
            overall_security_score,
            overall_gas_efficiency,
            overall_code_quality,
            critical_issues_count: critical_count,
            high_issues_count: high_count,
            medium_issues_count: medium_count,
            low_issues_count: low_count,
            total_gas_savings_potential,
            recommendation_priority,
        }
    }

    fn generate_recommendations(
        &self,
        security_analysis: &Option<SecurityAnalysis>,
        gas_analysis: &Option<GasAnalysisReport>,
        code_quality_metrics: &Option<CodeQualityMetrics>,
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Security recommendations
        if let Some(security) = security_analysis {
            for vulnerability in &security.vulnerabilities {
                let priority = match vulnerability.severity {
                    crate::detector::enhanced_detector::VulnerabilitySeverity::Critical => RecommendationPriority::Immediate,
                    crate::detector::enhanced_detector::VulnerabilitySeverity::High => RecommendationPriority::High,
                    crate::detector::enhanced_detector::VulnerabilitySeverity::Medium => RecommendationPriority::Medium,
                    crate::detector::enhanced_detector::VulnerabilitySeverity::Low => RecommendationPriority::Low,
                };

                recommendations.push(Recommendation {
                    id: vulnerability.swc_id.clone(),
                    title: vulnerability.title.clone(),
                    description: vulnerability.description.clone(),
                    priority,
                    category: RecommendationCategory::Security,
                    impact: vulnerability.impact.clone(),
                    effort: EffortLevel::Medium, // Default, could be more sophisticated
                    implementation_steps: vec![vulnerability.recommendation.clone()],
                    code_examples: vulnerability.example.as_ref().map(|e| format!("Before:\n{}\n\nAfter:\n{}", e.vulnerable_code, e.fixed_code)),
                });
            }
        }

        // Gas optimization recommendations
        if let Some(gas) = gas_analysis {
            for optimization in &gas.optimizations {
                if optimization.potential_savings.typical_savings() >= self.config.gas_optimization_threshold {
                    let priority = if optimization.potential_savings.typical_savings() > 10000 {
                        RecommendationPriority::High
                    } else if optimization.potential_savings.typical_savings() > 1000 {
                        RecommendationPriority::Medium
                    } else {
                        RecommendationPriority::Low
                    };

                    recommendations.push(Recommendation {
                        id: optimization.id.clone(),
                        title: optimization.title.clone(),
                        description: optimization.description.clone(),
                        priority,
                        category: RecommendationCategory::GasOptimization,
                        impact: format!("Potential savings: {} gas", optimization.potential_savings.typical_savings()),
                        effort: EffortLevel::Low, // Gas optimizations are usually simple
                        implementation_steps: vec![optimization.recommendation.clone()],
                        code_examples: optimization.code_examples.as_ref().map(|e| format!("Before:\n{}\n\nAfter:\n{}\n\nSavings: {}", e.before, e.after, e.savings_explanation)),
                    });
                }
            }
        }

        // Code quality recommendations
        if let Some(quality) = code_quality_metrics {
            for issue in &quality.issues {
                let priority = match issue.severity {
                    SeverityLevel::Critical => RecommendationPriority::Immediate,
                    SeverityLevel::High => RecommendationPriority::High,
                    SeverityLevel::Medium => RecommendationPriority::Medium,
                    SeverityLevel::Low => RecommendationPriority::Low,
                };

                recommendations.push(Recommendation {
                    id: format!("QUALITY_{}", issue.issue_type.replace(" ", "_").to_uppercase()),
                    title: format!("Improve {}", issue.issue_type),
                    description: issue.description.clone(),
                    priority,
                    category: RecommendationCategory::CodeQuality,
                    impact: "Improved code maintainability and readability".to_string(),
                    effort: EffortLevel::Minimal,
                    implementation_steps: vec![issue.recommendation.clone()],
                    code_examples: None,
                });
            }
        }

        // Sort by priority
        recommendations.sort_by(|a, b| {
            use std::cmp::Ordering;
            match (&a.priority, &b.priority) {
                (RecommendationPriority::Immediate, RecommendationPriority::Immediate) => Ordering::Equal,
                (RecommendationPriority::Immediate, _) => Ordering::Less,
                (_, RecommendationPriority::Immediate) => Ordering::Greater,
                (RecommendationPriority::High, RecommendationPriority::High) => Ordering::Equal,
                (RecommendationPriority::High, _) => Ordering::Less,
                (_, RecommendationPriority::High) => Ordering::Greater,
                (RecommendationPriority::Medium, RecommendationPriority::Medium) => Ordering::Equal,
                (RecommendationPriority::Medium, _) => Ordering::Less,
                (_, RecommendationPriority::Medium) => Ordering::Greater,
                (RecommendationPriority::Low, RecommendationPriority::Low) => Ordering::Equal,
            }
        });

        recommendations
    }

    fn find_solidity_files(&self, directory: &Path) -> Result<Vec<std::path::PathBuf>> {
        let mut solidity_files = Vec::new();
        
        if directory.is_dir() {
            for entry in walkdir::WalkDir::new(directory) {
                let entry = entry.context("Failed to read directory entry")?;
                if entry.file_type().is_file() {
                    if let Some(extension) = entry.path().extension() {
                        if extension == "sol" {
                            solidity_files.push(entry.path().to_path_buf());
                        }
                    }
                }
            }
        }

        Ok(solidity_files)
    }

    fn generate_batch_summary(&self, reports: &[ComprehensiveAnalysisReport]) -> BatchSummary {
        if reports.is_empty() {
            return BatchSummary {
                most_critical_contract: None,
                most_efficient_contract: None,
                highest_quality_contract: None,
                common_vulnerabilities: HashMap::new(),
                common_gas_issues: HashMap::new(),
                average_scores: AverageScores {
                    security: 0.0,
                    gas_efficiency: 0.0,
                    code_quality: 0.0,
                },
            };
        }

        // Find best contracts
        let most_critical_contract = reports
            .iter()
            .max_by(|a, b| a.summary.critical_issues_count.cmp(&b.summary.critical_issues_count))
            .map(|r| r.contract_name.clone());

        let most_efficient_contract = reports
            .iter()
            .max_by(|a, b| a.summary.overall_gas_efficiency.partial_cmp(&b.summary.overall_gas_efficiency).unwrap_or(std::cmp::Ordering::Equal))
            .map(|r| r.contract_name.clone());

        let highest_quality_contract = reports
            .iter()
            .max_by(|a, b| a.summary.overall_code_quality.partial_cmp(&b.summary.overall_code_quality).unwrap_or(std::cmp::Ordering::Equal))
            .map(|r| r.contract_name.clone());

        // Collect common issues
        let mut common_vulnerabilities = HashMap::new();
        let mut common_gas_issues = HashMap::new();

        for report in reports {
            if let Some(security) = &report.security_analysis {
                for vulnerability in &security.vulnerabilities {
                    *common_vulnerabilities.entry(vulnerability.title.clone()).or_insert(0) += 1;
                }
            }

            if let Some(gas) = &report.gas_analysis {
                for optimization in &gas.optimizations {
                    *common_gas_issues.entry(optimization.title.clone()).or_insert(0) += 1;
                }
            }
        }

        // Calculate averages
        let average_security = reports.iter().map(|r| r.summary.overall_security_score).sum::<f32>() / reports.len() as f32;
        let average_gas_efficiency = reports.iter().map(|r| r.summary.overall_gas_efficiency).sum::<f32>() / reports.len() as f32;
        let average_code_quality = reports.iter().map(|r| r.summary.overall_code_quality).sum::<f32>() / reports.len() as f32;

        BatchSummary {
            most_critical_contract,
            most_efficient_contract,
            highest_quality_contract,
            common_vulnerabilities,
            common_gas_issues,
            average_scores: AverageScores {
                security: average_security,
                gas_efficiency: average_gas_efficiency,
                code_quality: average_code_quality,
            },
        }
    }
}

#[derive(Debug)]
struct ContractParsingResult {
    contracts: Vec<EnhancedContract>,
    errors: Vec<ParsingError>,
    warnings: Vec<ParsingWarning>,
}

#[derive(Debug)]
enum AnalysisType {
    Security(SecurityAnalysis),
    Gas(GasAnalysisReport),
    CodeQuality(CodeQualityMetrics),
}

// Helper trait for severity level ordering
impl PartialOrd for crate::detector::enhanced_detector::VulnerabilitySeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        use crate::detector::enhanced_detector::VulnerabilitySeverity;
        use std::cmp::Ordering;

        let self_val = match self {
            VulnerabilitySeverity::Critical => 4,
            VulnerabilitySeverity::High => 3,
            VulnerabilitySeverity::Medium => 2,
            VulnerabilitySeverity::Low => 1,
        };

        let other_val = match other {
            VulnerabilitySeverity::Critical => 4,
            VulnerabilitySeverity::High => 3,
            VulnerabilitySeverity::Medium => 2,
            VulnerabilitySeverity::Low => 1,
        };

        Some(self_val.cmp(&other_val))
    }
}

impl Ord for crate::detector::enhanced_detector::VulnerabilitySeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}
