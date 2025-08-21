use std::fmt;
use std::error::Error as StdError;

/// Main error type for the smart contract analyzer
#[derive(Debug)]
pub enum SmartContractAnalyzerError {
    /// I/O related errors
    Io(std::io::Error),
    
    /// JSON parsing errors
    Json(serde_json::Error),
    
    /// TOML parsing errors
    Toml(toml::de::Error),
    
    /// Regex compilation errors
    Regex(regex::Error),
    
    /// HTTP request errors
    Http(reqwest::Error),
    
    /// Hex decoding errors
    Hex(hex::FromHexError),
    
    /// Parse errors for various data formats
    Parse(String),
    
    /// Contract compilation errors
    Compilation(String),
    
    /// Blockchain interaction errors
    Blockchain(String),
    
    /// Configuration errors
    Configuration(String),
    
    /// Analysis errors
    Analysis(String),
    
    /// Validation errors
    Validation(String),
    
    /// Generic errors with custom message
    Custom(String),
}

impl fmt::Display for SmartContractAnalyzerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmartContractAnalyzerError::Io(e) => write!(f, "I/O error: {}", e),
            SmartContractAnalyzerError::Json(e) => write!(f, "JSON error: {}", e),
            SmartContractAnalyzerError::Toml(e) => write!(f, "TOML error: {}", e),
            SmartContractAnalyzerError::Regex(e) => write!(f, "Regex error: {}", e),
            SmartContractAnalyzerError::Http(e) => write!(f, "HTTP error: {}", e),
            SmartContractAnalyzerError::Hex(e) => write!(f, "Hex decoding error: {}", e),
            SmartContractAnalyzerError::Parse(msg) => write!(f, "Parse error: {}", msg),
            SmartContractAnalyzerError::Compilation(msg) => write!(f, "Compilation error: {}", msg),
            SmartContractAnalyzerError::Blockchain(msg) => write!(f, "Blockchain error: {}", msg),
            SmartContractAnalyzerError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            SmartContractAnalyzerError::Analysis(msg) => write!(f, "Analysis error: {}", msg),
            SmartContractAnalyzerError::Validation(msg) => write!(f, "Validation error: {}", msg),
            SmartContractAnalyzerError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl StdError for SmartContractAnalyzerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            SmartContractAnalyzerError::Io(e) => Some(e),
            SmartContractAnalyzerError::Json(e) => Some(e),
            SmartContractAnalyzerError::Toml(e) => Some(e),
            SmartContractAnalyzerError::Regex(e) => Some(e),
            SmartContractAnalyzerError::Http(e) => Some(e),
            SmartContractAnalyzerError::Hex(e) => Some(e),
            _ => None,
        }
    }
}

// Automatic conversions from common error types
impl From<std::io::Error> for SmartContractAnalyzerError {
    fn from(error: std::io::Error) -> Self {
        SmartContractAnalyzerError::Io(error)
    }
}

impl From<serde_json::Error> for SmartContractAnalyzerError {
    fn from(error: serde_json::Error) -> Self {
        SmartContractAnalyzerError::Json(error)
    }
}

impl From<toml::de::Error> for SmartContractAnalyzerError {
    fn from(error: toml::de::Error) -> Self {
        SmartContractAnalyzerError::Toml(error)
    }
}

impl From<regex::Error> for SmartContractAnalyzerError {
    fn from(error: regex::Error) -> Self {
        SmartContractAnalyzerError::Regex(error)
    }
}

impl From<reqwest::Error> for SmartContractAnalyzerError {
    fn from(error: reqwest::Error) -> Self {
        SmartContractAnalyzerError::Http(error)
    }
}

impl From<hex::FromHexError> for SmartContractAnalyzerError {
    fn from(error: hex::FromHexError) -> Self {
        SmartContractAnalyzerError::Hex(error)
    }
}

impl From<String> for SmartContractAnalyzerError {
    fn from(error: String) -> Self {
        SmartContractAnalyzerError::Custom(error)
    }
}

impl From<toml::ser::Error> for SmartContractAnalyzerError {
    fn from(error: toml::ser::Error) -> Self {
        SmartContractAnalyzerError::Toml(toml::de::Error::custom(error.to_string()))
    }
}

impl From<std::num::ParseIntError> for SmartContractAnalyzerError {
    fn from(error: std::num::ParseIntError) -> Self {
        SmartContractAnalyzerError::Parse(format!("Integer parse error: {}", error))
    }
}

/// Result type alias for the smart contract analyzer
pub type Result<T> = std::result::Result<T, SmartContractAnalyzerError>;

/// Error categories for different types of analysis issues
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorCategory {
    /// Syntax errors in smart contracts
    Syntax,
    
    /// Logic errors that could cause unexpected behavior
    Logic,
    
    /// Security vulnerabilities
    Security,
    
    /// Performance issues
    Performance,
    
    /// Gas efficiency problems
    Gas,
    
    /// Best practice violations
    BestPractice,
    
    /// External dependency issues
    Dependency,
    
    /// Configuration problems
    Configuration,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::Syntax => write!(f, "Syntax"),
            ErrorCategory::Logic => write!(f, "Logic"),
            ErrorCategory::Security => write!(f, "Security"),
            ErrorCategory::Performance => write!(f, "Performance"),
            ErrorCategory::Gas => write!(f, "Gas"),
            ErrorCategory::BestPractice => write!(f, "Best Practice"),
            ErrorCategory::Dependency => write!(f, "Dependency"),
            ErrorCategory::Configuration => write!(f, "Configuration"),
        }
    }
}

/// Severity levels for errors and warnings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational messages
    Info,
    
    /// Low priority issues
    Low,
    
    /// Medium priority issues
    Medium,
    
    /// High priority issues
    High,
    
    /// Critical issues that must be addressed
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    /// Get numeric score for severity (higher = more severe)
    pub fn score(&self) -> u8 {
        match self {
            Severity::Info => 1,
            Severity::Low => 2,
            Severity::Medium => 3,
            Severity::High => 4,
            Severity::Critical => 5,
        }
    }
    
    /// Get color code for terminal output
    pub fn color(&self) -> &'static str {
        match self {
            Severity::Info => "\x1b[36m",      // Cyan
            Severity::Low => "\x1b[32m",       // Green
            Severity::Medium => "\x1b[33m",    // Yellow
            Severity::High => "\x1b[91m",      // Bright Red
            Severity::Critical => "\x1b[31m",  // Red
        }
    }
}

/// Detailed error information for analysis results
#[derive(Debug, Clone)]
pub struct AnalysisError {
    pub category: ErrorCategory,
    pub severity: Severity,
    pub message: String,
    pub location: Option<SourceLocation>,
    pub suggestion: Option<String>,
    pub rule_id: Option<String>,
}

/// Source code location information
#[derive(Debug, Clone, PartialEq)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub length: Option<u32>,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

impl AnalysisError {
    pub fn new(
        category: ErrorCategory,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            message: message.into(),
            location: None,
            suggestion: None,
            rule_id: None,
        }
    }
    
    pub fn with_location(mut self, location: SourceLocation) -> Self {
        self.location = Some(location);
        self
    }
    
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
    
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] [{}] {}", self.severity, self.category, self.message)?;
        
        if let Some(location) = &self.location {
            write!(f, " at {}", location)?;
        }
        
        if let Some(suggestion) = &self.suggestion {
            write!(f, "\n  Suggestion: {}", suggestion)?;
        }
        
        if let Some(rule_id) = &self.rule_id {
            write!(f, "\n  Rule: {}", rule_id)?;
        }
        
        Ok(())
    }
}

/// Helper functions for error handling
pub mod helpers {
    use super::*;

    /// Create a parse error
    pub fn parse_error(message: impl Into<String>) -> SmartContractAnalyzerError {
        SmartContractAnalyzerError::Parse(message.into())
    }

    /// Create a compilation error
    pub fn compilation_error(message: impl Into<String>) -> SmartContractAnalyzerError {
        SmartContractAnalyzerError::Compilation(message.into())
    }

    /// Create a blockchain error
    pub fn blockchain_error(message: impl Into<String>) -> SmartContractAnalyzerError {
        SmartContractAnalyzerError::Blockchain(message.into())
    }

    /// Create a configuration error
    pub fn configuration_error(message: impl Into<String>) -> SmartContractAnalyzerError {
        SmartContractAnalyzerError::Configuration(message.into())
    }

    /// Create an analysis error
    pub fn analysis_error(message: impl Into<String>) -> SmartContractAnalyzerError {
        SmartContractAnalyzerError::Analysis(message.into())
    }

    /// Create a validation error
    pub fn validation_error(message: impl Into<String>) -> SmartContractAnalyzerError {
        SmartContractAnalyzerError::Validation(message.into())
    }

    /// Wrap any error type in our custom error
    pub fn wrap_error<E: StdError + 'static>(
        error: E,
        context: impl Into<String>,
    ) -> SmartContractAnalyzerError {
        SmartContractAnalyzerError::Custom(format!("{}: {}", context.into(), error))
    }
}

/// Error collection for batch operations
#[derive(Debug, Default)]
pub struct ErrorCollector {
    pub errors: Vec<AnalysisError>,
}

impl ErrorCollector {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn add_error(&mut self, error: AnalysisError) {
        self.errors.push(error);
    }
    
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
    
    pub fn has_critical_errors(&self) -> bool {
        self.errors.iter().any(|e| e.severity == Severity::Critical)
    }
    
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
    
    pub fn critical_count(&self) -> usize {
        self.errors.iter().filter(|e| e.severity == Severity::Critical).count()
    }
    
    pub fn high_count(&self) -> usize {
        self.errors.iter().filter(|e| e.severity == Severity::High).count()
    }
    
    pub fn medium_count(&self) -> usize {
        self.errors.iter().filter(|e| e.severity == Severity::Medium).count()
    }
    
    pub fn low_count(&self) -> usize {
        self.errors.iter().filter(|e| e.severity == Severity::Low).count()
    }
    
    pub fn info_count(&self) -> usize {
        self.errors.iter().filter(|e| e.severity == Severity::Info).count()
    }
    
    /// Get errors sorted by severity (most severe first)
    pub fn sorted_by_severity(&self) -> Vec<&AnalysisError> {
        let mut errors: Vec<_> = self.errors.iter().collect();
        errors.sort_by(|a, b| b.severity.cmp(&a.severity));
        errors
    }
    
    /// Get errors filtered by category
    pub fn by_category(&self, category: &ErrorCategory) -> Vec<&AnalysisError> {
        self.errors.iter().filter(|e| &e.category == category).collect()
    }
    
    /// Get errors filtered by minimum severity
    pub fn by_min_severity(&self, min_severity: &Severity) -> Vec<&AnalysisError> {
        self.errors.iter().filter(|e| e.severity >= *min_severity).collect()
    }
    
    /// Clear all errors
    pub fn clear(&mut self) {
        self.errors.clear();
    }
}

impl fmt::Display for ErrorCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Analysis completed with {} issues:", self.error_count())?;
        writeln!(f, "  Critical: {}", self.critical_count())?;
        writeln!(f, "  High: {}", self.high_count())?;
        writeln!(f, "  Medium: {}", self.medium_count())?;
        writeln!(f, "  Low: {}", self.low_count())?;
        writeln!(f, "  Info: {}", self.info_count())?;
        
        if self.has_errors() {
            writeln!(f, "\nDetailed Issues:")?;
            for (i, error) in self.sorted_by_severity().iter().enumerate() {
                writeln!(f, "{}. {}", i + 1, error)?;
            }
        }
        
        Ok(())
    }
}
