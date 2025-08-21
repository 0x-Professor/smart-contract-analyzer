use crate::types::{Contract, Function, Variable};
use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;

/// Advanced Solidity parser with AST-like capabilities
pub struct EnhancedSolidityParser {
    // Compiled regex patterns for performance
    pragma_regex: Regex,
    contract_regex: Regex,
    function_regex: Regex,
    modifier_regex: Regex,
    event_regex: Regex,
    import_regex: Regex,
    state_var_regex: Regex,
    mapping_regex: Regex,
    struct_regex: Regex,
    enum_regex: Regex,
    constructor_regex: Regex,
    fallback_regex: Regex,
    receive_regex: Regex,
}

/// Represents a parsing context for better error handling and recovery
#[derive(Debug, Clone)]
pub struct ParseContext {
    pub current_line: usize,
    pub current_column: usize,
    pub current_contract: Option<String>,
    pub current_function: Option<String>,
    pub scope_depth: usize,
}

/// Enhanced function information with more metadata
#[derive(Debug, Clone)]
pub struct EnhancedFunction {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub return_types: Vec<String>,
    pub visibility: Visibility,
    pub state_mutability: StateMutability,
    pub modifiers: Vec<String>,
    pub body: String,
    pub line_start: usize,
    pub line_end: usize,
    pub is_constructor: bool,
    pub is_fallback: bool,
    pub is_receive: bool,
    pub has_overrides: bool,
    pub complexity: u32,
    pub gas_estimate: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub param_type: String,
    pub storage_location: Option<String>,
    pub is_indexed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    Public,
    Private,
    Internal,
    External,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateMutability {
    Pure,
    View,
    Payable,
    NonPayable,
}

/// Enhanced contract with more detailed information
#[derive(Debug, Clone)]
pub struct EnhancedContract {
    pub name: String,
    pub source_code: String,
    pub pragma_version: String,
    pub inheritance: Vec<String>,
    pub functions: Vec<EnhancedFunction>,
    pub state_variables: Vec<EnhancedVariable>,
    pub events: Vec<Event>,
    pub modifiers: Vec<ModifierDefinition>,
    pub structs: Vec<StructDefinition>,
    pub enums: Vec<EnumDefinition>,
    pub imports: Vec<Import>,
    pub using_for: Vec<UsingFor>,
    pub bytecode: Option<String>,
    pub abi: Option<String>,
    pub is_abstract: bool,
    pub is_interface: bool,
    pub is_library: bool,
    pub license: Option<String>,
    pub complexity_score: u32,
    pub line_count: usize,
}

#[derive(Debug, Clone)]
pub struct EnhancedVariable {
    pub name: String,
    pub var_type: String,
    pub visibility: Visibility,
    pub is_constant: bool,
    pub is_immutable: bool,
    pub initial_value: Option<String>,
    pub line_number: usize,
    pub storage_location: Option<String>,
    pub is_mapping: bool,
    pub mapping_key_type: Option<String>,
    pub mapping_value_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub is_anonymous: bool,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub struct ModifierDefinition {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub body: String,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub struct StructDefinition {
    pub name: String,
    pub fields: Vec<Parameter>,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub struct EnumDefinition {
    pub name: String,
    pub values: Vec<String>,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub path: String,
    pub symbols: Vec<String>,
    pub alias: Option<String>,
    pub is_wildcard: bool,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub struct UsingFor {
    pub library: String,
    pub target_type: String,
    pub line_number: usize,
}

static PARSER_INSTANCE: OnceLock<EnhancedSolidityParser> = OnceLock::new();

impl EnhancedSolidityParser {
    pub fn instance() -> &'static EnhancedSolidityParser {
        PARSER_INSTANCE.get_or_init(|| Self::new().expect("Failed to initialize parser"))
    }

    pub fn new() -> Result<Self> {
        Ok(Self {
            pragma_regex: Regex::new(r"pragma\s+solidity\s+([^;]+);")?,
            contract_regex: Regex::new(r"(?:abstract\s+)?(?:contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{")?,
            function_regex: Regex::new(
                r"function\s+(\w+)\s*\(([^)]*)\)\s*(?:(public|private|internal|external)\s*)?(?:(view|pure|payable)\s*)?(?:override\s*)?(?:returns\s*\(([^)]*)\))?\s*(?:\{|;)"
            )?,
            modifier_regex: Regex::new(r"modifier\s+(\w+)\s*\(([^)]*)\)\s*(?:\{|;)")?,
            event_regex: Regex::new(r"event\s+(\w+)\s*\(([^)]*)\)\s*(?:anonymous\s*)?;")?,
            import_regex: Regex::new(r#"import\s+(?:"([^"]+)"|'([^']+)'|(\{[^}]+\})\s+from\s+(?:"([^"]+)"|'([^']+)')|\*\s+as\s+(\w+)\s+from\s+(?:"([^"]+)"|'([^']+)'))"#)?,
            state_var_regex: Regex::new(r"(?:^|\n)\s*(?:(mapping\s*\([^)]+\)\s*(?:\s*=>\s*[^;]+)?)|(\w+(?:\[\])?))\s+(public|private|internal|constant|immutable)?\s*(\w+)(?:\s*=\s*([^;]+))?\s*;")?,
            mapping_regex: Regex::new(r"mapping\s*\(\s*(\w+)\s*=>\s*(.*?)\s*\)")?,
            struct_regex: Regex::new(r"struct\s+(\w+)\s*\{([^}]*)\}")?,
            enum_regex: Regex::new(r"enum\s+(\w+)\s*\{([^}]*)\}")?,
            constructor_regex: Regex::new(r"constructor\s*\(([^)]*)\)\s*(?:(public|internal)\s*)?(?:(payable)\s*)?(?:\{|;)")?,
            fallback_regex: Regex::new(r"fallback\s*\(\s*\)\s*(?:(external)\s*)?(?:(payable)\s*)?(?:\{|;)")?,
            receive_regex: Regex::new(r"receive\s*\(\s*\)\s*(?:(external)\s*)?(?:(payable)\s*)?(?:\{|;)")?,
        })
    }

    /// Parse a complete Solidity contract with enhanced error handling
    pub fn parse_contract(&self, source_code: &str) -> Result<EnhancedContract> {
        let mut context = ParseContext {
            current_line: 1,
            current_column: 1,
            current_contract: None,
            current_function: None,
            scope_depth: 0,
        };

        // Pre-process the source code
        let cleaned_source = self.preprocess_source(source_code)?;
        let lines: Vec<&str> = cleaned_source.lines().collect();

        // Extract basic information
        let pragma_version = self.extract_pragma_version(&cleaned_source)?;
        let license = self.extract_license(&cleaned_source);
        let imports = self.extract_imports(&cleaned_source)?;
        let (contract_name, inheritance, contract_type) = self.extract_contract_info(&cleaned_source)?;
        
        context.current_contract = Some(contract_name.clone());

        // Extract complex structures
        let structs = self.extract_structs(&cleaned_source)?;
        let enums = self.extract_enums(&cleaned_source)?;
        let events = self.extract_events(&cleaned_source)?;
        let modifiers = self.extract_modifiers(&cleaned_source)?;
        let using_for = self.extract_using_for(&cleaned_source)?;
        
        // Extract functions with enhanced analysis
        let functions = self.extract_enhanced_functions(&cleaned_source, &mut context)?;
        
        // Extract state variables with detailed information
        let state_variables = self.extract_enhanced_state_variables(&cleaned_source)?;

        // Calculate complexity metrics
        let complexity_score = self.calculate_complexity(&functions, &state_variables);

        Ok(EnhancedContract {
            name: contract_name,
            source_code: source_code.to_string(),
            pragma_version,
            inheritance,
            functions,
            state_variables,
            events,
            modifiers,
            structs,
            enums,
            imports,
            using_for,
            bytecode: None,
            abi: None,
            is_abstract: contract_type.0,
            is_interface: contract_type.1,
            is_library: contract_type.2,
            license,
            complexity_score,
            line_count: lines.len(),
        })
    }

    /// Preprocess source code to handle comments and formatting
    fn preprocess_source(&self, source_code: &str) -> Result<String> {
        let mut processed = source_code.to_string();
        
        // Remove single-line comments but preserve line structure
        let single_comment_regex = Regex::new(r"//.*$")?;
        processed = single_comment_regex.replace_all(&processed, "").to_string();
        
        // Remove multi-line comments but preserve line structure
        let multi_comment_regex = Regex::new(r"(?s)/\*.*?\*/")?;
        processed = multi_comment_regex.replace_all(&processed, |caps: &regex::Captures| {
            // Replace comment content with spaces to maintain line numbers
            caps.get(0).unwrap().as_str().chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect::<String>()
        }).to_string();

        Ok(processed)
    }

    fn extract_pragma_version(&self, source_code: &str) -> Result<String> {
        if let Some(captures) = self.pragma_regex.captures(source_code) {
            Ok(captures[1].trim().to_string())
        } else {
            Ok("unknown".to_string())
        }
    }

    fn extract_license(&self, source_code: &str) -> Option<String> {
        let license_regex = Regex::new(r"(?i)(?:SPDX-License-Identifier|License):\s*([^\n\r]+)").ok()?;
        license_regex.captures(source_code)
            .map(|cap| cap[1].trim().to_string())
    }

    fn extract_contract_info(&self, source_code: &str) -> Result<(String, Vec<String>, (bool, bool, bool))> {
        if let Some(captures) = self.contract_regex.captures(source_code) {
            let name = captures[1].to_string();
            let inheritance = if let Some(inheritance_str) = captures.get(2) {
                inheritance_str
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            } else {
                Vec::new()
            };

            // Determine contract type
            let full_match = captures.get(0).unwrap().as_str();
            let is_abstract = full_match.contains("abstract");
            let is_interface = full_match.contains("interface");
            let is_library = full_match.contains("library");

            Ok((name, inheritance, (is_abstract, is_interface, is_library)))
        } else {
            Err(anyhow!("Could not find contract declaration"))
        }
    }

    fn extract_imports(&self, source_code: &str) -> Result<Vec<Import>> {
        let mut imports = Vec::new();
        let lines_with_numbers: Vec<(usize, &str)> = source_code.lines().enumerate().collect();

        for (line_num, line) in &lines_with_numbers {
            if let Some(captures) = self.import_regex.captures(line) {
                let path = captures.get(1)
                    .or_else(|| captures.get(2))
                    .or_else(|| captures.get(4))
                    .or_else(|| captures.get(5))
                    .or_else(|| captures.get(7))
                    .or_else(|| captures.get(8))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                let symbols = if let Some(symbols_match) = captures.get(3) {
                    // Parse symbols from {symbol1, symbol2, ...}
                    let symbols_str = symbols_match.as_str();
                    symbols_str
                        .trim_matches(|c| c == '{' || c == '}')
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else {
                    Vec::new()
                };

                let alias = captures.get(6).map(|m| m.as_str().to_string());
                let is_wildcard = captures.get(6).is_some(); // * as alias

                imports.push(Import {
                    path,
                    symbols,
                    alias,
                    is_wildcard,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(imports)
    }

    fn extract_enhanced_functions(&self, source_code: &str, context: &mut ParseContext) -> Result<Vec<EnhancedFunction>> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();

        // Find all function declarations
        for (line_idx, line) in lines.iter().enumerate() {
            if let Some(captures) = self.function_regex.captures(line) {
                let name = captures[1].to_string();
                
                // Parse parameters
                let params_str = captures.get(2).map_or("", |m| m.as_str());
                let parameters = self.parse_parameters(params_str)?;

                // Parse visibility
                let visibility = captures.get(3)
                    .map(|m| match m.as_str() {
                        "public" => Visibility::Public,
                        "private" => Visibility::Private,
                        "internal" => Visibility::Internal,
                        "external" => Visibility::External,
                        _ => Visibility::Public,
                    })
                    .unwrap_or(Visibility::Public);

                // Parse state mutability
                let state_mutability = captures.get(4)
                    .map(|m| match m.as_str() {
                        "pure" => StateMutability::Pure,
                        "view" => StateMutability::View,
                        "payable" => StateMutability::Payable,
                        _ => StateMutability::NonPayable,
                    })
                    .unwrap_or(StateMutability::NonPayable);

                // Parse return types
                let return_types = if let Some(returns_str) = captures.get(5) {
                    self.parse_return_types(returns_str.as_str())?
                } else {
                    Vec::new()
                };

                // Extract function body and calculate metrics
                let (body, line_start, line_end) = self.extract_function_body_with_lines(source_code, &name, line_idx)?;
                let modifiers = self.extract_function_modifiers(source_code, &name);
                let complexity = self.calculate_function_complexity(&body);
                let gas_estimate = self.estimate_gas_cost(&body);

                functions.push(EnhancedFunction {
                    name,
                    parameters,
                    return_types,
                    visibility,
                    state_mutability,
                    modifiers,
                    body,
                    line_start: line_start + 1,
                    line_end: line_end + 1,
                    is_constructor: false,
                    is_fallback: false,
                    is_receive: false,
                    has_overrides: captures.get(0).unwrap().as_str().contains("override"),
                    complexity,
                    gas_estimate,
                });
            }
        }

        // Also check for constructors, fallback, and receive functions
        functions.extend(self.extract_special_functions(source_code)?);

        Ok(functions)
    }

    fn parse_parameters(&self, params_str: &str) -> Result<Vec<Parameter>> {
        if params_str.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut parameters = Vec::new();
        let parts: Vec<&str> = params_str.split(',').collect();

        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let tokens: Vec<&str> = part.split_whitespace().collect();
            if tokens.len() >= 2 {
                let param_type = tokens[0].to_string();
                let storage_location = if tokens.len() > 2 && 
                    ["memory", "storage", "calldata"].contains(&tokens[1]) {
                    Some(tokens[1].to_string())
                } else {
                    None
                };

                let name_idx = if storage_location.is_some() { 2 } else { 1 };
                let name = if tokens.len() > name_idx {
                    tokens[name_idx].to_string()
                } else {
                    format!("param_{}", parameters.len())
                };

                parameters.push(Parameter {
                    name,
                    param_type,
                    storage_location,
                    is_indexed: part.contains("indexed"),
                });
            }
        }

        Ok(parameters)
    }

    fn parse_return_types(&self, returns_str: &str) -> Result<Vec<String>> {
        let cleaned = returns_str.trim_matches('(').trim_matches(')');
        Ok(cleaned.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    fn extract_function_body_with_lines(&self, source_code: &str, function_name: &str, start_line: usize) -> Result<(String, usize, usize)> {
        let lines: Vec<&str> = source_code.lines().collect();
        
        // Find the opening brace
        let mut brace_line = start_line;
        let mut found_brace = false;
        
        for i in start_line..lines.len() {
            if lines[i].contains('{') {
                brace_line = i;
                found_brace = true;
                break;
            }
            if lines[i].contains(';') {
                // Function declaration without body (interface or abstract)
                return Ok(("".to_string(), start_line, i));
            }
        }
        
        if !found_brace {
            return Ok(("".to_string(), start_line, start_line));
        }

        // Extract the body using brace matching
        let mut brace_count = 0;
        let mut body_lines = Vec::new();
        let mut current_line = brace_line;

        for i in brace_line..lines.len() {
            let line = lines[i];
            body_lines.push(line);

            for ch in line.chars() {
                match ch {
                    '{' => brace_count += 1,
                    '}' => {
                        brace_count -= 1;
                        if brace_count == 0 {
                            current_line = i;
                            let body = body_lines.join("\n");
                            return Ok((body, brace_line, current_line));
                        }
                    }
                    _ => {}
                }
            }
        }

        // If we reach here, braces weren't balanced
        let body = body_lines.join("\n");
        Ok((body, brace_line, lines.len() - 1))
    }

    fn extract_function_modifiers(&self, source_code: &str, function_name: &str) -> Vec<String> {
        let function_line_regex = Regex::new(&format!(
            r"function\s+{}\s*\([^)]*\)\s*([^{{]*)\{{", 
            regex::escape(function_name)
        )).unwrap();
        
        if let Some(captures) = function_line_regex.captures(source_code) {
            let modifiers_str = captures[1].to_string();
            let modifier_regex = Regex::new(r"\b(\w+)\b").unwrap();
            let reserved_words = [
                "public", "private", "internal", "external", 
                "view", "pure", "payable", "returns", "override", "virtual"
            ];
            
            modifier_regex
                .captures_iter(&modifiers_str)
                .map(|cap| cap[1].to_string())
                .filter(|word| !reserved_words.contains(&word.as_str()))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn extract_special_functions(&self, source_code: &str) -> Result<Vec<EnhancedFunction>> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = source_code.lines().enumerate().collect();

        // Constructor functions
        for (line_num, line) in &lines {
            if let Some(captures) = self.constructor_regex.captures(line) {
                let params_str = captures.get(1).map_or("", |m| m.as_str());
                let parameters = self.parse_parameters(params_str)?;
                
                let visibility = captures.get(2)
                    .map(|m| match m.as_str() {
                        "public" => Visibility::Public,
                        "internal" => Visibility::Internal,
                        _ => Visibility::Public,
                    })
                    .unwrap_or(Visibility::Public);

                let state_mutability = if captures.get(3).is_some() {
                    StateMutability::Payable
                } else {
                    StateMutability::NonPayable
                };

                let (body, line_start, line_end) = self.extract_function_body_with_lines(source_code, "constructor", *line_num)?;

                functions.push(EnhancedFunction {
                    name: "constructor".to_string(),
                    parameters,
                    return_types: Vec::new(),
                    visibility,
                    state_mutability,
                    modifiers: Vec::new(),
                    body,
                    line_start: line_start + 1,
                    line_end: line_end + 1,
                    is_constructor: true,
                    is_fallback: false,
                    is_receive: false,
                    has_overrides: false,
                    complexity: self.calculate_function_complexity(&body),
                    gas_estimate: self.estimate_gas_cost(&body),
                });
            }
        }

        // Fallback functions
        for (line_num, line) in &lines {
            if let Some(captures) = self.fallback_regex.captures(line) {
                let state_mutability = if captures.get(2).is_some() {
                    StateMutability::Payable
                } else {
                    StateMutability::NonPayable
                };

                let (body, line_start, line_end) = self.extract_function_body_with_lines(source_code, "fallback", *line_num)?;

                functions.push(EnhancedFunction {
                    name: "fallback".to_string(),
                    parameters: Vec::new(),
                    return_types: Vec::new(),
                    visibility: Visibility::External,
                    state_mutability,
                    modifiers: Vec::new(),
                    body,
                    line_start: line_start + 1,
                    line_end: line_end + 1,
                    is_constructor: false,
                    is_fallback: true,
                    is_receive: false,
                    has_overrides: false,
                    complexity: self.calculate_function_complexity(&body),
                    gas_estimate: self.estimate_gas_cost(&body),
                });
            }
        }

        // Receive functions
        for (line_num, line) in &lines {
            if let Some(_captures) = self.receive_regex.captures(line) {
                let (body, line_start, line_end) = self.extract_function_body_with_lines(source_code, "receive", *line_num)?;

                functions.push(EnhancedFunction {
                    name: "receive".to_string(),
                    parameters: Vec::new(),
                    return_types: Vec::new(),
                    visibility: Visibility::External,
                    state_mutability: StateMutability::Payable,
                    modifiers: Vec::new(),
                    body,
                    line_start: line_start + 1,
                    line_end: line_end + 1,
                    is_constructor: false,
                    is_fallback: false,
                    is_receive: true,
                    has_overrides: false,
                    complexity: self.calculate_function_complexity(&body),
                    gas_estimate: self.estimate_gas_cost(&body),
                });
            }
        }

        Ok(functions)
    }

    fn calculate_function_complexity(&self, body: &str) -> u32 {
        let mut complexity = 1; // Base complexity

        // Count decision points
        complexity += body.matches("if").count() as u32;
        complexity += body.matches("else").count() as u32;
        complexity += body.matches("while").count() as u32;
        complexity += body.matches("for").count() as u32;
        complexity += body.matches("switch").count() as u32;
        complexity += body.matches("case").count() as u32;
        complexity += body.matches("&&").count() as u32;
        complexity += body.matches("||").count() as u32;
        complexity += body.matches("?").count() as u32; // Ternary operator

        complexity
    }

    fn estimate_gas_cost(&self, body: &str) -> Option<u64> {
        let mut gas = 0u64;

        // Basic gas cost estimation
        gas += body.matches("sstore").count() as u64 * 20000; // Storage write
        gas += body.matches("sload").count() as u64 * 800;    // Storage read
        gas += body.matches(".call").count() as u64 * 2600;   // External call
        gas += body.matches("create").count() as u64 * 32000; // Contract creation
        gas += body.matches("selfdestruct").count() as u64 * 5000;
        
        // Arithmetic operations (rough estimate)
        gas += (body.matches("+").count() + 
                body.matches("-").count() + 
                body.matches("*").count() + 
                body.matches("/").count()) as u64 * 3;

        if gas > 0 { Some(gas) } else { None }
    }

    fn extract_enhanced_state_variables(&self, source_code: &str) -> Result<Vec<EnhancedVariable>> {
        let mut variables = Vec::new();
        let lines: Vec<&str> = source_code.lines().enumerate().collect();

        for (line_num, line) in &lines_with_numbers {
            // Skip comments and empty lines
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Check for mapping declarations
            if let Some(mapping_caps) = self.mapping_regex.captures(line) {
                let key_type = mapping_caps[1].to_string();
                let value_type = mapping_caps[2].to_string();

                // Extract variable name and other properties
                if let Some(var_caps) = self.state_var_regex.captures(line) {
                    let var_name = var_caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let visibility_str = var_caps.get(3).map(|m| m.as_str()).unwrap_or("internal");
                    
                    let visibility = match visibility_str {
                        "public" => Visibility::Public,
                        "private" => Visibility::Private,
                        "internal" => Visibility::Internal,
                        _ => Visibility::Internal,
                    };

                    variables.push(EnhancedVariable {
                        name: var_name,
                        var_type: mapping_caps.get(0).unwrap().as_str().to_string(),
                        visibility,
                        is_constant: line.contains("constant"),
                        is_immutable: line.contains("immutable"),
                        initial_value: var_caps.get(5).map(|m| m.as_str().to_string()),
                        line_number: line_num + 1,
                        storage_location: None,
                        is_mapping: true,
                        mapping_key_type: Some(key_type),
                        mapping_value_type: Some(value_type),
                    });
                }
            }
            // Regular state variables
            else if let Some(var_caps) = self.state_var_regex.captures(line) {
                let var_type = var_caps.get(1).or_else(|| var_caps.get(2))
                    .map(|m| m.as_str().to_string()).unwrap_or_default();
                let var_name = var_caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default();
                let visibility_str = var_caps.get(3).map(|m| m.as_str()).unwrap_or("internal");

                if !var_name.is_empty() && !var_type.is_empty() {
                    let visibility = match visibility_str {
                        "public" => Visibility::Public,
                        "private" => Visibility::Private,
                        "internal" => Visibility::Internal,
                        _ => Visibility::Internal,
                    };

                    variables.push(EnhancedVariable {
                        name: var_name,
                        var_type,
                        visibility,
                        is_constant: line.contains("constant"),
                        is_immutable: line.contains("immutable"),
                        initial_value: var_caps.get(5).map(|m| m.as_str().to_string()),
                        line_number: line_num + 1,
                        storage_location: None,
                        is_mapping: false,
                        mapping_key_type: None,
                        mapping_value_type: None,
                    });
                }
            }
        }

        Ok(variables)
    }

    fn extract_events(&self, source_code: &str) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let lines: Vec<&str> = source_code.lines().enumerate().collect();

        for (line_num, line) in &lines_with_numbers {
            if let Some(captures) = self.event_regex.captures(line) {
                let name = captures[1].to_string();
                let params_str = captures.get(2).map_or("", |m| m.as_str());
                let parameters = self.parse_parameters(params_str)?;
                let is_anonymous = line.contains("anonymous");

                events.push(Event {
                    name,
                    parameters,
                    is_anonymous,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(events)
    }

    fn extract_modifiers(&self, source_code: &str) -> Result<Vec<ModifierDefinition>> {
        let mut modifiers = Vec::new();
        let lines: Vec<&str> = source_code.lines().enumerate().collect();

        for (line_num, line) in &lines_with_numbers {
            if let Some(captures) = self.modifier_regex.captures(line) {
                let name = captures[1].to_string();
                let params_str = captures.get(2).map_or("", |m| m.as_str());
                let parameters = self.parse_parameters(params_str)?;
                
                let (body, _, _) = self.extract_function_body_with_lines(source_code, &name, line_num)?;

                modifiers.push(ModifierDefinition {
                    name,
                    parameters,
                    body,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(modifiers)
    }

    fn extract_structs(&self, source_code: &str) -> Result<Vec<StructDefinition>> {
        let mut structs = Vec::new();
        let lines: Vec<&str> = source_code.lines().enumerate().collect();

        for (line_num, _) in lines {
            if let Some(captures) = self.struct_regex.captures(source_code) {
                let name = captures[1].to_string();
                let fields_str = captures[2].to_string();
                
                let mut fields = Vec::new();
                for field_line in fields_str.lines() {
                    let field_line = field_line.trim();
                    if field_line.ends_with(';') {
                        let parts: Vec<&str> = field_line.trim_end_matches(';').split_whitespace().collect();
                        if parts.len() >= 2 {
                            fields.push(Parameter {
                                param_type: parts[0].to_string(),
                                name: parts[1].to_string(),
                                storage_location: None,
                                is_indexed: false,
                            });
                        }
                    }
                }

                structs.push(StructDefinition {
                    name,
                    fields,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(structs)
    }

    fn extract_enums(&self, source_code: &str) -> Result<Vec<EnumDefinition>> {
        let mut enums = Vec::new();
        let lines: Vec<&str> = source_code.lines().enumerate().collect();

        for (line_num, _) in lines {
            if let Some(captures) = self.enum_regex.captures(source_code) {
                let name = captures[1].to_string();
                let values_str = captures[2].to_string();
                
                let values: Vec<String> = values_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                enums.push(EnumDefinition {
                    name,
                    values,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(enums)
    }

    fn extract_using_for(&self, source_code: &str) -> Result<Vec<UsingFor>> {
        let mut using_for = Vec::new();
        let using_regex = Regex::new(r"using\s+(\w+)\s+for\s+(\w+)\s*;")?;
        let lines: Vec<&str> = source_code.lines().enumerate().collect();

        for (line_num, line) in &lines_with_numbers {
            if let Some(captures) = using_regex.captures(line) {
                using_for.push(UsingFor {
                    library: captures[1].to_string(),
                    target_type: captures[2].to_string(),
                    line_number: line_num + 1,
                });
            }
        }

        Ok(using_for)
    }

    fn calculate_complexity(&self, functions: &[EnhancedFunction], state_variables: &[EnhancedVariable]) -> u32 {
        let function_complexity: u32 = functions.iter().map(|f| f.complexity).sum();
        let variable_complexity = state_variables.len() as u32;
        
        function_complexity + variable_complexity
    }

    /// Convert enhanced contract back to basic contract for compatibility
    pub fn to_basic_contract(&self, enhanced: &EnhancedContract) -> Contract {
        Contract {
            name: enhanced.name.clone(),
            source_code: enhanced.source_code.clone(),
            pragma_version: enhanced.pragma_version.clone(),
            inheritance: enhanced.inheritance.clone(),
            functions: enhanced.functions.iter().map(|f| Function {
                name: f.name.clone(),
                parameters: f.parameters.iter()
                    .map(|p| format!("{} {}", p.param_type, p.name))
                    .collect::<Vec<_>>()
                    .join(", "),
                visibility: match f.visibility {
                    Visibility::Public => "public",
                    Visibility::Private => "private",
                    Visibility::Internal => "internal",
                    Visibility::External => "external",
                }.to_string(),
                state_mutability: match f.state_mutability {
                    StateMutability::Pure => "pure",
                    StateMutability::View => "view",
                    StateMutability::Payable => "payable",
                    StateMutability::NonPayable => "",
                }.to_string(),
                returns: f.return_types.join(", "),
                modifiers: f.modifiers.clone(),
                body: f.body.clone(),
            }).collect(),
            state_variables: enhanced.state_variables.iter().map(|v| Variable {
                name: v.name.clone(),
                var_type: v.var_type.clone(),
                visibility: match v.visibility {
                    Visibility::Public => "public",
                    Visibility::Private => "private",
                    Visibility::Internal => "internal",
                    Visibility::External => "external",
                }.to_string(),
                is_constant: v.is_constant,
                is_immutable: v.is_immutable,
            }).collect(),
            events: enhanced.events.iter().map(|e| e.name.clone()).collect(),
            bytecode: enhanced.bytecode.clone(),
            abi: enhanced.abi.clone(),
        }
    }
}

impl Default for EnhancedSolidityParser {
    fn default() -> Self {
        Self::new().expect("Failed to create default parser")
    }
}
