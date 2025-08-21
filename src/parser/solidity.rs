use crate::types::{Contract, Function, Variable};
use regex::Regex;
use std::collections::HashMap;

pub struct SolidityParser {
    pragma_regex: Regex,
    contract_regex: Regex,
    function_regex: Regex,
    modifier_regex: Regex,
    event_regex: Regex,
}

impl Default for SolidityParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SolidityParser {
    pub fn new() -> Self {
        Self {
            pragma_regex: Regex::new(r"pragma\s+solidity\s+([^;]+);").unwrap(),
            contract_regex: Regex::new(r"contract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{").unwrap(),
            function_regex: Regex::new(
                r"function\s+(\w+)\s*\(([^)]*)\)\s*(public|private|internal|external)?\s*(view|pure|payable)?\s*(returns\s*\([^)]*\))?\s*\{"
            ).unwrap(),
            modifier_regex: Regex::new(r"modifier\s+(\w+)\s*\(([^)]*)\)\s*\{").unwrap(),
            event_regex: Regex::new(r"event\s+(\w+)\s*\(([^)]*)\)\s*;").unwrap(),
        }
    }

    pub fn parse_contract(&self, source_code: &str) -> crate::Result<Contract> {
        let pragma_version = self.extract_pragma_version(source_code)?;
        let (contract_name, inheritance) = self.extract_contract_info(source_code)?;
        let functions = self.extract_functions(source_code)?;
        let state_variables = self.extract_state_variables(source_code)?;
        let events = self.extract_events(source_code)?;

        Ok(Contract {
            name: contract_name,
            source_code: source_code.to_string(),
            pragma_version,
            inheritance,
            functions,
            state_variables,
            events,
            bytecode: None,
            abi: None,
        })
    }

    fn extract_pragma_version(&self, source_code: &str) -> crate::Result<String> {
        if let Some(captures) = self.pragma_regex.captures(source_code) {
            Ok(captures[1].to_string())
        } else {
            Ok("unknown".to_string())
        }
    }

    fn extract_contract_info(&self, source_code: &str) -> crate::Result<(String, Vec<String>)> {
        if let Some(captures) = self.contract_regex.captures(source_code) {
            let name = captures[1].to_string();
            let inheritance = if let Some(inheritance_str) = captures.get(2) {
                inheritance_str
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
            } else {
                Vec::new()
            };
            Ok((name, inheritance))
        } else {
            Err("Could not find contract declaration".into())
        }
    }

    fn extract_functions(&self, source_code: &str) -> crate::Result<Vec<Function>> {
        let mut functions = Vec::new();
        
        for captures in self.function_regex.captures_iter(source_code) {
            let name = captures[1].to_string();
            let parameters = captures.get(2).map_or(String::new(), |m| m.as_str().to_string());
            let visibility = captures.get(3).map_or("public".to_string(), |m| m.as_str().to_string());
            let state_mutability = captures.get(4).map_or(String::new(), |m| m.as_str().to_string());
            let returns = captures.get(5).map_or(String::new(), |m| m.as_str().to_string());

            functions.push(Function {
                name,
                parameters,
                visibility,
                state_mutability,
                returns,
                modifiers: Vec::new(),
                body: String::new(), // Would need more complex parsing for function body
            });
        }

        Ok(functions)
    }

    fn extract_state_variables(&self, source_code: &str) -> crate::Result<Vec<Variable>> {
        // Simplified state variable extraction
        let var_regex = Regex::new(r"(\w+)(?:\s+(?:public|private|internal))?\s+(\w+)(?:\s*=\s*[^;]+)?\s*;")?;
        let mut variables = Vec::new();

        for captures in var_regex.captures_iter(source_code) {
            variables.push(Variable {
                name: captures[2].to_string(),
                var_type: captures[1].to_string(),
                visibility: "internal".to_string(), // Default
                is_constant: false,
                is_immutable: false,
            });
        }

        Ok(variables)
    }

    fn extract_events(&self, source_code: &str) -> crate::Result<Vec<String>> {
        let mut events = Vec::new();
        
        for captures in self.event_regex.captures_iter(source_code) {
            events.push(captures[1].to_string());
        }

        Ok(events)
    }

    pub fn analyze_imports(&self, source_code: &str) -> Vec<String> {
        let import_regex = Regex::new(r#"import\s+(?:"([^"]+)"|'([^']+)')"#).unwrap();
        import_regex
            .captures_iter(source_code)
            .map(|cap| {
                cap.get(1)
                    .or_else(|| cap.get(2))
                    .map_or(String::new(), |m| m.as_str().to_string())
            })
            .collect()
    }

    pub fn extract_custom_errors(&self, source_code: &str) -> Vec<String> {
        let error_regex = Regex::new(r"error\s+(\w+)\s*\(([^)]*)\)\s*;").unwrap();
        error_regex
            .captures_iter(source_code)
            .map(|cap| cap[1].to_string())
            .collect()
    }
}
