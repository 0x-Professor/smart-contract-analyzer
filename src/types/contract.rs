use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub name: String,
    pub source_code: String,
    pub pragma_version: String,
    pub inheritance: Vec<String>,
    pub functions: Vec<Function>,
    pub state_variables: Vec<Variable>,
    pub events: Vec<String>,
    pub bytecode: Option<String>,
    pub abi: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub parameters: String,
    pub visibility: String,
    pub state_mutability: String,
    pub returns: String,
    pub modifiers: Vec<String>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub var_type: String,
    pub visibility: String,
    pub is_constant: bool,
    pub is_immutable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub compiler_version: String,
    pub optimization_enabled: bool,
    pub optimization_runs: u32,
    pub creation_timestamp: String,
    pub creator_address: Option<String>,
    pub deployment_transaction: Option<String>,
}

impl Contract {
    pub fn new(name: String, source_code: String) -> Self {
        Self {
            name,
            source_code,
            pragma_version: "unknown".to_string(),
            inheritance: Vec::new(),
            functions: Vec::new(),
            state_variables: Vec::new(),
            events: Vec::new(),
            bytecode: None,
            abi: None,
        }
    }

    pub fn with_bytecode(mut self, bytecode: String) -> Self {
        self.bytecode = Some(bytecode);
        self
    }

    pub fn with_abi(mut self, abi: String) -> Self {
        self.abi = Some(abi);
        self
    }

    pub fn get_public_functions(&self) -> Vec<&Function> {
        self.functions
            .iter()
            .filter(|f| f.visibility == "public")
            .collect()
    }

    pub fn get_external_functions(&self) -> Vec<&Function> {
        self.functions
            .iter()
            .filter(|f| f.visibility == "external")
            .collect()
    }

    pub fn get_payable_functions(&self) -> Vec<&Function> {
        self.functions
            .iter()
            .filter(|f| f.state_mutability == "payable")
            .collect()
    }

    pub fn has_fallback_function(&self) -> bool {
        self.functions.iter().any(|f| f.name == "fallback")
    }

    pub fn has_receive_function(&self) -> bool {
        self.functions.iter().any(|f| f.name == "receive")
    }

    pub fn get_constructor(&self) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == "constructor")
    }

    pub fn count_lines_of_code(&self) -> usize {
        self.source_code.lines().count()
    }

    pub fn has_inheritance(&self) -> bool {
        !self.inheritance.is_empty()
    }

    pub fn get_function_by_name(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == name)
    }

    pub fn get_variable_by_name(&self, name: &str) -> Option<&Variable> {
        self.state_variables.iter().find(|v| v.name == name)
    }
}

impl Default for Contract {
    fn default() -> Self {
        Self::new("Unknown".to_string(), String::new())
    }
}

impl Function {
    pub fn new(name: String, visibility: String) -> Self {
        Self {
            name,
            visibility,
            parameters: String::new(),
            state_mutability: "nonpayable".to_string(),
            returns: String::new(),
            modifiers: Vec::new(),
            body: String::new(),
        }
    }

    pub fn is_view(&self) -> bool {
        self.state_mutability == "view"
    }

    pub fn is_pure(&self) -> bool {
        self.state_mutability == "pure"
    }

    pub fn is_payable(&self) -> bool {
        self.state_mutability == "payable"
    }

    pub fn is_public(&self) -> bool {
        self.visibility == "public"
    }

    pub fn is_external(&self) -> bool {
        self.visibility == "external"
    }

    pub fn has_modifier(&self, modifier: &str) -> bool {
        self.modifiers.iter().any(|m| m.contains(modifier))
    }

    pub fn is_constructor(&self) -> bool {
        self.name == "constructor"
    }

    pub fn is_fallback(&self) -> bool {
        self.name == "fallback"
    }

    pub fn is_receive(&self) -> bool {
        self.name == "receive"
    }
}

impl Variable {
    pub fn new(name: String, var_type: String) -> Self {
        Self {
            name,
            var_type,
            visibility: "internal".to_string(),
            is_constant: false,
            is_immutable: false,
        }
    }

    pub fn is_public(&self) -> bool {
        self.visibility == "public"
    }

    pub fn is_private(&self) -> bool {
        self.visibility == "private"
    }

    pub fn is_internal(&self) -> bool {
        self.visibility == "internal"
    }

    pub fn with_visibility(mut self, visibility: String) -> Self {
        self.visibility = visibility;
        self
    }

    pub fn as_constant(mut self) -> Self {
        self.is_constant = true;
        self
    }

    pub fn as_immutable(mut self) -> Self {
        self.is_immutable = true;
        self
    }
}
