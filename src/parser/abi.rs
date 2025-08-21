use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABI {
    pub functions: Vec<ABIFunction>,
    pub events: Vec<ABIEvent>,
    pub constructor: Option<ABIConstructor>,
    pub fallback: Option<ABIFallback>,
    pub receive: Option<ABIReceive>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIFunction {
    pub name: String,
    pub inputs: Vec<ABIParameter>,
    pub outputs: Vec<ABIParameter>,
    pub state_mutability: String,
    pub function_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIEvent {
    pub name: String,
    pub inputs: Vec<ABIEventInput>,
    pub anonymous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIConstructor {
    pub inputs: Vec<ABIParameter>,
    pub state_mutability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIFallback {
    pub state_mutability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIReceive {
    pub state_mutability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIParameter {
    pub name: String,
    pub param_type: String,
    pub internal_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIEventInput {
    pub name: String,
    pub param_type: String,
    pub indexed: bool,
    pub internal_type: Option<String>,
}

pub struct ABIParser;

impl ABIParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_abi_json(&self, abi_json: &str) -> crate::Result<ABI> {
        let abi_array: Vec<Value> = serde_json::from_str(abi_json)?;
        let mut functions = Vec::new();
        let mut events = Vec::new();
        let mut constructor = None;
        let mut fallback = None;
        let mut receive = None;

        for item in abi_array {
            match item.get("type").and_then(|t| t.as_str()) {
                Some("function") => {
                    functions.push(self.parse_function(&item)?);
                }
                Some("event") => {
                    events.push(self.parse_event(&item)?);
                }
                Some("constructor") => {
                    constructor = Some(self.parse_constructor(&item)?);
                }
                Some("fallback") => {
                    fallback = Some(self.parse_fallback(&item)?);
                }
                Some("receive") => {
                    receive = Some(self.parse_receive(&item)?);
                }
                _ => {} // Skip unknown types
            }
        }

        Ok(ABI {
            functions,
            events,
            constructor,
            fallback,
            receive,
        })
    }

    fn parse_function(&self, item: &Value) -> crate::Result<ABIFunction> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .ok_or("Function name is required")?
            .to_string();

        let inputs = self.parse_parameters(item.get("inputs"))?;
        let outputs = self.parse_parameters(item.get("outputs"))?;

        let state_mutability = item.get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("nonpayable")
            .to_string();

        Ok(ABIFunction {
            name,
            inputs,
            outputs,
            state_mutability,
            function_type: "function".to_string(),
        })
    }

    fn parse_event(&self, item: &Value) -> crate::Result<ABIEvent> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .ok_or("Event name is required")?
            .to_string();

        let anonymous = item.get("anonymous")
            .and_then(|a| a.as_bool())
            .unwrap_or(false);

        let inputs = self.parse_event_inputs(item.get("inputs"))?;

        Ok(ABIEvent {
            name,
            inputs,
            anonymous,
        })
    }

    fn parse_constructor(&self, item: &Value) -> crate::Result<ABIConstructor> {
        let inputs = self.parse_parameters(item.get("inputs"))?;
        let state_mutability = item.get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("nonpayable")
            .to_string();

        Ok(ABIConstructor {
            inputs,
            state_mutability,
        })
    }

    fn parse_fallback(&self, item: &Value) -> crate::Result<ABIFallback> {
        let state_mutability = item.get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("nonpayable")
            .to_string();

        Ok(ABIFallback {
            state_mutability,
        })
    }

    fn parse_receive(&self, item: &Value) -> crate::Result<ABIReceive> {
        let state_mutability = item.get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("payable")
            .to_string();

        Ok(ABIReceive {
            state_mutability,
        })
    }

    fn parse_parameters(&self, params: Option<&Value>) -> crate::Result<Vec<ABIParameter>> {
        let mut parameters = Vec::new();
        
        if let Some(params_array) = params.and_then(|p| p.as_array()) {
            for param in params_array {
                let name = param.get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();

                let param_type = param.get("type")
                    .and_then(|t| t.as_str())
                    .ok_or("Parameter type is required")?
                    .to_string();

                let internal_type = param.get("internalType")
                    .and_then(|it| it.as_str())
                    .map(|s| s.to_string());

                parameters.push(ABIParameter {
                    name,
                    param_type,
                    internal_type,
                });
            }
        }

        Ok(parameters)
    }

    fn parse_event_inputs(&self, params: Option<&Value>) -> crate::Result<Vec<ABIEventInput>> {
        let mut inputs = Vec::new();
        
        if let Some(params_array) = params.and_then(|p| p.as_array()) {
            for param in params_array {
                let name = param.get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();

                let param_type = param.get("type")
                    .and_then(|t| t.as_str())
                    .ok_or("Parameter type is required")?
                    .to_string();

                let indexed = param.get("indexed")
                    .and_then(|i| i.as_bool())
                    .unwrap_or(false);

                let internal_type = param.get("internalType")
                    .and_then(|it| it.as_str())
                    .map(|s| s.to_string());

                inputs.push(ABIEventInput {
                    name,
                    param_type,
                    indexed,
                    internal_type,
                });
            }
        }

        Ok(inputs)
    }

    pub fn generate_function_selector(&self, function: &ABIFunction) -> String {
        let signature = format!(
            "{}({})",
            function.name,
            function.inputs
                .iter()
                .map(|param| param.param_type.clone())
                .collect::<Vec<_>>()
                .join(",")
        );

        let mut hasher = Sha256::new();
        hasher.update(signature.as_bytes());
        let hash = hasher.finalize();
        format!("0x{:08x}", u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]))
    }

    pub fn analyze_abi(&self, abi: &ABI) -> ABIAnalysis {
        let mut payable_functions = 0;
        let mut view_functions = 0;
        let mut pure_functions = 0;
        let mut external_functions = 0;
        let has_fallback = abi.fallback.is_some();
        let has_receive = abi.receive.is_some();

        for function in &abi.functions {
            match function.state_mutability.as_str() {
                "payable" => payable_functions += 1,
                "view" => view_functions += 1,
                "pure" => pure_functions += 1,
                _ => {}
            }
            
            // Assuming all ABI functions are external by default
            external_functions += 1;
        }

        ABIAnalysis {
            total_functions: abi.functions.len(),
            total_events: abi.events.len(),
            payable_functions,
            view_functions,
            pure_functions,
            external_functions,
            has_constructor: abi.constructor.is_some(),
            has_fallback,
            has_receive,
        }
    }
}

impl Default for ABIParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ABIAnalysis {
    pub total_functions: usize,
    pub total_events: usize,
    pub payable_functions: usize,
    pub view_functions: usize,
    pub pure_functions: usize,
    pub external_functions: usize,
    pub has_constructor: bool,
    pub has_fallback: bool,
    pub has_receive: bool,
}
