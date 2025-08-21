use std::collections::HashMap;

pub struct BytecodeParser {
    opcodes: HashMap<u8, &'static str>,
}

impl Default for BytecodeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BytecodeParser {
    pub fn new() -> Self {
        let mut opcodes = HashMap::new();
        
        // Basic arithmetic operations
        opcodes.insert(0x01, "ADD");
        opcodes.insert(0x02, "MUL");
        opcodes.insert(0x03, "SUB");
        opcodes.insert(0x04, "DIV");
        opcodes.insert(0x06, "MOD");
        opcodes.insert(0x08, "ADDMOD");
        opcodes.insert(0x09, "MULMOD");
        
        // Comparison & bitwise logic operations
        opcodes.insert(0x10, "LT");
        opcodes.insert(0x11, "GT");
        opcodes.insert(0x12, "SLT");
        opcodes.insert(0x13, "SGT");
        opcodes.insert(0x14, "EQ");
        opcodes.insert(0x15, "ISZERO");
        opcodes.insert(0x16, "AND");
        opcodes.insert(0x17, "OR");
        opcodes.insert(0x18, "XOR");
        opcodes.insert(0x19, "NOT");
        
        // SHA3
        opcodes.insert(0x20, "SHA3");
        
        // Environmental information
        opcodes.insert(0x30, "ADDRESS");
        opcodes.insert(0x31, "BALANCE");
        opcodes.insert(0x32, "ORIGIN");
        opcodes.insert(0x33, "CALLER");
        opcodes.insert(0x34, "CALLVALUE");
        opcodes.insert(0x35, "CALLDATALOAD");
        opcodes.insert(0x36, "CALLDATASIZE");
        opcodes.insert(0x37, "CALLDATACOPY");
        opcodes.insert(0x38, "CODESIZE");
        opcodes.insert(0x39, "CODECOPY");
        opcodes.insert(0x3A, "GASPRICE");
        
        // Block information
        opcodes.insert(0x40, "BLOCKHASH");
        opcodes.insert(0x41, "COINBASE");
        opcodes.insert(0x42, "TIMESTAMP");
        opcodes.insert(0x43, "NUMBER");
        opcodes.insert(0x44, "DIFFICULTY");
        opcodes.insert(0x45, "GASLIMIT");
        
        // Stack, memory, storage and flow operations
        opcodes.insert(0x50, "POP");
        opcodes.insert(0x51, "MLOAD");
        opcodes.insert(0x52, "MSTORE");
        opcodes.insert(0x53, "MSTORE8");
        opcodes.insert(0x54, "SLOAD");
        opcodes.insert(0x55, "SSTORE");
        opcodes.insert(0x56, "JUMP");
        opcodes.insert(0x57, "JUMPI");
        opcodes.insert(0x58, "PC");
        opcodes.insert(0x59, "MSIZE");
        opcodes.insert(0x5A, "GAS");
        opcodes.insert(0x5B, "JUMPDEST");
        
        // Push operations
        for i in 0x60..=0x7F {
            opcodes.insert(i, "PUSH");
        }
        
        // Duplicate operations
        for i in 0x80..=0x8F {
            opcodes.insert(i, "DUP");
        }
        
        // Exchange operations
        for i in 0x90..=0x9F {
            opcodes.insert(i, "SWAP");
        }
        
        // Logging operations
        for i in 0xA0..=0xA4 {
            opcodes.insert(i, "LOG");
        }
        
        // System operations
        opcodes.insert(0xF0, "CREATE");
        opcodes.insert(0xF1, "CALL");
        opcodes.insert(0xF2, "CALLCODE");
        opcodes.insert(0xF3, "RETURN");
        opcodes.insert(0xF4, "DELEGATECALL");
        opcodes.insert(0xF5, "CREATE2");
        opcodes.insert(0xFA, "STATICCALL");
        opcodes.insert(0xFD, "REVERT");
        opcodes.insert(0xFE, "INVALID");
        opcodes.insert(0xFF, "SELFDESTRUCT");

        Self { opcodes }
    }

    pub fn parse(&self, bytecode: &str) -> crate::Result<Vec<Instruction>> {
        let cleaned_bytecode = bytecode.trim_start_matches("0x");
        let bytes = hex::decode(cleaned_bytecode)?;
        let mut instructions = Vec::new();
        let mut i = 0;

        while i < bytes.len() {
            let opcode = bytes[i];
            let instruction_name = self.opcodes.get(&opcode)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("UNKNOWN_{:02X}", opcode));

            let mut instruction = Instruction {
                opcode,
                name: instruction_name.clone(),
                operand: None,
                gas_cost: self.get_gas_cost(opcode),
                address: i,
            };

            // Handle PUSH operations with operands
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_size = (opcode - 0x60 + 1) as usize;
                if i + push_size < bytes.len() {
                    let operand_bytes = &bytes[i + 1..i + 1 + push_size];
                    instruction.operand = Some(hex::encode(operand_bytes));
                    i += push_size;
                }
                instruction.name = format!("PUSH{}", push_size);
            }

            instructions.push(instruction);
            i += 1;
        }

        Ok(instructions)
    }

    pub fn analyze_gas_usage(&self, instructions: &[Instruction]) -> GasAnalysis {
        let mut total_gas = 0;
        let mut expensive_operations = Vec::new();
        let mut storage_operations = 0;
        let mut external_calls = 0;

        for instruction in instructions {
            total_gas += instruction.gas_cost;

            match instruction.opcode {
                0x54 | 0x55 => storage_operations += 1, // SLOAD, SSTORE
                0xF1 | 0xF2 | 0xF4 | 0xFA => external_calls += 1, // CALL operations
                _ => {}
            }

            if instruction.gas_cost > 700 {
                expensive_operations.push(instruction.clone());
            }
        }

        GasAnalysis {
            total_estimated_gas: total_gas,
            expensive_operations,
            storage_operations,
            external_calls,
            optimization_suggestions: self.generate_gas_optimizations(instructions),
        }
    }

    fn get_gas_cost(&self, opcode: u8) -> u32 {
        match opcode {
            0x00 => 0,          // STOP
            0x01..=0x0B => 3,   // Arithmetic operations
            0x10..=0x1A => 3,   // Comparison operations
            0x20 => 30,         // SHA3
            0x30..=0x3F => 2,   // Environmental information
            0x40..=0x48 => 20,  // Block information
            0x50 => 2,          // POP
            0x51 => 3,          // MLOAD
            0x52 => 3,          // MSTORE
            0x53 => 3,          // MSTORE8
            0x54 => 800,        // SLOAD
            0x55 => 20000,      // SSTORE (can be less in some cases)
            0x56 => 8,          // JUMP
            0x57 => 10,         // JUMPI
            0x58..=0x5B => 2,   // PC, MSIZE, GAS, JUMPDEST
            0x60..=0x7F => 3,   // PUSH operations
            0x80..=0x8F => 3,   // DUP operations
            0x90..=0x9F => 3,   // SWAP operations
            0xA0..=0xA4 => 375, // LOG operations
            0xF0 => 32000,      // CREATE
            0xF1 => 700,        // CALL
            0xF2 => 700,        // CALLCODE
            0xF3 => 0,          // RETURN
            0xF4 => 700,        // DELEGATECALL
            0xF5 => 32000,      // CREATE2
            0xFA => 700,        // STATICCALL
            0xFD => 0,          // REVERT
            0xFE => 0,          // INVALID
            0xFF => 5000,       // SELFDESTRUCT
            _ => 1,             // Default
        }
    }

    fn generate_gas_optimizations(&self, instructions: &[Instruction]) -> Vec<String> {
        let mut suggestions = Vec::new();
        let mut storage_reads = 0;
        let mut storage_writes = 0;

        for instruction in instructions {
            match instruction.opcode {
                0x54 => storage_reads += 1,  // SLOAD
                0x55 => storage_writes += 1, // SSTORE
                _ => {}
            }
        }

        if storage_reads > 5 {
            suggestions.push("Consider caching storage reads in memory variables".to_string());
        }

        if storage_writes > 3 {
            suggestions.push("Consider batching storage writes or using packed structs".to_string());
        }

        suggestions
    }

    pub fn find_function_selectors(&self, bytecode: &str) -> crate::Result<Vec<String>> {
        let instructions = self.parse(bytecode)?;
        let mut selectors = Vec::new();

        for (i, instruction) in instructions.iter().enumerate() {
            if instruction.name.starts_with("PUSH4") {
                if let Some(operand) = &instruction.operand {
                    if operand.len() == 8 { // 4 bytes = 8 hex chars
                        selectors.push(format!("0x{}", operand));
                    }
                }
            }
        }

        Ok(selectors)
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub opcode: u8,
    pub name: String,
    pub operand: Option<String>,
    pub gas_cost: u32,
    pub address: usize,
}

#[derive(Debug)]
pub struct GasAnalysis {
    pub total_estimated_gas: u32,
    pub expensive_operations: Vec<Instruction>,
    pub storage_operations: u32,
    pub external_calls: u32,
    pub optimization_suggestions: Vec<String>,
}
