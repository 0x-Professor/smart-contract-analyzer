# Smart Contract Analyzer

A comprehensive Ethereum smart contract analyzer built in Rust that provides static analysis, vulnerability detection, gas optimization suggestions, and deployment simulation capabilities.

## Features

### 🔍 Analysis Capabilities
- **Static Code Analysis**: Comprehensive parsing and analysis of Solidity contracts
- **Vulnerability Detection**: Security vulnerability scanning with detailed reports
- **Gas Analysis**: Detailed gas consumption analysis and optimization suggestions
- **Bytecode Analysis**: EVM bytecode parsing and instruction analysis

### 🛡️ Security Features
- **Reentrancy Detection**: Identifies potential reentrancy vulnerabilities
- **Integer Overflow/Underflow**: Detects unsafe arithmetic operations
- **Unchecked Return Values**: Finds unchecked external call return values
- **Access Control Issues**: Identifies authorization vulnerabilities
- **Timestamp Dependencies**: Detects reliance on block timestamps
- **Selfdestruct Vulnerabilities**: Finds unprotected selfdestruct calls

### ⚡ Performance Analysis
- **Gas Optimization**: Identifies gas-intensive operations and suggests optimizations
- **Function-level Analysis**: Per-function gas cost breakdown
- **Storage Analysis**: Efficient storage layout recommendations
- **Dead Code Detection**: Identifies unused code segments

### 🚀 Advanced Features
- **Contract Comparison**: Side-by-side analysis of multiple contracts
- **Simulation Engine**: Test contract behavior without deployment
- **Interactive Mode**: Real-time analysis and exploration
- **Multiple Output Formats**: JSON, HTML, Text, and Markdown reports
- **Template Generation**: Customizable report templates

## Installation

### Prerequisites
- Rust 1.70+ (with Cargo)
- Windows/Linux/macOS

### Build from Source
```bash
git clone <repository-url>
cd smart-contract-analyzer
cargo build --release
```

The binary will be available at `target/release/smart-contract-analyzer.exe` (Windows) or `target/release/smart-contract-analyzer` (Unix).

## Usage

### Basic Analysis
```bash
# Analyze a single contract
smart-contract-analyzer analyze -f contract.sol

# With detailed vulnerability analysis
smart-contract-analyzer analyze -f contract.sol --vulnerability-analysis --gas-analysis

# Output to JSON file
smart-contract-analyzer analyze -f contract.sol -o report.json --output-format json
```

### Compare Contracts
```bash
# Compare multiple contracts
smart-contract-analyzer compare contract1.sol contract2.sol -o comparison.html --output-format html
```

### Optimization Suggestions
```bash
# Get gas optimization suggestions
smart-contract-analyzer optimize -f contract.sol --focus gas
```

### Contract Simulation
```bash
# Simulate contract execution
smart-contract-analyzer simulate -f contract.sol --scenarios scenarios.json
```

### Interactive Mode
```bash
# Launch interactive analysis mode
smart-contract-analyzer interactive -f contract.sol
```

### Configuration Management
```bash
# Set up custom analysis rules
smart-contract-analyzer config set --rules custom-rules.json
smart-contract-analyzer config init
```

## Command Reference

### `analyze`
Analyze a single smart contract file.

**Options:**
- `-f, --file <FILE>`: Path to the Solidity contract file (required)
- `-b, --bytecode <BYTECODE>`: Optional bytecode file path
- `-a, --abi <ABI>`: Optional ABI file path
- `-o, --output <OUTPUT>`: Output file path
- `--output-format <FORMAT>`: Output format (json, html, text, markdown)
- `--gas-analysis`: Enable detailed gas analysis
- `--vulnerability-analysis`: Enable vulnerability detection
- `--rules <RULES>`: Custom rules file path
- `-v, --verbose`: Verbose output

### `compare`
Compare multiple contracts side-by-side.

**Options:**
- `<FILES>...`: Contract files to compare (2 or more)
- `-o, --output <OUTPUT>`: Output file path
- `--output-format <FORMAT>`: Output format (json, html, text, markdown)
- `-v, --verbose`: Verbose output

### `optimize`
Generate optimization suggestions for contracts.

**Options:**
- `-f, --file <FILE>`: Path to the Solidity contract file
- `--focus <FOCUS>`: Focus area (gas, security, readability)
- `-o, --output <OUTPUT>`: Output file path
- `--aggressive`: Enable aggressive optimizations

### `simulate`
Simulate contract execution scenarios.

**Options:**
- `-f, --file <FILE>`: Path to the Solidity contract file
- `--scenarios <SCENARIOS>`: Scenarios configuration file
- `--network <NETWORK>`: Target network (mainnet, sepolia, hardhat)
- `-o, --output <OUTPUT>`: Output file path

### `deploy`
Deploy contract for testing purposes.

**Options:**
- `-f, --file <FILE>`: Path to the Solidity contract file
- `--network <NETWORK>`: Target network
- `--private-key <KEY>`: Private key for deployment
- `--gas-limit <LIMIT>`: Gas limit for deployment
- `--gas-price <PRICE>`: Gas price in gwei

### `interactive`
Launch interactive analysis mode.

**Options:**
- `-f, --file <FILE>`: Optional initial contract file

### `template`
Generate report templates.

**Options:**
- `--type <TYPE>`: Template type (analysis, comparison, optimization)
- `-o, --output <OUTPUT>`: Output file path

### `config`
Configuration management.

**Subcommands:**
- `init`: Initialize default configuration
- `set`: Set configuration values
- `get`: Get configuration values
- `list`: List all configuration options

## Project Structure

```
smart-contract-analyzer/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config/
│   │   ├── mod.rs
│   │   └── settings.rs
│   ├── parser/
│   │   ├── mod.rs
│   │   ├── solidity.rs
│   │   ├── bytecode.rs
│   │   └── abi.rs
│   ├── analyzer/
│   │   ├── mod.rs
│   │   ├── gas/
│   │   │   ├── mod.rs
│   │   │   ├── static_analyzer.rs
│   │   │   ├── dynamic_analyzer.rs
│   │   │   └── optimizer.rs
│   │   ├── vulnerabilities/
│   │   │   ├── mod.rs
│   │   │   ├── detector.rs
│   │   │   ├── patterns.rs
│   │   │   └── rules.rs
│   │   └── reports/
│   │       ├── mod.rs
│   │       ├── generator.rs
│   │       └── formatter.rs
│   ├── blockchain/
│   │   ├── mod.rs
│   │   ├── client.rs
│   │   ├── contract.rs
│   │   └── simulation.rs
│   ├── cli/
│   │   ├── mod.rs
│   │   ├── commands.rs
│   │   └── args.rs
│   ├── utils/
│   │   ├── mod.rs
│   │   ├── helpers.rs
│   │   └── errors.rs
│   └── types/
│       ├── mod.rs
│       ├── contract.rs
│       ├── analysis.rs
│       └── vulnerability.rs
├── tests/
│   ├── integration/
│   └── unit/
├── examples/
├── docs/
└── config/
    ├── rules.json
    └── settings.toml
```

## Development

### Architecture
The analyzer is built with a modular architecture:

1. **Parser Layer**: Solidity and bytecode parsing
2. **Analysis Layer**: Static analysis and vulnerability detection
3. **Optimization Layer**: Gas optimization and suggestions
4. **Blockchain Layer**: Network interaction and simulation
5. **CLI Layer**: User interface and command handling

### Adding New Analyzers
1. Create a new analyzer in `src/analyzer/`
2. Implement the analysis trait
3. Register it in the main analyzer
4. Add CLI commands if needed

### Custom Rules
Create a JSON file with custom vulnerability patterns:

```json
{
  "rules": [
    {
      "id": "CUSTOM-001",
      "name": "Custom Pattern",
      "pattern": "regex_pattern_here",
      "severity": "Medium",
      "description": "Description of the issue"
    }
  ]
}
```

## Dependencies

### Core Dependencies
- **clap**: Command-line argument parsing
- **serde**: Serialization/deserialization
- **tokio**: Async runtime
- **reqwest**: HTTP client for blockchain interaction
- **regex**: Pattern matching
- **chrono**: Date/time handling

### Analysis Dependencies
- **hex**: Hexadecimal encoding/decoding
- **sha2**: Cryptographic hashing
- **rand**: Random number generation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For issues, questions, or contributions, please:
1. Check the existing issues
2. Create a new issue with detailed information
3. Include contract samples if reporting bugs

## Changelog

### v0.1.0 (Initial Release)
- Complete smart contract analysis engine
- Vulnerability detection for common security issues
- Gas analysis and optimization suggestions
- Multi-format report generation
- Interactive analysis mode
- Contract comparison capabilities
- Blockchain simulation support

---

**Note**: This analyzer is for educational and development purposes. Always conduct thorough security audits before deploying contracts to production environments.
