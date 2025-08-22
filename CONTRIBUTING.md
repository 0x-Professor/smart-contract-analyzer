# Contributing to Smart Contract Analyzer

Thank you for your interest in contributing to the Smart Contract Analyzer! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues

1. **Check Existing Issues**: Before creating a new issue, please search existing issues to avoid duplicates.
2. **Use Issue Templates**: We provide templates for bug reports, feature requests, and security issues.
3. **Provide Details**: Include relevant information such as:
   - Operating system and version
   - Rust version (`rustc --version`)
   - Smart contract code that caused the issue
   - Expected vs actual behavior
   - Error messages and stack traces

### Submitting Pull Requests

1. **Fork the Repository**: Create your own fork of the project.
2. **Create a Feature Branch**: Use descriptive branch names like `feature/add-swc-123` or `fix/gas-calculation-bug`.
3. **Make Your Changes**: Follow our coding standards and guidelines.
4. **Test Your Changes**: Ensure all tests pass and add new tests for your changes.
5. **Update Documentation**: Update relevant documentation and comments.
6. **Submit PR**: Create a pull request with a clear description of your changes.

## 🏗️ Development Setup

### Prerequisites

- **Rust 1.70+** with Cargo
- **Git** for version control
- **Code Editor** with Rust support (VS Code recommended)

### Setup Instructions

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/smart-contract-analyzer.git
cd smart-contract-analyzer

# Build the project
cargo build

# Run tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings
```

### Project Structure

```
smart-contract-analyzer/
├── src/
│   ├── main.rs                 # CLI entry point
│   ├── lib.rs                  # Library exports
│   ├── analyzer/               # Analysis engines
│   │   ├── mod.rs
│   │   ├── enhanced_analyzer.rs
│   │   ├── gas_analyzer.rs
│   │   └── vulnerabilities/    # Vulnerability detection
│   ├── parser/                 # Solidity parsers
│   │   ├── mod.rs
│   │   ├── solidity.rs
│   │   ├── enhanced_solidity.rs
│   │   └── bytecode.rs
│   ├── detector/               # Detection engines
│   │   ├── mod.rs
│   │   └── enhanced_detector.rs
│   ├── cli/                    # Command-line interface
│   │   ├── mod.rs
│   │   ├── args.rs
│   │   └── commands.rs
│   ├── blockchain/             # Blockchain integration
│   │   ├── mod.rs
│   │   ├── client.rs
│   │   ├── contract.rs
│   │   └── simulation.rs
│   ├── report/                 # Report generation
│   │   ├── mod.rs
│   │   ├── generator.rs
│   │   └── formatter.rs
│   └── types/                  # Type definitions
│       ├── mod.rs
│       ├── contract.rs
│       └── vulnerability.rs
├── tests/                      # Integration tests
├── test-contracts/             # Test Solidity contracts
├── examples/                   # Usage examples
├── docs/                       # Documentation
└── config/                     # Configuration files
```

## 📝 Coding Standards

### Rust Code Style

- **Formatting**: Use `cargo fmt` with default settings
- **Linting**: Address all `cargo clippy` warnings
- **Naming**: Follow Rust naming conventions
  - `snake_case` for variables and functions
  - `PascalCase` for types and structs
  - `SCREAMING_SNAKE_CASE` for constants
- **Documentation**: Use rustdoc comments (`///`) for public APIs
- **Error Handling**: Use `Result<T, E>` and custom error types

### Code Quality Guidelines

1. **Single Responsibility**: Each function should have one clear purpose
2. **Documentation**: Document all public APIs and complex logic
3. **Testing**: Write unit tests for all new functionality
4. **Error Messages**: Provide clear, actionable error messages
5. **Performance**: Consider performance implications, especially for large contracts
6. **Safety**: Prefer safe Rust patterns over unsafe code

### Example Code Style

```rust
/// Analyzes a Solidity function for potential vulnerabilities
/// 
/// # Arguments
/// * `function` - The parsed function to analyze
/// * `context` - Analysis context containing contract information
/// 
/// # Returns
/// * `Result<Vec<Vulnerability>>` - List of detected vulnerabilities
/// 
/// # Errors
/// * Returns error if function parsing fails
pub fn analyze_function(
    &self,
    function: &EnhancedFunction,
    context: &AnalysisContext,
) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    
    // Check for reentrancy vulnerabilities
    if self.has_external_calls(function) && !self.has_reentrancy_guard(function) {
        vulnerabilities.push(self.create_reentrancy_vulnerability(function)?);
    }
    
    Ok(vulnerabilities)
}
```

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test complete analysis workflows  
3. **Contract Tests**: Test against real Solidity contracts
4. **Performance Tests**: Ensure scalability

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reentrancy_detection() {
        let detector = EnhancedVulnerabilityDetector::new();
        let vulnerable_code = r#"
            function withdraw(uint amount) external {
                require(balances[msg.sender] >= amount);
                msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        "#;
        
        let function = parse_test_function(vulnerable_code);
        let vulnerabilities = detector.check_reentrancy(&function).unwrap();
        
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].id, "SWC-107");
        assert_eq!(vulnerabilities[0].severity, "Critical");
    }
}
```

### Test Data

- Add test contracts to `test-contracts/`
- Use realistic contract examples
- Cover both vulnerable and secure patterns
- Include edge cases and complex scenarios

## 🔒 Security Considerations

### Responsible Disclosure

If you discover security vulnerabilities:

1. **DO NOT** create a public issue
2. **DO** email security concerns to: security@smart-contract-analyzer.dev
3. **DO** provide detailed reproduction steps
4. **DO** allow time for assessment and patching

### Security Testing

- Test with various malicious contract patterns
- Validate that the analyzer doesn't execute contract code
- Ensure safe handling of untrusted input
- Test memory and resource limits

## 📚 Documentation

### Required Documentation

1. **Code Comments**: Document complex algorithms and business logic
2. **API Documentation**: Complete rustdoc for all public APIs
3. **README Updates**: Update README.md for new features
4. **CHANGELOG**: Add entries for all changes
5. **Examples**: Provide usage examples for new features

### Documentation Style

```rust
/// Detects integer overflow vulnerabilities in arithmetic operations
/// 
/// This function analyzes the AST of a function to identify arithmetic operations
/// that could potentially overflow or underflow. It considers:
/// 
/// - Addition, subtraction, multiplication, and division operations
/// - Presence of SafeMath library usage
/// - Solidity compiler version (0.8+ has built-in checks)
/// - Explicit bounds checking with require() statements
/// 
/// # Examples
/// 
/// ```rust
/// let detector = VulnerabilityDetector::new();
/// let vulnerabilities = detector.check_integer_overflow(&function)?;
/// ```
/// 
/// # Returns
/// 
/// Returns a vector of `Vulnerability` objects, each representing a potential
/// integer overflow issue with severity, location, and remediation advice.
pub fn check_integer_overflow(&self, function: &Function) -> Result<Vec<Vulnerability>> {
    // Implementation...
}
```

## 🎯 Contribution Areas

### High Priority

1. **Vulnerability Detection**
   - Implement additional SWC registry patterns
   - Improve false positive reduction
   - Add context-aware analysis

2. **Gas Analysis**
   - Enhance gas cost calculations
   - Add storage optimization detection
   - Implement loop analysis for DoS detection

3. **Parser Improvements**
   - Better error recovery
   - Support for latest Solidity features
   - Performance optimizations

### Medium Priority

1. **Integration**
   - Foundry/Hardhat plugins
   - CI/CD integration
   - IDE extensions

2. **Report Generation**
   - Additional output formats (SARIF, XML)
   - Interactive HTML reports
   - Custom report templates

3. **User Experience**
   - Progress indicators
   - Better error messages
   - Configuration management

### Low Priority

1. **Advanced Features**
   - Machine learning integration
   - Historical vulnerability tracking
   - Automated fix suggestions

## 🏷️ Issue Labels

We use the following labels to organize issues:

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements to documentation
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention is needed
- `priority:high` - High priority issues
- `priority:medium` - Medium priority issues
- `priority:low` - Low priority issues
- `area:parser` - Parser-related issues
- `area:detector` - Detection engine issues
- `area:gas` - Gas analysis issues
- `area:cli` - Command-line interface issues

## 💬 Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Discord**: Real-time chat (link in README)

### Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please read our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🔄 Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- MAJOR: Breaking changes
- MINOR: New features, backwards compatible
- PATCH: Bug fixes, backwards compatible

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in Cargo.toml
- [ ] Create GitHub release with notes

## 📋 Review Process

### Pull Request Review

1. **Automated Checks**: All CI checks must pass
2. **Code Review**: At least one maintainer review
3. **Testing**: New features must include tests
4. **Documentation**: Updates must include docs

### Review Criteria

- Code quality and style compliance
- Test coverage and quality
- Documentation completeness
- Performance impact consideration
- Security implications review

## 🙏 Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- GitHub repository contributors
- Release notes acknowledgments
- Annual contributor highlights

Thank you for contributing to Smart Contract Analyzer! Your efforts help make smart contract development safer for everyone.

---

**Questions?** Feel free to ask in GitHub Discussions or create an issue with the `question` label.
