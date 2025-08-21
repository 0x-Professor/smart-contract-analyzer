// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract has integer overflow/underflow vulnerabilities
contract IntegerOverflowVulnerable {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balances[msg.sender] = _initialSupply;
    }
    
    function transfer(address to, uint256 value) external returns (bool) {
        require(to != address(0), "Invalid address");
        
        // Vulnerable: No overflow check
        balances[msg.sender] -= value; // Can underflow
        balances[to] += value; // Can overflow
        
        emit Transfer(msg.sender, to, value);
        return true;
    }
    
    function mint(address to, uint256 value) external {
        // Vulnerable: No overflow check
        totalSupply += value; // Can overflow
        balances[to] += value; // Can overflow
        
        emit Transfer(address(0), to, value);
    }
    
    function unsafeMath(uint256 a, uint256 b) external pure returns (uint256) {
        // Various overflow vulnerabilities
        uint256 result1 = a + b; // Addition overflow
        uint256 result2 = a - b; // Subtraction underflow
        uint256 result3 = a * b; // Multiplication overflow
        uint256 result4 = a / b; // Division by zero (not overflow, but still dangerous)
        
        return result1 + result2 + result3 + result4;
    }
    
    function arrayAccess(uint256[] memory arr, uint256 index) external pure returns (uint256) {
        // Potential array out-of-bounds access
        return arr[index];
    }
}
