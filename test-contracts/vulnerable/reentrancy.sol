// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract is vulnerable to reentrancy attacks
contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: External call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // State change after external call
        emit Withdraw(msg.sender, amount);
    }
    
    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        // Another reentrancy vulnerability
        msg.sender.transfer(balance);
        balances[msg.sender] = 0;
    }
    
    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
