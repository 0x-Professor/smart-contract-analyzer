// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract has unchecked return value vulnerabilities
contract UncheckedReturnValues {
    mapping(address => uint256) public balances;
    
    event Transfer(address indexed to, uint256 amount);
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdrawUnsafe(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        // Vulnerable: Not checking return value
        msg.sender.call{value: amount}("");
    }
    
    function sendEther(address payable recipient, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        // Vulnerable: Not checking return value
        recipient.send(amount);
        
        emit Transfer(recipient, amount);
    }
    
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "Array length mismatch");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(balances[msg.sender] >= amounts[i], "Insufficient balance");
            
            balances[msg.sender] -= amounts[i];
            
            // Vulnerable: Not checking return value in loop
            payable(recipients[i]).send(amounts[i]);
        }
    }
    
    function delegateCallUnsafe(address target, bytes calldata data) external {
        // Vulnerable: Not checking return value of delegatecall
        target.delegatecall(data);
    }
    
    function staticCallUnsafe(address target, bytes calldata data) external view returns (bytes memory) {
        // This is actually safe in view functions, but shown for completeness
        (bool success, bytes memory result) = target.staticcall(data);
        return result; // Not checking success
    }
}
