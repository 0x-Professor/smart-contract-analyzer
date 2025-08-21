// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract has unprotected selfdestruct vulnerabilities
contract UnprotectedSelfdestruct {
    address public owner;
    mapping(address => uint256) public balances;
    bool public contractActive;
    
    event ContractDestroyed(address indexed by);
    event EmergencyStop(address indexed by);
    
    constructor() {
        owner = msg.sender;
        contractActive = true;
    }
    
    function deposit() external payable {
        require(contractActive, "Contract is inactive");
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(contractActive, "Contract is inactive");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // Vulnerable: No access control on selfdestruct
    function destroyContract() external {
        emit ContractDestroyed(msg.sender);
        selfdestruct(payable(msg.sender));
    }
    
    // Vulnerable: Weak access control
    function emergencyDestroy() external {
        require(msg.sender != address(0), "Invalid sender");
        
        emit ContractDestroyed(msg.sender);
        selfdestruct(payable(owner));
    }
    
    // Vulnerable: Using suicide (deprecated but still works)
    function killContract() external {
        suicide(payable(msg.sender));
    }
    
    // Vulnerable: Conditional selfdestruct with weak condition
    function conditionalDestroy(uint256 code) external {
        if (code == 12345) {  // Weak condition
            selfdestruct(payable(msg.sender));
        }
    }
    
    // This would be the correct way (but we're testing vulnerabilities)
    function safeDestroy() external {
        require(msg.sender == owner, "Only owner");
        require(!contractActive, "Contract still active");
        
        selfdestruct(payable(owner));
    }
    
    function emergencyStop() external {
        // Vulnerable: Anyone can stop the contract
        contractActive = false;
        emit EmergencyStop(msg.sender);
    }
    
    // Function that looks safe but has hidden selfdestruct
    function updateSettings(bytes calldata data) external {
        if (data.length == 4 && keccak256(data) == keccak256("kill")) {
            selfdestruct(payable(msg.sender));
        }
    }
}
