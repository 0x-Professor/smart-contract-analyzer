// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract has access control vulnerabilities
contract AccessControlVulnerable {
    address public owner;
    mapping(address => bool) public admins;
    uint256 public contractBalance;
    
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerable: Using tx.origin instead of msg.sender
    modifier onlyOwnerUnsafe() {
        require(tx.origin == owner, "Not the owner");
        _;
    }
    
    modifier onlyAdmin() {
        require(admins[msg.sender], "Not an admin");
        _;
    }
    
    function transferOwnership(address newOwner) external onlyOwnerUnsafe {
        require(newOwner != address(0), "Invalid address");
        
        address previousOwner = owner;
        owner = newOwner;
        
        emit OwnershipTransferred(previousOwner, newOwner);
    }
    
    function addAdmin(address admin) external {
        // Vulnerable: No access control
        admins[admin] = true;
        emit AdminAdded(admin);
    }
    
    function removeAdmin(address admin) external onlyAdmin {
        // Vulnerable: Admins can remove each other, including themselves
        admins[admin] = false;
        emit AdminRemoved(admin);
    }
    
    function withdrawAll() external {
        // Vulnerable: No access control
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function emergencyWithdraw() external {
        // Vulnerable: Using tx.origin for authorization
        require(tx.origin == owner, "Not authorized");
        payable(tx.origin).transfer(address(this).balance);
    }
    
    function sensitiveOperation() external {
        // Vulnerable: No proper access control
        require(msg.sender != address(0), "Invalid sender");
        
        // Critical operation without proper authorization
        contractBalance = 0;
    }
    
    // Vulnerable: Public function that should be restricted
    function setContractBalance(uint256 newBalance) external {
        contractBalance = newBalance;
    }
    
    receive() external payable {
        contractBalance += msg.value;
    }
}
