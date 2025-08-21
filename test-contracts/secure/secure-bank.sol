// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This is a secure contract that follows best practices
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract SecureBank is ReentrancyGuard, Ownable, Pausable {
    mapping(address => uint256) private balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 amount);
    
    constructor() Ownable(msg.sender) {}
    
    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "Must deposit something");
        
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        require(amount > 0, "Must withdraw something");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Effects before interactions (CEI pattern)
        balances[msg.sender] -= amount;
        
        // Safe external call
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdraw(msg.sender, amount);
    }
    
    function emergencyWithdraw() external nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // Effects before interactions
        balances[msg.sender] = 0;
        
        (bool success, ) = payable(msg.sender).call{value: balance}("");
        require(success, "Emergency transfer failed");
        
        emit EmergencyWithdraw(msg.sender, balance);
    }
    
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }
    
    // Secure: Proper access control for critical functions
    function emergencyDrain() external onlyOwner whenPaused {
        uint256 contractBalance = address(this).balance;
        (bool success, ) = payable(owner()).call{value: contractBalance}("");
        require(success, "Emergency drain failed");
    }
}
