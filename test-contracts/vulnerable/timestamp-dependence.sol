// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract has timestamp dependence vulnerabilities
contract TimestampDependence {
    address public owner;
    uint256 public lastUpdate;
    uint256 public randomSeed;
    mapping(address => uint256) public lockTime;
    
    event RandomGenerated(uint256 randomNumber);
    event TimeLock(address indexed user, uint256 lockUntil);
    
    constructor() {
        owner = msg.sender;
        lastUpdate = block.timestamp;
    }
    
    function generateRandom() external returns (uint256) {
        // Vulnerable: Using block.timestamp for randomness
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
        randomSeed = random;
        
        emit RandomGenerated(random);
        return random;
    }
    
    function timeLock(address user, uint256 duration) external {
        require(msg.sender == owner, "Not owner");
        
        // Vulnerable: Relying on block.timestamp
        lockTime[user] = block.timestamp + duration;
        
        emit TimeLock(user, lockTime[user]);
    }
    
    function withdraw() external {
        // Vulnerable: Using block.timestamp for time checks
        require(block.timestamp > lockTime[msg.sender], "Still locked");
        
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function updateLastActive() external {
        // Vulnerable: Using block.timestamp
        require(block.timestamp > lastUpdate + 1 hours, "Too soon");
        lastUpdate = block.timestamp;
    }
    
    function isExpired(uint256 deadline) external view returns (bool) {
        // Vulnerable: Timestamp manipulation
        return block.timestamp > deadline;
    }
    
    function timeBasedReward() external {
        // Vulnerable: Using 'now' (alias for block.timestamp)
        require(now > lastUpdate + 1 days, "Wait longer");
        
        uint256 reward = (now - lastUpdate) * 1 ether / 1 days;
        payable(msg.sender).transfer(reward);
        
        lastUpdate = now;
    }
    
    function blockNumberBasedLogic() external {
        // Also vulnerable: Block number manipulation
        require(block.number > 1000000, "Too early");
        
        uint256 pseudoRandom = block.number % 10;
        randomSeed = pseudoRandom;
    }
    
    receive() external payable {}
}
