// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract demonstrates secure coding practices
contract SecureToken {
    using SafeMath for uint256; // Safe math operations
    
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    
    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) private allowances;
    
    address public owner;
    bool public paused;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Paused();
    event Unpaused();
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }
    
    modifier validAddress(address addr) {
        require(addr != address(0), "Invalid address");
        _;
    }
    
    constructor(string memory _name, string memory _symbol, uint256 _totalSupply) {
        name = _name;
        symbol = _symbol;
        decimals = 18;
        totalSupply = _totalSupply * 10**decimals;
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
        
        emit Transfer(address(0), msg.sender, totalSupply);
    }
    
    function transfer(address to, uint256 value) 
        external 
        validAddress(to) 
        whenNotPaused 
        returns (bool) 
    {
        require(value <= balances[msg.sender], "Insufficient balance");
        
        // Safe math operations
        balances[msg.sender] = balances[msg.sender].sub(value);
        balances[to] = balances[to].add(value);
        
        emit Transfer(msg.sender, to, value);
        return true;
    }
    
    function approve(address spender, uint256 value) 
        external 
        validAddress(spender) 
        whenNotPaused 
        returns (bool) 
    {
        allowances[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 value) 
        external 
        validAddress(from) 
        validAddress(to) 
        whenNotPaused 
        returns (bool) 
    {
        require(value <= balances[from], "Insufficient balance");
        require(value <= allowances[from][msg.sender], "Insufficient allowance");
        
        // Safe operations
        balances[from] = balances[from].sub(value);
        balances[to] = balances[to].add(value);
        allowances[from][msg.sender] = allowances[from][msg.sender].sub(value);
        
        emit Transfer(from, to, value);
        return true;
    }
    
    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
    
    function allowance(address owner, address spender) external view returns (uint256) {
        return allowances[owner][spender];
    }
    
    function pause() external onlyOwner {
        paused = true;
        emit Paused();
    }
    
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }
    
    // Secure: Proper access control for minting
    function mint(address to, uint256 value) external onlyOwner validAddress(to) {
        require(totalSupply.add(value) >= totalSupply, "Overflow check");
        
        totalSupply = totalSupply.add(value);
        balances[to] = balances[to].add(value);
        
        emit Transfer(address(0), to, value);
    }
}

// Safe Math Library (for demonstration - OpenZeppelin's is better)
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
    
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }
    
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }
    
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }
}
