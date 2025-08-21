// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private storedData;
    address public owner;

    event DataStored(uint256 indexed value);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    function set(uint256 x) public onlyOwner {
        storedData = x;
        emit DataStored(x);
    }

    function get() public view returns (uint256) {
        return storedData;
    }

    function add(uint256 value) public onlyOwner {
        storedData = storedData + value; // Potential overflow
    }

    function transfer(address payable recipient) public onlyOwner {
        recipient.transfer(address(this).balance); // Potential reentrancy
    }
}
