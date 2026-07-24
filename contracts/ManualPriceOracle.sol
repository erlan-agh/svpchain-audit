// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract ManualPriceOracle is Ownable {
    mapping(address => uint256) private prices;

    event PriceUpdated(address indexed asset, uint256 price);

    constructor(address owner_) Ownable(owner_) {
        require(owner_ != address(0), "Invalid owner");
    }

    function setPrice(address asset, uint256 price) external onlyOwner {
        require(asset != address(0), "Invalid asset");
        require(price > 0, "Invalid price");

        prices[asset] = price;
        emit PriceUpdated(asset, price);
    }

    function getPrice(address asset) external view returns (uint256) {
        uint256 price = prices[asset];
        require(price > 0, "Price not set");
        return price;
    }
}
