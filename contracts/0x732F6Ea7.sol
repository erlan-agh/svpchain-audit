// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {BankERC20} from "./cosmos-evm-bank/BankERC20.sol";
// NOTE: BankERC20 only works on SVP chain (requires bank precompile at 0x807).

/// @title USDCBank
/// @notice USD Coin (6 decimals) backed by the Cosmos x/bank module via the
///         bank precompile at 0x0000000000000000000000000000000000000804.
///         Balances, mint, burn, and transfer are delegated to bank;
///         EVM balanceOf / totalSupply mirror bank state.
///
/// @dev Flow:
///      1. Deploy with `new USDCBank(initialOwner)`.
///      2. Submit governance MsgRegisterERC20WithDenom binding address(this)
///         to the target denom.
///      3. After the proposal passes, owner calls mint() — bank precompile
///         credits bank coins directly (no ConvertERC20 needed).
contract USDCBank is BankERC20 {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "USDCBank: caller is not the owner");
        _;
    }

    constructor(address initialOwner) BankERC20("USD Coin", "USDC", 6) {
        require(initialOwner != address(0), "USDCBank: zero address owner");
        owner = initialOwner;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) external {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "USDCBank: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
