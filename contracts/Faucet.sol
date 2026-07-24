// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract Faucet {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    address public constant SVP = address(0);

    struct TokenConfig {
        uint256 amountAllowed;
        bool enabled;
    }

    mapping(address => TokenConfig) public tokenConfigs;
    EnumerableSet.AddressSet private _enabledTokens;
    address public operator;
    address public adminer;

    modifier onlyOperator() {
        require(msg.sender == operator, "only operator");
        _;
    }

    modifier onlyAdminer() {
        require(msg.sender == adminer, "only adminer");
        _;
    }

    event Claimed(address indexed token, uint256 amount, address indexed user);
    event TokenUpdated(
        address indexed token,
        uint256 amountAllowed,
        bool enabled
    );
    event OperatorUpdated(address indexed oldOperator, address indexed newOperator);
    event AdminerUpdated(address indexed oldAdminer, address indexed newAdminer);
    event Withdrawn(address indexed token, uint256 amount, address indexed to);

    struct TokenInit {
        address token;
        uint256 amountAllowed;
    }

    constructor(TokenInit[] memory tokens) {
        adminer = msg.sender;

        tokenConfigs[SVP] = TokenConfig({
            amountAllowed: 1 ether,
            enabled: true
        });
        _enabledTokens.add(SVP);
        emit TokenUpdated(SVP, 1 ether, true);

        for (uint256 i = 0; i < tokens.length; i++) {
            require(tokens[i].amountAllowed != 0, "invalid amount");
            tokenConfigs[tokens[i].token] = TokenConfig({
                amountAllowed: tokens[i].amountAllowed,
                enabled: true
            });
            _enabledTokens.add(tokens[i].token);
            emit TokenUpdated(tokens[i].token, tokens[i].amountAllowed, true);
        }
    }

    function claim(address token, address user) external onlyOperator {
        require(user != address(0), "invalid user address");
        TokenConfig memory config = tokenConfigs[token];
        require(config.enabled, "token not enabled");
        uint256 amount = config.amountAllowed;

        if (token == SVP) {
            require(address(this).balance >= amount, "insufficient SVP balance");
            (bool success, ) = user.call{value: amount}("");
            require(success, "SVP transfer failed");
        } else {
            require(
                IERC20(token).balanceOf(address(this)) >= amount,
                "insufficient token balance"
            );
            IERC20(token).safeTransfer(user, amount);
        }

        emit Claimed(token, amount, user);
    }

    function setToken(address token, uint256 amount) external onlyAdminer {
        require(amount != 0, "invalid amount");
        tokenConfigs[token] = TokenConfig({
            amountAllowed: amount,
            enabled: true
        });
        _enabledTokens.add(token);
        emit TokenUpdated(token, amount, true);
    }

    function removeToken(address token) external onlyAdminer {
        require(tokenConfigs[token].enabled, "token not enabled");
        delete tokenConfigs[token];
        _enabledTokens.remove(token);
        emit TokenUpdated(token, 0, false);
    }

    function enabledTokens() external view returns (address[] memory) {
        return _enabledTokens.values();
    }

    function enabledTokenInfos()
        external
        view
        returns (address[] memory tokens, uint256[] memory amounts)
    {
        uint256 n = _enabledTokens.length();
        tokens = new address[](n);
        amounts = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            address t = _enabledTokens.at(i);
            tokens[i] = t;
            amounts[i] = tokenConfigs[t].amountAllowed;
        }
    }

    function withdraw(
        address token,
        uint256 amount,
        address to
    ) external onlyAdminer {
        require(to != address(0), "invalid to address");
        require(amount != 0, "invalid amount");

        if (token == SVP) {
            require(address(this).balance >= amount, "insufficient SVP balance");
            (bool success, ) = to.call{value: amount}("");
            require(success, "SVP transfer failed");
        } else {
            require(
                IERC20(token).balanceOf(address(this)) >= amount,
                "insufficient token balance"
            );
            IERC20(token).safeTransfer(to, amount);
        }

        emit Withdrawn(token, amount, to);
    }

    function updateOperator(address _operator) external onlyAdminer {
        require(_operator != address(0), "invalid operator address");
        address oldOperator = operator;
        operator = _operator;
        emit OperatorUpdated(oldOperator, _operator);
    }

    function updateAdminer(address _adminer) external onlyAdminer {
        require(_adminer != address(0), "invalid adminer address");
        address oldAdminer = adminer;
        adminer = _adminer;
        emit AdminerUpdated(oldAdminer, _adminer);
    }

    receive() external payable {}
}
