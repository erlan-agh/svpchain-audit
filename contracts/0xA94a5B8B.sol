// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title VanToken
 * @dev 可升级的ERC20稳定币合约，支持暂停、冻结、黑名单等管理功能，以及EIP-2612 Permit功能
 */
contract VanToken is
    Initializable,
    ERC20Upgradeable,
    ERC20PermitUpgradeable,
    PausableUpgradeable,
    AccessControlEnumerableUpgradeable,
    UUPSUpgradeable
{
    // 角色定义
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant FREEZER_ROLE = keccak256("FREEZER_ROLE");
    bytes32 public constant BLACKLIST_ROLE = keccak256("BLACKLIST_ROLE");

    // EIP-3009 类型哈希（与 USDC 规范字符串一致）
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    // 状态变量
    uint8 private _decimals;
    mapping(address => bool) private _frozenAccounts;
    mapping(address => bool) private _blacklistedAccounts;
    // EIP-3009: authorizer => nonce => 已使用或已取消（追加到 storage 末尾以保证升级兼容）
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    // 事件
    event AccountFrozen(address indexed account);
    event AccountUnfrozen(address indexed account);
    event BlacklistAdded(address indexed account);
    event BlacklistRemoved(address indexed account);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    // 自定义错误
    error EAccountFrozen(address account);
    error AccountBlacklisted(address account);
    error ZeroAddress();
    error InvalidAmount();
    error AuthorizationNotYetValid();
    error AuthorizationExpired();
    error AuthorizationUsedOrCanceled();
    error InvalidSignature();
    error CallerMustBePayee();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev 初始化函数，替代构造函数
     * @param name 代币名称
     * @param symbol 代币符号
     * @param decimals_ 代币精度
     * @param admin 默认管理员地址
     * @param pauser 暂停角色地址
     * @param minter 铸造角色地址
     * @param upgrader 升级角色地址
     * @param freezer 冻结角色地址
     * @param blacklister 黑名单角色地址
     */
    function initialize(
        string memory name,
        string memory symbol,
        uint8 decimals_,
        address admin,
        address pauser,
        address minter,
        address upgrader,
        address freezer,
        address blacklister
    ) public initializer {
        if (admin == address(0)) {
            revert ZeroAddress();
        }
        if (pauser == address(0)) {
            revert ZeroAddress();
        }
        if (minter == address(0)) {
            revert ZeroAddress();
        }
        if (upgrader == address(0)) {
            revert ZeroAddress();
        }
        if (freezer == address(0)) {
            revert ZeroAddress();
        }
        if (blacklister == address(0)) {
            revert ZeroAddress();
        }

        __ERC20_init(name, symbol);
        __ERC20Permit_init(name);
        __Pausable_init();
        __AccessControlEnumerable_init();

        // 设置代币精度
        _decimals = decimals_;

        // 设置各个角色到不同的地址
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, pauser);
        _grantRole(MINTER_ROLE, minter);
        _grantRole(UPGRADER_ROLE, upgrader);
        _grantRole(FREEZER_ROLE, freezer);
        _grantRole(BLACKLIST_ROLE, blacklister);
    }

    /**
     * @dev 返回代币精度
     * @return 代币精度
     */
    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    /**
     * @dev 检查账户是否被冻结
     * @param account 要检查的账户地址
     * @return 如果账户被冻结返回true
     */
    function isFrozen(address account) public view returns (bool) {
        return _frozenAccounts[account];
    }

    /**
     * @dev 检查账户是否在黑名单中
     * @param account 要检查的账户地址
     * @return 如果账户在黑名单中返回true
     */
    function isBlacklisted(address account) public view returns (bool) {
        return _blacklistedAccounts[account];
    }

    /**
     * @dev 冻结账户
     * @param account 要冻结的账户地址
     */
    function freezeAccount(address account) public onlyRole(FREEZER_ROLE) {
        if (account == address(0)) {
            revert ZeroAddress();
        }
        _frozenAccounts[account] = true;
        emit AccountFrozen(account);
    }

    /**
     * @dev 解冻账户
     * @param account 要解冻的账户地址
     */
    function unfreezeAccount(address account) public onlyRole(FREEZER_ROLE) {
        if (account == address(0)) {
            revert ZeroAddress();
        }
        _frozenAccounts[account] = false;
        emit AccountUnfrozen(account);
    }

    /**
     * @dev 添加地址到黑名单
     * @param account 要添加到黑名单的地址
     */
    function addToBlacklist(address account) public onlyRole(BLACKLIST_ROLE) {
        if (account == address(0)) {
            revert ZeroAddress();
        }
        _blacklistedAccounts[account] = true;
        emit BlacklistAdded(account);
    }

    /**
     * @dev 从黑名单中移除地址
     * @param account 要从黑名单中移除的地址
     */
    function removeFromBlacklist(address account) public onlyRole(BLACKLIST_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        _blacklistedAccounts[account] = false;
        emit BlacklistRemoved(account);
    }

    /**
     * @dev 铸造代币
     * @param to 接收代币的地址
     * @param amount 铸造数量
     */
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        if (to == address(0)) {
            revert ZeroAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        _mint(to, amount);
    }

    /**
     * @dev 销毁代币
     * @param from 销毁代币的地址
     * @param amount 销毁数量
     */
    function burn(address from, uint256 amount) public onlyRole(MINTER_ROLE) {
        if (from == address(0)) {
            revert ZeroAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        _burn(from, amount);
    }

    /**
     * @dev EIP-3009: 查询某个授权 nonce 是否已被使用或取消
     */
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    /**
     * @dev EIP-3009: 凭签名授权执行转账，任何地址都可提交（gas-less / meta-tx）。
     *      转账经由 _update，自动受暂停、冻结、黑名单约束。
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        if (ECDSA.recover(_hashTypedDataV4(structHash), v, r, s) != from) {
            revert InvalidSignature();
        }
        _markAuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }

    /**
     * @dev EIP-3009: 与 transferWithAuthorization 类似，但要求 msg.sender 必须是收款方 `to`，
     *      防止签名在 mempool 中被抢跑改道。
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (to != msg.sender) {
            revert CallerMustBePayee();
        }
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        bytes32 structHash = keccak256(
            abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        if (ECDSA.recover(_hashTypedDataV4(structHash), v, r, s) != from) {
            revert InvalidSignature();
        }
        _markAuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }

    /**
     * @dev EIP-3009: 由授权人签名取消一个尚未使用的 nonce
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (_authorizationStates[authorizer][nonce]) {
            revert AuthorizationUsedOrCanceled();
        }
        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce));
        if (ECDSA.recover(_hashTypedDataV4(structHash), v, r, s) != authorizer) {
            revert InvalidSignature();
        }
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /**
     * @dev EIP-3009 共享校验：时间窗口（严格不等，与 USDC 一致）+ nonce 未被消费
     */
    function _requireValidAuthorization(
        address authorizer,
        bytes32 nonce,
        uint256 validAfter,
        uint256 validBefore
    ) private view {
        if (block.timestamp <= validAfter) {
            revert AuthorizationNotYetValid();
        }
        if (block.timestamp >= validBefore) {
            revert AuthorizationExpired();
        }
        if (_authorizationStates[authorizer][nonce]) {
            revert AuthorizationUsedOrCanceled();
        }
    }

    /**
     * @dev EIP-3009 共享逻辑：标记 nonce 已消费并发出事件
     */
    function _markAuthorizationUsed(address authorizer, bytes32 nonce) private {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }

    /**
     * @dev 暂停合约
     */
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @dev 恢复合约
     */
    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev 授权升级函数
     * @param newImplementation 新实现合约地址
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @dev 转账时的检查，包括暂停、冻结、黑名单检查
     * @param from 发送方地址
     * @param to 接收方地址
     * @param value 转账数量
     */
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override whenNotPaused {
        // 检查冻结状态
        if (from != address(0) && _frozenAccounts[from]) {
            revert EAccountFrozen(from);
        }
        if (to != address(0) && _frozenAccounts[to]) {
            revert EAccountFrozen(to);
        }

        // 检查黑名单状态
        if (from != address(0) && _blacklistedAccounts[from]) {
            revert AccountBlacklisted(from);
        }
        if (to != address(0) && _blacklistedAccounts[to]) {
            revert AccountBlacklisted(to);
        }

        super._update(from, to, value);
    }

    /**
     * @dev 返回合约版本
     */
    function version() public pure returns (string memory) {
        return "1.2.0";
    }

    /**
     * @dev 覆盖nonces函数以解决多重继承冲突
     */
    function nonces(address owner) public view virtual override(ERC20PermitUpgradeable) returns (uint256) {
        return super.nonces(owner);
    }
}