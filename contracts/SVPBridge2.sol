// SPDX-License-Identifier: UNLICENSED

/*
    SVPBridge — 统一跨链桥合约，同时支持 deposit 和 withdrawal，支持多代币。
    两条链各部署一份，backend 监听 Deposit 事件后在对端链提交 withdrawal。

    Deposit 流程：
      ERC20: 用户 approve 后调用 deposit(token, amount)，合约锁定代币并发出 Deposit 事件。
      Native: 用户调用 depositNative() 并通过 msg.value 存入原生代币，事件 token 为 address(0)。

    Withdrawal 流程：
      backend 收集验证者签名后调用 batchedRequestWithdrawals 提交提款请求，
      等待争议期后调用 batchedFinalizeWithdrawals 释放代币。
*/

pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./Signature.sol";

struct ValidatorSet {
  uint64 epoch;
  address[] validators;
  uint64[] powers;
}

struct ValidatorSetUpdateRequest {
  uint64 epoch;
  address[] hotAddresses;
  address[] coldAddresses;
  uint64[] powers;
}

struct PendingValidatorSetUpdate {
  uint64 epoch;
  uint64 totalValidatorPower;
  uint64 updateTime;
  uint64 updateBlockNumber;
  uint64 nValidators;
  bytes32 hotValidatorSetHash;
  bytes32 coldValidatorSetHash;
}

// sourceToken is the asset address on the source chain that was originally
// locked in deposit. We carry it through the withdrawal payload so the
// target chain can enforce its own (sourceChainId, sourceToken → token)
// whitelist (`inboundTokenPairs`), keeping the cold-key safety property
// symmetric on both ends instead of trusting hot validators alone.
// nonce is a bytes32 (NOT uint64) — it must hold the FULL output of
// keccak256(source_chain_name || tx_hash || event_index) computed off-chain
// by the validator backend. Truncating to uint64 historically gave ~10⁻⁸
// collision probability per million deposits AND lost the explicit
// (chain_name, event_index) domain separation in the truncated bits, both
// of which can permanently lock funds if two distinct deposits ever produce
// the same message hash (requestedWithdrawals is a permanent mapping).
// See bridge-backend/internal/withdrawal/generate_signatures.go::nonceForDeposit.
struct BridgeWithdrawal {
  uint64 sourceChainId;
  address sourceToken;
  address user;
  address destination;
  address token;
  uint256 amount;
  bytes32 nonce;
  uint64 requestedTime;
  uint64 requestedBlockNumber;
  bytes32 message;
}

struct BridgeWithdrawalRequest {
  uint64 sourceChainId;
  address sourceToken;
  address user;
  address destination;
  address token;
  uint256 amount;
  bytes32 nonce;
  Signature[] signatures;
}

contract SVPBridge is Pausable, ReentrancyGuard {
  using SafeERC20 for IERC20;

  address public constant NATIVE_TOKEN = address(0);

  bytes32 public hotValidatorSetHash;
  bytes32 public coldValidatorSetHash;
  PendingValidatorSetUpdate public pendingValidatorSetUpdate;

  mapping(bytes32 => bool) public usedMessages;
  mapping(address => bool) public lockers;
  address[] private lockersVotingLock;
  uint64 public lockerThreshold;

  mapping(address => bool) public finalizers;
  uint64 public epoch;
  uint64 public totalValidatorPower;
  uint64 public disputePeriodSeconds;
  uint64 public blockDurationMillis;
  uint64 public nValidators;

  mapping(address => bool) public supportedTokens;

  // Multi-chain routing whitelists (governed by cold validator set).
  // allowedTargetChains: which chainIds this contract will accept deposits "to"
  //   (i.e. user wants funds released on chainId X — only enabled if X is here).
  // allowedSourceChains: which chainIds this contract will accept withdrawals "from"
  //   (i.e. backend claims a deposit happened on chainId X — only honored if X is here).
  // sourceChainId is also folded into the withdrawal message hash so that the same
  // signed payload cannot be replayed across two chains that share a validator set.
  mapping(uint64 => bool) public allowedTargetChains;
  mapping(uint64 => bool) public allowedSourceChains;

  // Two cold-key token-pair whitelists, one for each leg of bridging:
  //
  // outboundTokenPairs: governs `deposit()` on THIS chain (we're the source).
  //   Key  = keccak256(abi.encode(sourceToken, targetChainId, targetToken))
  //   Why  = if a user supplies a wrong targetToken, funds would lock here
  //          (backend rejects the pair, no withdrawal is ever signed).
  //
  // inboundTokenPairs:  governs `_requestWithdrawal()` on THIS chain (we're the target).
  //   Key  = keccak256(abi.encode(sourceChainId, sourceToken, targetToken))
  //   Why  = defense-in-depth against hot-validator compromise. Without this,
  //          a hot-key quorum could finalize any (allowedSourceChain × supportedToken)
  //          combination, draining the contract for token pairs that were never
  //          intended to bridge. With this check, cold-key governance bounds the
  //          blast radius to pairs explicitly approved per (sourceChain, srcToken,
  //          targetToken) triple.
  //
  // The keys are intentionally NOT symmetric: each chain stores entries from
  // its own perspective ("from me to X" vs. "into me from Y"), so the same
  // logical pair becomes two on-chain entries on two different chains.
  mapping(bytes32 => bool) public outboundTokenPairs;
  mapping(bytes32 => bool) public inboundTokenPairs;

  mapping(bytes32 => BridgeWithdrawal) public requestedWithdrawals;
  mapping(bytes32 => bool) public finalizedWithdrawals;
  mapping(bytes32 => bool) public withdrawalsInvalidated;

  bytes32 immutable domainSeparator;

  receive() external payable {}

  // ─── Events: Deposit ────────────────────────────────────────────────────
  // targetChainId / targetToken / destination are user-declared routing
  // intent — the backend validates them against bridge_routes +
  // token_pairs before producing a withdrawal on the destination chain.
  //   targetToken = address(0) → "give me native on the target chain".
  //   destination               → the recipient address on the target chain.
  //                               Indexed so backends / indexers can filter
  //                               "all bridge deposits inbound to addr X".
  // The withdrawal side already keys on `destination` (see
  // BridgeWithdrawal.destination + _transferOut), so emitting it here
  // closes the loop: an off-chain relayer reads source-chain Deposit
  // events and forwards the SAME destination into _requestWithdrawal,
  // and the validators sign over it as part of the message hash.
  event Deposit(
    address indexed user,
    address indexed token,
    uint256 amount,
    uint64 targetChainId,
    address targetToken,
    address indexed destination
  );

  // ─── Events: Withdrawal ─────────────────────────────────────────────────
  // sourceChainId / sourceToken identify the deposit-side asset on the
  // originating chain. Both participate in the withdrawal message hash, so a
  // signature scoped to (sourceChain=A, sourceToken=X → token=Y) cannot be
  // replayed for any other tuple — neither across chains nor across assets.
  event RequestedWithdrawal(
    uint64 sourceChainId,
    address sourceToken,
    address indexed user, address destination,
    address token, uint256 amount, bytes32 nonce, bytes32 message, uint64 requestedTime
  );
  event FinalizedWithdrawal(
    uint64 sourceChainId,
    address sourceToken,
    address indexed user, address destination,
    address token, uint256 amount, bytes32 nonce, bytes32 message
  );
  event FailedWithdrawal(bytes32 message, uint32 errorCode);
  event InvalidatedWithdrawal(BridgeWithdrawal withdrawal);

  // ─── Events: Validator Set ──────────────────────────────────────────────
  event RequestedValidatorSetUpdate(
    uint64 epoch, bytes32 hotValidatorSetHash,
    bytes32 coldValidatorSetHash, uint64 updateTime
  );
  event FinalizedValidatorSetUpdate(
    uint64 epoch, bytes32 hotValidatorSetHash, bytes32 coldValidatorSetHash
  );

  // ─── Events: Admin ─────────────────────────────────────────────────────
  event ModifiedLocker(address indexed locker, bool isLocker);
  event ModifiedFinalizer(address indexed finalizer, bool isFinalizer);
  event ChangedDisputePeriodSeconds(uint64 newDisputePeriodSeconds);
  event ChangedBlockDurationMillis(uint64 newBlockDurationMillis);
  event ChangedLockerThreshold(uint64 newLockerThreshold);
  event TokenAdded(address indexed token);
  event TokenRemoved(address indexed token);
  event ModifiedAllowedTargetChain(uint64 indexed targetChainId, bool allowed);
  event ModifiedAllowedSourceChain(uint64 indexed sourceChainId, bool allowed);
  event ModifiedOutboundTokenPair(
    address indexed sourceToken,
    uint64 indexed targetChainId,
    address indexed targetToken,
    bool allowed
  );
  event ModifiedInboundTokenPair(
    uint64 indexed sourceChainId,
    address indexed sourceToken,
    address indexed targetToken,
    bool allowed
  );

  constructor(
    address[] memory hotAddresses,
    address[] memory coldAddresses,
    uint64[] memory powers,
    uint64 _disputePeriodSeconds,
    uint64 _blockDurationMillis,
    uint64 _lockerThreshold
  ) {
    domainSeparator = makeDomainSeparator();
    totalValidatorPower = _checkNewValidatorPowers(powers);

    require(hotAddresses.length == coldAddresses.length, "Hot and cold validator sets length mismatch");
    nValidators = uint64(hotAddresses.length);

    ValidatorSet memory hotVS = ValidatorSet({ epoch: 0, validators: hotAddresses, powers: powers });
    bytes32 newHotHash = _makeValidatorSetHash(hotVS);
    hotValidatorSetHash = newHotHash;

    ValidatorSet memory coldVS = ValidatorSet({ epoch: 0, validators: coldAddresses, powers: powers });
    bytes32 newColdHash = _makeValidatorSetHash(coldVS);
    coldValidatorSetHash = newColdHash;

    disputePeriodSeconds = _disputePeriodSeconds;
    blockDurationMillis = _blockDurationMillis;
    lockerThreshold = _lockerThreshold;
    _addLockersAndFinalizers(hotAddresses);

    emit RequestedValidatorSetUpdate(0, hotValidatorSetHash, coldValidatorSetHash, uint64(block.timestamp));

    pendingValidatorSetUpdate = PendingValidatorSetUpdate({
      epoch: 0, totalValidatorPower: totalValidatorPower,
      updateTime: 0, updateBlockNumber: uint64(block.number),
      hotValidatorSetHash: hotValidatorSetHash, coldValidatorSetHash: coldValidatorSetHash,
      nValidators: nValidators
    });

    emit FinalizedValidatorSetUpdate(0, hotValidatorSetHash, coldValidatorSetHash);
  }

  // ─── Deposit ──────────────────────────────────────────────────────────────

  // deposit ERC20 across chains.
  //
  // targetChainId : EVM chain id of the destination chain. Must be in
  //                 allowedTargetChains and must not equal this chain.
  // targetToken   : Address the user wants to receive on the destination chain.
  //                 address(0) = native on destination. Validated via
  //                 _checkOutboundPair against the cold-whitelisted pair set.
  // destination   : Recipient address on the target chain. Bound into the
  //                 withdrawal message hash by the backend → validators sign
  //                 over it, so it cannot be rewritten after the deposit.
  //                 Explicit (not defaulted to msg.sender) to keep the
  //                 cross-chain transfer intent visible on-chain.
  function deposit(
    address token,
    uint256 amount,
    uint64 targetChainId,
    address targetToken,
    address destination
  ) external nonReentrant whenNotPaused {
    require(token != NATIVE_TOKEN, "Use depositNative for native token");
    require(supportedTokens[token], "Token not supported");
    require(amount > 0, "Amount must be > 0");
    require(destination != address(0), "destination is zero");
    _checkTargetChain(targetChainId);
    _checkOutboundPair(token, targetChainId, targetToken);
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    emit Deposit(msg.sender, token, amount, targetChainId, targetToken, destination);
  }

  function depositNative(
    uint64 targetChainId,
    address targetToken,
    address destination
  ) external payable nonReentrant whenNotPaused {
    require(supportedTokens[NATIVE_TOKEN], "Token not supported");
    require(msg.value > 0, "Amount must be > 0");
    require(destination != address(0), "destination is zero");
    _checkTargetChain(targetChainId);
    _checkOutboundPair(NATIVE_TOKEN, targetChainId, targetToken);
    emit Deposit(msg.sender, NATIVE_TOKEN, msg.value, targetChainId, targetToken, destination);
  }

  function _checkTargetChain(uint64 targetChainId) private view {
    require(targetChainId != 0, "targetChainId is zero");
    require(uint256(targetChainId) != block.chainid, "Target chain cannot be self");
    require(allowedTargetChains[targetChainId], "Target chain not allowed");
  }

  // Outbound: invoked on the SOURCE chain at deposit time. The implicit
  // dimension is "this chain == sourceChain", so we key only on the
  // remaining three fields.
  function _checkOutboundPair(
    address sourceToken,
    uint64 targetChainId,
    address targetToken
  ) private view {
    require(
      outboundTokenPairs[_outboundKey(sourceToken, targetChainId, targetToken)],
      "Token pair not allowed (outbound)"
    );
  }

  function _outboundKey(
    address sourceToken,
    uint64 targetChainId,
    address targetToken
  ) private pure returns (bytes32) {
    return keccak256(abi.encode(sourceToken, targetChainId, targetToken));
  }

  // Inbound: invoked on the TARGET chain at withdrawal-request time. The
  // implicit dimension is "this chain == targetChain", so we key on
  // sourceChainId + sourceToken + targetToken (the local release token).
  function _checkInboundPair(
    uint64 sourceChainId,
    address sourceToken,
    address targetToken
  ) private view {
    require(
      inboundTokenPairs[_inboundKey(sourceChainId, sourceToken, targetToken)],
      "Token pair not allowed (inbound)"
    );
  }

  function _inboundKey(
    uint64 sourceChainId,
    address sourceToken,
    address targetToken
  ) private pure returns (bytes32) {
    return keccak256(abi.encode(sourceChainId, sourceToken, targetToken));
  }

  // ─── Withdrawal ───────────────────────────────────────────────────────────

  function batchedRequestWithdrawals(
    BridgeWithdrawalRequest[] memory withdrawalRequests,
    ValidatorSet calldata hotVS
  ) external nonReentrant whenNotPaused {
    uint64 end = uint64(withdrawalRequests.length);
    for (uint64 idx; idx < end; idx++) {
      BridgeWithdrawalRequest memory wr = withdrawalRequests[idx];
      _requestWithdrawal(
        wr.sourceChainId, wr.sourceToken,
        wr.user, wr.destination, wr.token, wr.amount, wr.nonce,
        hotVS, wr.signatures
      );
    }
  }

  function batchedFinalizeWithdrawals(
    bytes32[] calldata messages
  ) external nonReentrant whenNotPaused {
    _checkFinalizer(msg.sender);
    uint64 end = uint64(messages.length);
    for (uint64 idx; idx < end; idx++) {
      _finalizeWithdrawal(messages[idx]);
    }
  }

  function invalidateWithdrawals(
    bytes32[] memory messages, uint64 nonce,
    ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    bytes32 data = keccak256(abi.encode("invalidateWithdrawals", messages, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    uint64 end = uint64(messages.length);
    for (uint64 idx; idx < end; idx++) {
      withdrawalsInvalidated[messages[idx]] = true;
      emit InvalidatedWithdrawal(requestedWithdrawals[messages[idx]]);
    }
  }

  // ─── Token Management ────────────────────────────────────────────────────

  function addSupportedToken(
    address token, uint64 nonce,
    ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    bytes32 data = keccak256(abi.encode("addSupportedToken", token, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    supportedTokens[token] = true;
    emit TokenAdded(token);
  }

  function removeSupportedToken(
    address token, uint64 nonce,
    ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    bytes32 data = keccak256(abi.encode("removeSupportedToken", token, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    supportedTokens[token] = false;
    emit TokenRemoved(token);
  }

  // ─── Route Whitelist Management ───────────────────────────────────────────

  // Authorize / revoke a destination chain id for outgoing deposits.
  // Cold-key governed: opening a new route is as sensitive as token support.
  function modifyAllowedTargetChain(
    uint64 targetChainId, bool allowed, uint64 nonce,
    ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    require(targetChainId != 0, "targetChainId is zero");
    require(uint256(targetChainId) != block.chainid, "Target chain cannot be self");
    bytes32 data = keccak256(abi.encode("modifyAllowedTargetChain", targetChainId, allowed, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    allowedTargetChains[targetChainId] = allowed;
    emit ModifiedAllowedTargetChain(targetChainId, allowed);
  }

  // Authorize / revoke a source chain id for incoming withdrawals.
  function modifyAllowedSourceChain(
    uint64 sourceChainId, bool allowed, uint64 nonce,
    ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    require(sourceChainId != 0, "sourceChainId is zero");
    require(uint256(sourceChainId) != block.chainid, "Source chain cannot be self");
    bytes32 data = keccak256(abi.encode("modifyAllowedSourceChain", sourceChainId, allowed, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    allowedSourceChains[sourceChainId] = allowed;
    emit ModifiedAllowedSourceChain(sourceChainId, allowed);
  }

  // Authorize / revoke an OUTBOUND (sourceToken, targetChainId, targetToken)
  // pair on this chain. Required before deposit() will accept the combination.
  //
  // We deliberately do NOT require sourceToken in supportedTokens here, because
  // supportedTokens governs both deposit (this chain accepts the asset) and
  // finalize (this chain releases the asset). A new outbound route can be
  // opened in parallel with adding token support; the deposit-time check
  // still requires supportedTokens[sourceToken].
  function modifyOutboundTokenPair(
    address sourceToken,
    uint64 targetChainId,
    address targetToken,
    bool allowed,
    uint64 nonce,
    ValidatorSet memory coldVS,
    Signature[] memory sigs
  ) external {
    require(targetChainId != 0, "targetChainId is zero");
    require(uint256(targetChainId) != block.chainid, "Target chain cannot be self");
    bytes32 data = keccak256(abi.encode(
      "modifyOutboundTokenPair", sourceToken, targetChainId, targetToken, allowed, nonce
    ));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    outboundTokenPairs[_outboundKey(sourceToken, targetChainId, targetToken)] = allowed;
    emit ModifiedOutboundTokenPair(sourceToken, targetChainId, targetToken, allowed);
  }

  // Authorize / revoke an INBOUND (sourceChainId, sourceToken, targetToken)
  // pair on this chain. Required before requestWithdrawal will accept a
  // withdrawal claiming to originate from this triple.
  //
  // Mirror of modifyOutboundTokenPair on the receiving side. Together they
  // make the cold-key whitelist symmetric: every cross-chain pair needs two
  // governance txs (outbound on the source chain, inbound on the target chain)
  // before user-facing bridging is possible.
  function modifyInboundTokenPair(
    uint64 sourceChainId,
    address sourceToken,
    address targetToken,
    bool allowed,
    uint64 nonce,
    ValidatorSet memory coldVS,
    Signature[] memory sigs
  ) external {
    require(sourceChainId != 0, "sourceChainId is zero");
    require(uint256(sourceChainId) != block.chainid, "Source chain cannot be self");
    bytes32 data = keccak256(abi.encode(
      "modifyInboundTokenPair", sourceChainId, sourceToken, targetToken, allowed, nonce
    ));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    inboundTokenPairs[_inboundKey(sourceChainId, sourceToken, targetToken)] = allowed;
    emit ModifiedInboundTokenPair(sourceChainId, sourceToken, targetToken, allowed);
  }

  // ─── Validator Set Management ─────────────────────────────────────────────

  function updateValidatorSet(
    ValidatorSetUpdateRequest memory newVS,
    ValidatorSet memory activeHotVS,
    Signature[] memory signatures
  ) external whenNotPaused {
    require(
      _makeValidatorSetHash(activeHotVS) == hotValidatorSetHash,
      "Supplied active validators and powers do not match checkpoint"
    );
    bytes32 data = keccak256(
      abi.encode("updateValidatorSet", newVS.epoch, newVS.hotAddresses, newVS.coldAddresses, newVS.powers)
    );
    bytes32 message = _makeMessage(data);
    _updateValidatorSetInner(newVS, activeHotVS, signatures, message, false);
  }

  function finalizeValidatorSetUpdate() external nonReentrant whenNotPaused {
    _checkFinalizer(msg.sender);
    require(pendingValidatorSetUpdate.updateTime != 0, "Pending validator set update already finalized");
    uint32 errorCode = _getDisputePeriodErrorCode(
      pendingValidatorSetUpdate.updateTime, pendingValidatorSetUpdate.updateBlockNumber
    );
    require(errorCode == 0, "Still in dispute period");
    _finalizeValidatorSetUpdateInner();
  }

  // ─── Locker / Finalizer / Emergency ───────────────────────────────────────

  function modifyLocker(
    address locker, bool _isLocker, uint64 nonce,
    ValidatorSet calldata activeVS, Signature[] memory signatures
  ) external {
    bytes32 data = keccak256(abi.encode("modifyLocker", locker, _isLocker, nonce));
    bytes32 message = _makeMessage(data);
    bytes32 vsHash = _isLocker ? hotValidatorSetHash : coldValidatorSetHash;
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, activeVS, signatures, vsHash);
    if (lockers[locker] && !_isLocker && !paused()) { _removeLockerVote(locker); }
    lockers[locker] = _isLocker;
    emit ModifiedLocker(locker, _isLocker);
  }

  function modifyFinalizer(
    address finalizer, bool _isFinalizer, uint64 nonce,
    ValidatorSet calldata activeVS, Signature[] memory signatures
  ) external {
    bytes32 data = keccak256(abi.encode("modifyFinalizer", finalizer, _isFinalizer, nonce));
    bytes32 message = _makeMessage(data);
    bytes32 vsHash = _isFinalizer ? hotValidatorSetHash : coldValidatorSetHash;
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, activeVS, signatures, vsHash);
    finalizers[finalizer] = _isFinalizer;
    emit ModifiedFinalizer(finalizer, _isFinalizer);
  }

  function voteEmergencyLock() external {
    require(lockers[msg.sender], "Sender is not authorized to lock smart contract");
    require(!_isVotingLock(msg.sender), "Locker already voted for emergency lock");
    lockersVotingLock.push(msg.sender);
    if (uint64(lockersVotingLock.length) >= lockerThreshold && !paused()) { _pause(); }
  }

  function unvoteEmergencyLock() external whenNotPaused {
    require(lockers[msg.sender], "Sender is not authorized to lock smart contract");
    require(_isVotingLock(msg.sender), "Locker is not currently voting for emergency lock");
    _removeLockerVote(msg.sender);
  }

  function emergencyUnlock(
    ValidatorSetUpdateRequest memory newVS,
    ValidatorSet calldata activeColdVS,
    Signature[] calldata signatures,
    uint64 nonce
  ) external whenPaused {
    bytes32 data = keccak256(
      abi.encode("unlock", newVS.epoch, newVS.hotAddresses, newVS.coldAddresses, newVS.powers, nonce)
    );
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _updateValidatorSetInner(newVS, activeColdVS, signatures, message, true);
    _finalizeValidatorSetUpdateInner();
    delete lockersVotingLock;
    _unpause();
  }

  function changeDisputePeriodSeconds(
    uint64 val, uint64 nonce, ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    bytes32 data = keccak256(abi.encode("changeDisputePeriodSeconds", val, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    disputePeriodSeconds = val;
    emit ChangedDisputePeriodSeconds(val);
  }

  function changeBlockDurationMillis(
    uint64 val, uint64 nonce, ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    bytes32 data = keccak256(abi.encode("changeBlockDurationMillis", val, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    blockDurationMillis = val;
    emit ChangedBlockDurationMillis(val);
  }

  function changeLockerThreshold(
    uint64 val, uint64 nonce, ValidatorSet memory coldVS, Signature[] memory sigs
  ) external {
    bytes32 data = keccak256(abi.encode("changeLockerThreshold", val, nonce));
    bytes32 message = _makeMessage(data);
    _checkMessageNotUsed(message);
    _checkValidatorSignatures(message, coldVS, sigs, coldValidatorSetHash);
    lockerThreshold = val;
    if (uint64(lockersVotingLock.length) >= lockerThreshold && !paused()) { _pause(); }
    emit ChangedLockerThreshold(val);
  }

  function getLockersVotingLock() external view returns (address[] memory) { return lockersVotingLock; }

  // ─── Internal: Withdrawal ─────────────────────────────────────────────────

  function _requestWithdrawal(
    uint64 sourceChainId,
    address sourceToken,
    address user, address destination, address token, uint256 amount, bytes32 nonce,
    ValidatorSet calldata hotVS, Signature[] memory signatures
  ) internal {
    // Defense layers, in order of priority:
    //   1. allowedSourceChains[sourceChainId]    — chain-level cold whitelist
    //   2. inboundTokenPairs[(srcChain, srcTok, releaseTok)] — pair-level cold whitelist
    //   3. hot validator quorum signature
    //   4. message-hash uniqueness (replay)
    // Layers 1 & 2 are cold-key governed: even with a fully compromised
    // hot validator set, an attacker cannot release tokens for any pair
    // that wasn't explicitly approved by cold quorum here.
    //
    // Both sourceChainId AND sourceToken are bound into the message hash,
    // so a signed (sourceChain=A, sourceToken=X → token=Y) payload cannot
    // be reused for any (B, Z → Y), (A, Z → Y), or (A, X → W) tuple.
    require(allowedSourceChains[sourceChainId], "Source chain not allowed");
    _checkInboundPair(sourceChainId, sourceToken, token);

    bytes32 data = keccak256(abi.encode(
      "requestWithdrawal", sourceChainId, sourceToken, user, destination, token, amount, nonce
    ));
    bytes32 message = _makeMessage(data);
    if (!_isValidWithdrawal(message)) { emit FailedWithdrawal(message, 5); return; }

    BridgeWithdrawal memory w = BridgeWithdrawal({
      sourceChainId: sourceChainId,
      sourceToken: sourceToken,
      user: user, destination: destination, token: token, amount: amount, nonce: nonce,
      requestedTime: uint64(block.timestamp), requestedBlockNumber: uint64(block.number),
      message: message
    });
    if (requestedWithdrawals[message].requestedTime != 0) { emit FailedWithdrawal(message, 0); return; }

    _checkValidatorSignatures(message, hotVS, signatures, hotValidatorSetHash);
    requestedWithdrawals[message] = w;
    emit RequestedWithdrawal(
      w.sourceChainId, w.sourceToken,
      w.user, w.destination, w.token, w.amount, w.nonce, w.message, w.requestedTime
    );
  }

  function _finalizeWithdrawal(bytes32 message) internal {
    if (!_isValidWithdrawal(message)) { emit FailedWithdrawal(message, 5); return; }
    if (finalizedWithdrawals[message]) { emit FailedWithdrawal(message, 1); return; }

    BridgeWithdrawal memory w = requestedWithdrawals[message];
    if (w.requestedTime == 0) { emit FailedWithdrawal(message, 2); return; }

    uint32 errorCode = _getDisputePeriodErrorCode(w.requestedTime, w.requestedBlockNumber);
    if (errorCode != 0) { emit FailedWithdrawal(message, errorCode); return; }

    finalizedWithdrawals[message] = true;
    require(supportedTokens[w.token], "Token not supported");
    _transferOut(w.token, w.destination, w.amount);
    emit FinalizedWithdrawal(
      w.sourceChainId, w.sourceToken,
      w.user, w.destination, w.token, w.amount, w.nonce, w.message
    );
  }

  function _isValidWithdrawal(bytes32 message) private view returns (bool) {
    return !withdrawalsInvalidated[message];
  }

  function _transferOut(address token, address destination, uint256 amount) private {
    if (token == NATIVE_TOKEN) {
      (bool sent, ) = payable(destination).call{ value: amount }("");
      require(sent, "Native transfer failed");
      return;
    }
    IERC20(token).safeTransfer(destination, amount);
  }

  // ─── Internal: Validator ──────────────────────────────────────────────────

  function _addLockersAndFinalizers(address[] memory addrs) private {
    for (uint64 i; i < addrs.length; i++) {
      lockers[addrs[i]] = true;
      finalizers[addrs[i]] = true;
    }
  }

  function _makeValidatorSetHash(ValidatorSet memory vs) private pure returns (bytes32) {
    require(vs.validators.length == vs.powers.length, "Malformed validator set");
    return keccak256(abi.encode(vs.validators, vs.powers, vs.epoch));
  }

  function _checkValidatorSignatures(
    bytes32 message, ValidatorSet memory activeVS,
    Signature[] memory signatures, bytes32 vsHash
  ) private view {
    require(_makeValidatorSetHash(activeVS) == vsHash, "Supplied validators do not match checkpoint");
    uint64 nSigs = uint64(signatures.length);
    require(nSigs > 0, "Signers empty");
    uint64 cumPower;
    uint64 sigIdx;
    uint64 end = uint64(activeVS.validators.length);
    for (uint64 i; i < end; i++) {
      address signer = recoverSigner(message, signatures[sigIdx], domainSeparator);
      if (signer == activeVS.validators[i]) {
        cumPower += activeVS.powers[i];
        if (3 * cumPower > 2 * totalValidatorPower) break;
        sigIdx += 1;
        if (sigIdx >= nSigs) break;
      }
    }
    require(3 * cumPower > 2 * totalValidatorPower, "Not enough validator power");
  }

  function _checkMessageNotUsed(bytes32 message) private {
    require(!usedMessages[message], "message already used");
    usedMessages[message] = true;
  }

  function _makeMessage(bytes32 data) private view returns (bytes32) {
    Agent memory agent = Agent("a", keccak256(abi.encode(address(this), data)));
    return hash(agent);
  }

  function _checkFinalizer(address f) private view {
    require(finalizers[f], "Sender is not a finalizer");
  }

  function _checkNewValidatorPowers(uint64[] memory powers) private pure returns (uint64) {
    uint64 cum;
    for (uint64 i; i < powers.length; i++) { cum += powers[i]; }
    require(cum > 0, "Submitted validator powers must be greater than zero");
    return cum;
  }

  function _getDisputePeriodErrorCode(uint64 time, uint64 blockNumber) private view returns (uint32) {
    if (!(block.timestamp > time + disputePeriodSeconds)) return 3;
    uint64 cur = uint64(block.number);
    if (!((cur - blockNumber) * blockDurationMillis > 1000 * disputePeriodSeconds)) return 4;
    return 0;
  }

  function _updateValidatorSetInner(
    ValidatorSetUpdateRequest memory newVS,
    ValidatorSet memory activeVS,
    Signature[] memory signatures,
    bytes32 message,
    bool useCold
  ) private {
    require(newVS.hotAddresses.length == newVS.coldAddresses.length, "Hot/cold length mismatch");
    require(newVS.hotAddresses.length == newVS.powers.length, "Powers length mismatch");
    require(newVS.epoch > activeVS.epoch, "Epoch must be greater");
    uint64 newTotal = _checkNewValidatorPowers(newVS.powers);
    bytes32 vsHash = useCold ? coldValidatorSetHash : hotValidatorSetHash;
    _checkValidatorSignatures(message, activeVS, signatures, vsHash);

    ValidatorSet memory newHot = ValidatorSet({ epoch: newVS.epoch, validators: newVS.hotAddresses, powers: newVS.powers });
    ValidatorSet memory newCold = ValidatorSet({ epoch: newVS.epoch, validators: newVS.coldAddresses, powers: newVS.powers });
    bytes32 newHotHash = _makeValidatorSetHash(newHot);
    bytes32 newColdHash = _makeValidatorSetHash(newCold);

    pendingValidatorSetUpdate = PendingValidatorSetUpdate({
      epoch: newVS.epoch, totalValidatorPower: newTotal,
      updateTime: uint64(block.timestamp), updateBlockNumber: uint64(block.number),
      hotValidatorSetHash: newHotHash, coldValidatorSetHash: newColdHash,
      nValidators: uint64(newHot.validators.length)
    });
    emit RequestedValidatorSetUpdate(newVS.epoch, newHotHash, newColdHash, uint64(block.timestamp));
  }

  function _finalizeValidatorSetUpdateInner() private {
    hotValidatorSetHash = pendingValidatorSetUpdate.hotValidatorSetHash;
    coldValidatorSetHash = pendingValidatorSetUpdate.coldValidatorSetHash;
    epoch = pendingValidatorSetUpdate.epoch;
    totalValidatorPower = pendingValidatorSetUpdate.totalValidatorPower;
    nValidators = pendingValidatorSetUpdate.nValidators;
    pendingValidatorSetUpdate.updateTime = 0;
    emit FinalizedValidatorSetUpdate(epoch, hotValidatorSetHash, coldValidatorSetHash);
  }

  function _isVotingLock(address locker) private view returns (bool) {
    for (uint64 i; i < lockersVotingLock.length; i++) {
      if (lockersVotingLock[i] == locker) return true;
    }
    return false;
  }

  function _removeLockerVote(address locker) private whenNotPaused {
    require(lockers[locker], "Not authorized");
    uint64 length = uint64(lockersVotingLock.length);
    for (uint64 i; i < length; i++) {
      if (lockersVotingLock[i] == locker) {
        lockersVotingLock[i] = lockersVotingLock[length - 1];
        lockersVotingLock.pop();
        break;
      }
    }
  }
}
