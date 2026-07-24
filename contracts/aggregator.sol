// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IOffChainAggregator.sol";
import "../interfaces/IReporterRegistry.sol";
import "../libraries/MedianLib.sol";

/// @title Per-asset price feed with multi-reporter median aggregation
contract OffChainAggregator is IOffChainAggregator {
    IReporterRegistry public immutable reporterRegistry;

    string private _description;
    uint8 private _decimals;
    uint256 public immutable minTransmitters;
    uint256 public immutable deviationThresholdBps;

    uint80 private _roundId;
    int256 private _latestAnswer;
    uint256 private _latestTimestamp;

    mapping(uint80 => int256) private _answers;
    mapping(uint80 => uint256) private _timestamps;
    mapping(uint80 => uint256) private _startedAt;

    uint80 private _submissionRound;
    mapping(address => int256) private _submissions;
    mapping(address => bool) private _hasSubmitted;
    uint256 private _submissionCount;

    event AnswerUpdated(int256 indexed answer, uint80 indexed roundId, uint256 updatedAt);
    event TransmissionReceived(address indexed reporter, int256 answer, uint80 roundId);

    error NotReporter();
    error AlreadySubmitted();
    error InvalidAnswer();

    constructor(
        address registry,
        string memory description_,
        uint8 decimals_,
        uint256 minTransmitters_,
        uint256 deviationThresholdBps_
    ) {
        require(registry != address(0), "zero registry");
        require(minTransmitters_ > 0, "min transmitters zero");

        reporterRegistry = IReporterRegistry(registry);
        _description = description_;
        _decimals = decimals_;
        minTransmitters = minTransmitters_;
        deviationThresholdBps = deviationThresholdBps_;
        _submissionRound = 1;
    }

    function transmit(int256 answer) external {
        if (!reporterRegistry.isReporter(msg.sender)) revert NotReporter();
        if (answer <= 0) revert InvalidAnswer();
        if (_hasSubmitted[msg.sender]) revert AlreadySubmitted();

        _hasSubmitted[msg.sender] = true;
        _submissions[msg.sender] = answer;
        _submissionCount++;

        emit TransmissionReceived(msg.sender, answer, _submissionRound);

        if (_submissionCount >= minTransmitters) {
            _finalizeRound();
        }
    }

    function _finalizeRound() private {
        int256[] memory values = new int256[](_submissionCount);
        uint256 idx = 0;

        address[] memory reporters = _getCurrentReporters();
        for (uint256 i = 0; i < reporters.length; i++) {
            if (_hasSubmitted[reporters[i]]) {
                values[idx] = _submissions[reporters[i]];
                idx++;
            }
        }

        int256 medianValue = MedianLib.median(values);
        int256[] memory filtered = MedianLib.filterByDeviation(
            values,
            medianValue,
            deviationThresholdBps
        );

        int256 finalAnswer = filtered.length > 0
            ? MedianLib.median(filtered)
            : medianValue;

        _roundId = _submissionRound;
        _latestAnswer = finalAnswer;
        _latestTimestamp = block.timestamp;
        _answers[_roundId] = finalAnswer;
        _timestamps[_roundId] = block.timestamp;
        _startedAt[_roundId] = block.timestamp;

        emit AnswerUpdated(finalAnswer, _roundId, block.timestamp);

        _resetSubmissions();
        _submissionRound++;
    }

    function _resetSubmissions() private {
        address[] memory reporters = _getCurrentReporters();
        for (uint256 i = 0; i < reporters.length; i++) {
            delete _hasSubmitted[reporters[i]];
            delete _submissions[reporters[i]];
        }
        _submissionCount = 0;
    }

    function _getCurrentReporters() private view returns (address[] memory) {
        uint256 count = reporterRegistry.reporterCount();
        address[] memory reporters = new address[](count);
        ReporterRegistryExt registry = ReporterRegistryExt(
            address(reporterRegistry)
        );
        for (uint256 i = 0; i < count; i++) {
            reporters[i] = registry.getReporterAt(i);
        }
        return reporters;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function description() external view returns (string memory) {
        return _description;
    }

    function version() external pure returns (uint256) {
        return 1;
    }

    function latestAnswer() external view returns (int256) {
        return _latestAnswer;
    }

    function latestTimestamp() external view returns (uint256) {
        return _latestTimestamp;
    }

    function latestRound() external view returns (uint256) {
        return _roundId;
    }

    function getAnswer(uint256 roundId) external view returns (int256) {
        return _answers[uint80(roundId)];
    }

    function getTimestamp(uint256 roundId) external view returns (uint256) {
        return _timestamps[uint80(roundId)];
    }

    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (
            _roundId,
            _latestAnswer,
            _startedAt[_roundId],
            _latestTimestamp,
            _roundId
        );
    }

    function getRoundData(
        uint80 roundId_
    )
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (
            roundId_,
            _answers[roundId_],
            _startedAt[roundId_],
            _timestamps[roundId_],
            roundId_
        );
    }
}

interface ReporterRegistryExt {
    function getReporterAt(uint256 index) external view returns (address);
}
