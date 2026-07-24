// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "../interfaces/IReporterRegistry.sol";

/// @title Reporter whitelist registry
contract ReporterRegistry is IReporterRegistry, Ownable {
    mapping(address => bool) private _isActiveReporter;
    address[] private _reporters;

    event ReporterAdded(address indexed reporter);
    event ReporterRemoved(address indexed reporter);
    event ReporterStatusChanged(address indexed reporter, bool active);

    constructor(address initialOwner) Ownable(initialOwner) {}

    function addReporter(address reporter) external onlyOwner {
        require(reporter != address(0), "zero address");
        require(!_isActiveReporter[reporter], "already reporter");

        _isActiveReporter[reporter] = true;
        _reporters.push(reporter);

        emit ReporterAdded(reporter);
    }

    function removeReporter(address reporter) external onlyOwner {
        require(_isActiveReporter[reporter], "not reporter");

        _isActiveReporter[reporter] = false;

        for (uint256 i = 0; i < _reporters.length; i++) {
            if (_reporters[i] == reporter) {
                _reporters[i] = _reporters[_reporters.length - 1];
                _reporters.pop();
                break;
            }
        }

        emit ReporterRemoved(reporter);
    }

    function setReporterActive(address reporter, bool active) external onlyOwner {
        require(reporter != address(0), "zero address");
        _isActiveReporter[reporter] = active;
        emit ReporterStatusChanged(reporter, active);
    }

    function isReporter(address reporter) external view returns (bool) {
        return _isActiveReporter[reporter];
    }

    function reporterCount() external view returns (uint256) {
        return _reporters.length;
    }

    function getReporterAt(uint256 index) external view returns (address) {
        return _reporters[index];
    }
}
