// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

interface IGuardianRegistry {
    // Minimal reads used by trap — replace with real registry ABI when integrating
    function pendingRecoveries() external view returns (uint256);
    function averageGuardianVotes() external view returns (uint256);
}

interface ISSV {
    function getOperatorMisses(address operator) external view returns (uint256);
}

interface IResponse {
    function executeResponse(bytes calldata payload) external;
}

contract SSVGuardianTrap is ITrap {
    address public owner;
    address public guardianRegistry;
    address public ssv;
    address public responseContract;

    // thresholds (owner-set) — included in collect() blob so shouldRespond remains pure
    uint256 public pendingRecoveriesThreshold; // e.g., 3
    uint256 public avgGuardianVotesThresholdBp; // in basis points, e.g., 3000 = 30%
    uint256 public triggerRiskBp; // 0..10000

    struct Snapshot {
        uint256 blockNum;
        uint256 ts;
        uint256 pendingRecoveries;
        uint256 avgGuardianVotesBp;
        uint256 operatorMisses;
        uint256 risk;
    }
    Snapshot[] public snapshots;

    event Collected(uint256 indexed blockNum, uint256 pendingRecoveries, uint256 avgGuardianVotesBp, uint256 operatorMisses);
    event RespondTriggered(uint256 indexed blockNum, uint256 risk, string action);
    event Initialized(address owner, address guardianRegistry, address ssv, address response);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        require(msg.sender == owner, "SSVGuardianTrap: only owner");
    }

    function initialize(
        address _owner,
        address _guardianRegistry,
        address _ssv,
        address _response
    ) external {
        require(owner == address(0), "already init");
        owner = _owner;
        guardianRegistry = _guardianRegistry;
        ssv = _ssv;
        responseContract = _response;

        // default POC thresholds
        pendingRecoveriesThreshold = 3;
        avgGuardianVotesThresholdBp = 3000; // 30%
        triggerRiskBp = 6000; // 60%

        emit Initialized(_owner, _guardianRegistry, _ssv, _response);
    }

    function setConfig(address _guardianRegistry, address _ssv, address _response) external onlyOwner {
        guardianRegistry = _guardianRegistry;
        ssv = _ssv;
        responseContract = _response;
    }

    function setThresholds(
        uint256 _pendingRecoveriesThreshold,
        uint256 _avgGuardianVotesBp,
        uint256 _triggerRiskBp
    ) external onlyOwner {
        pendingRecoveriesThreshold = _pendingRecoveriesThreshold;
        avgGuardianVotesThresholdBp = _avgGuardianVotesBp;
        triggerRiskBp = _triggerRiskBp;
    }

    // Drosera-required API: cheap collect
    function collect() external view override returns (bytes memory) {
        uint256 pendingRecoveries = 0;
        uint256 avgVotesBp = 0;
        uint256 operatorMisses = 0;

        if (guardianRegistry != address(0)) {
            try IGuardianRegistry(guardianRegistry).pendingRecoveries() returns (uint256 p) {
                pendingRecoveries = p;
            } catch {}
            try IGuardianRegistry(guardianRegistry).averageGuardianVotes() returns (uint256 v) {
                avgVotesBp = v;
            } catch {}
        }

        if (ssv != address(0)) {
            try ISSV(ssv).getOperatorMisses(address(this)) returns (uint256 m) {
                operatorMisses = m;
            } catch {}
        }

        return abi.encode(
            block.number,
            block.timestamp,
            pendingRecoveries,
            avgVotesBp,
            operatorMisses,
            pendingRecoveriesThreshold,
            avgGuardianVotesThresholdBp,
            triggerRiskBp
        );
    }

    // shouldRespond must be deterministic/pure: only uses the provided data array
    function shouldRespond(bytes[] calldata data) external pure override returns (bool, bytes memory) {
        if (data.length == 0) {
            return (false, bytes(""));
        }

        (
            uint256 blockNum,
            ,
            uint256 pendingRecoveries,
            uint256 avgVotesBp,
            uint256 operatorMisses,
            uint256 pendingThreshold,
            uint256 avgVotesThresholdBp,
            uint256 triggerBp
        ) = abi.decode(data[data.length - 1], (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256));

        uint256 risk = _computeRiskPure(
            pendingRecoveries,
            avgVotesBp,
            operatorMisses,
            pendingThreshold,
            avgVotesThresholdBp
        );

        bool should = (risk >= triggerBp);
        bytes memory payload = abi.encode(blockNum, risk, pendingRecoveries, avgVotesBp, operatorMisses);
        return (should, payload);
    }

    // Operator/invoker calls respond() with a collect() blob to perform the actual response action
    function respond(bytes calldata data) external {
        (
            uint256 blockNum,
            uint256 ts,
            uint256 pendingRecoveries,
            uint256 avgVotesBp,
            uint256 operatorMisses,
            uint256 pendingThreshold,
            uint256 avgVotesThresholdBp,
            uint256 triggerBp
        ) = abi.decode(data, (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256));

        uint256 risk = _computeRiskPure(
            pendingRecoveries,
            avgVotesBp,
            operatorMisses,
            pendingThreshold,
            avgVotesThresholdBp
        );

        snapshots.push(
            Snapshot({
                blockNum: blockNum,
                ts: ts,
                pendingRecoveries: pendingRecoveries,
                avgGuardianVotesBp: avgVotesBp,
                operatorMisses: operatorMisses,
                risk: risk
            })
        );

        emit Collected(blockNum, pendingRecoveries, avgVotesBp, operatorMisses);

        if (risk >= triggerBp && responseContract != address(0)) {
            bytes memory payload = abi.encode(blockNum, ts, pendingRecoveries, avgVotesBp, operatorMisses, risk);
            try IResponse(responseContract).executeResponse(payload) {
                emit RespondTriggered(blockNum, risk, "response_ok");
            } catch {
                emit RespondTriggered(blockNum, risk, "response_failed");
            }
        } else {
            emit RespondTriggered(blockNum, risk, "no_action");
        }
    }

    // deterministic pure scoring function (no storage, no timestamp dependencies inside)
    function _computeRiskPure(
        uint256 pendingRecoveries,
        uint256 avgVotesBp,
        uint256 operatorMisses,
        uint256 pendingThreshold,
        uint256 avgVotesThresholdBp
    ) internal pure returns (uint256) {
        uint256 score = 0;

        if (pendingRecoveries >= pendingThreshold && pendingThreshold > 0) {
            score += 5000;
        } else {
            score += pendingRecoveries * 500;
        }

        if (avgVotesThresholdBp > 0 && avgVotesBp < avgVotesThresholdBp) {
            uint256 drop = (avgVotesThresholdBp - avgVotesBp);
            score += (drop * 2);
        }

        score += operatorMisses * 300;

        if (score > 10000) return 10000;
        return score;
    }

    // helpers
    function snapshotsCount() external view returns (uint256) {
        return snapshots.length;
    }

    function getSnapshot(uint256 idx) external view returns (Snapshot memory) {
        require(idx < snapshots.length, "SSVGuardianTrap: OOB");
        return snapshots[idx];
    }
}
