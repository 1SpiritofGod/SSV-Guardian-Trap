SSVGuardianTrap
Overview

SSVGuardianTrap is a Drosera trap PoC that monitors validator activity and performance signals within the SSV ecosystem.
It’s designed to track validator uptime, slashing risk, and threshold metrics across operators, triggering a response when critical parameters are breached — acting as a decentralized “guardian” for SSV validator health.

This repository contains:

SSVGuardianTrap.sol — the main trap contract implementing ITrap semantics (collect + shouldRespond).

SSVGuardianResponse.sol — a lightweight on-chain response contract that records validator statuses and emits alerts.

drosera.toml — the Drosera manifest and deployment metadata for your unique POC.

Contracts — exact signatures & behaviour
SSVGuardianTrap.sol (highlights)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

contract SSVGuardianTrap is ITrap {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    struct ValidatorStats {
        uint256 operatorMisses;
        uint256 pendingThresh;
        uint256 avgVotesThreshBP;
        uint256 triggerBP;
    }

    function collect() external view returns (bytes memory) {
        // Example: encode simulated performance metrics
        uint256 operatorMisses = 2;
        uint256 pendingThresh = 10;
        uint256 avgVotesThreshBP = 9000;
        uint256 triggerBP = 9500;

        return abi.encode(operatorMisses, pendingThresh, avgVotesThreshBP, triggerBP, block.number);
    }

    function shouldRespond(bytes[] calldata data)
        external
        pure
        override
        returns (bool, bytes memory)
    {
        if (data.length == 0) return (false, "");

        (uint256 operatorMisses,, uint256 avgVotesThreshBP, uint256 triggerBP,) =
            abi.decode(data[0], (uint256, uint256, uint256, uint256, uint256));

        bool breach = operatorMisses > 5 || avgVotesThreshBP < triggerBP;
        return (breach, abi.encode(operatorMisses, avgVotesThreshBP, triggerBP));
    }
}

Important exact function signatures:

function collect() external view returns (bytes memory) — gathers current validator performance data.

function shouldRespond(bytes[] calldata data) external override pure returns (bool, bytes memory) — checks whether metrics breach defined safety thresholds, triggering the guardian response.

SSVGuardianResponse.sol (highlights)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract SSVGuardianResponse {
    struct ValidatorStatus {
        bool isActive;
        uint256 uptime;
        uint256 slashRisk;
        uint256 lastUpdate;
    }

    address public guardian;
    mapping(string => ValidatorStatus) private validators;

    event ValidatorUpdated(string indexed validatorId, bool isActive, uint256 uptime, uint256 slashRisk, uint256 timestamp);

    constructor() {
        guardian = msg.sender;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Not authorized");
        _;
    }

    function updateValidator(
        string memory validatorId,
        bool isActive,
        uint256 uptime,
        uint256 slashRisk
    ) public onlyGuardian {
        validators[validatorId] = ValidatorStatus(isActive, uptime, slashRisk, block.timestamp);
        emit ValidatorUpdated(validatorId, isActive, uptime, slashRisk, block.timestamp);
    }

    function getValidatorStatus(string memory validatorId)
        public
        view
        returns (bool, uint256, uint256, uint256)
    {
        ValidatorStatus memory v = validators[validatorId];
        return (v.isActive, v.uptime, v.slashRisk, v.lastUpdate);
    }
}

Exact response signature in drosera.toml:
executeResponse(bytes)

Behaviour:
Records validator health metrics and emits ValidatorUpdated when the trap signals an abnormal state (e.g., operator misses > threshold).

drosera.toml (as provided)
ethereum_rpc = "https://ethereum-hoodi-rpc.publicnode.com"
drosera_rpc = "https://relay.hoodi.drosera.io"
eth_chain_id = 560048
drosera_address = "0x91cB447BaFc6e0EA0F4Fe056F5a9b1F14bb06e5D"

[traps]

[traps.ssv_guardian]
path = "out/SSVGuardianTrap.sol/SSVGuardianTrap.json"
response_contract = "0x73156FD92B4e813233Af451E7d6359E17493c7c3"
response_function = "executeResponse(bytes)"
cooldown_period_blocks = 33
min_number_of_operators = 1
max_number_of_operators = 2
block_sample_size = 10
private_trap = true
whitelist = ["0x87358cb0cba4380393cc512b796775116b7ddc20"]
address = "0x2580671CB93484a6279FA8E5700148Efb34Be989"

How the data flows

Drosera coordinator repeatedly calls collect() from the trap to sample validator metrics.

Once enough samples are gathered, Drosera calls shouldRespond(bytes[] data) with encoded snapshots.

If performance thresholds are breached, the trap returns (true, abi.encode(...)).

Drosera invokes the configured response_function (executeResponse(bytes)) on SSVGuardianResponse, which records the anomaly and emits a validator update event.

Example Foundry / cast usage
Simulate collect:
cast call <TRAP_ADDR> "collect()"

Simulate response:
cast send <RESPONSE_ADDR> "updateValidator(string,bool,uint256,uint256)" "validator_1" true 98 12 --private-key <PRIVATE_KEY>

Check validator status:
cast call <RESPONSE_ADDR> "getValidatorStatus(string)" "validator_1"

Summary

SSVGuardianTrap extends Drosera’s monitoring framework to focus on validator integrity in the SSV network.
It demonstrates how traps can evolve from static metrics into automated, decentralized health monitors — with real-time data pipelines connecting validator performance to on-chain accountability.
