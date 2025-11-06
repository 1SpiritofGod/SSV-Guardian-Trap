// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title SSVGuardianResponse
 * @dev A lightweight response contract for recording validator statuses
 *      and handling Drosera-triggered responses from the SSVGuardian trap.
 */
contract SSVGuardianResponse {
    struct ValidatorStatus {
        bool isActive;
        uint256 uptime; // measured in %
        uint256 slashRisk; // percentage of potential risk (0–100)
        uint256 lastUpdate;
    }

    address public guardian;
    mapping(string => ValidatorStatus) private validators;

    event ValidatorUpdated(
        string indexed validatorId,
        bool isActive,
        uint256 uptime,
        uint256 slashRisk,
        uint256 timestamp
    );

    event ResponseExecuted(
        address indexed caller,
        bytes payload
    );

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

    /**
     * @dev Called automatically by Drosera when a trap triggers.
     *      The payload is sent from your SSVGuardianTrap's `respond()` function.
     */
    function executeResponse(bytes calldata payload) external {
        emit ResponseExecuted(msg.sender, payload);

        // Optional: decode the payload for logging or future automation
        // Example: (uint256 blockNum, uint256 risk, uint256 pendingRecoveries, uint256 avgVotesBP, uint256 operatorMisses)
        // = abi.decode(payload, (uint256, uint256, uint256, uint256, uint256));
    }
}
