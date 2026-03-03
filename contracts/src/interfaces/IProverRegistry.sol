// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IProverRegistry
/// @notice Registry interface for prover registration, staking, and reputation
/// @dev Manages prover lifecycle including registration, reputation scoring, and slashing
interface IProverRegistry {
    // === Errors ===
    error InsufficientStake();
    error ProverAlreadyRegistered();
    error ProverNotFound();
    error ProverSuspended();
    error Unauthorized();
    error TransferFailed();

    // === Events ===

    /// @notice Emitted when a prover registers with stake
    /// @param prover Address of the registered prover
    /// @param stake Amount of stake deposited
    event ProverRegistered(address indexed prover, uint256 stake);

    /// @notice Emitted when a prover is slashed
    /// @param prover Address of the slashed prover
    /// @param amount Amount of stake slashed
    /// @param reason Human-readable slashing reason
    event ProverSlashed(address indexed prover, uint256 amount, string reason);

    /// @notice Emitted when a prover deregisters
    /// @param prover Address of the deregistered prover
    event ProverDeregistered(address indexed prover);

    /// @notice Emitted when a prover's reputation is updated
    /// @param prover Address of the prover
    /// @param newScore Updated reputation score (0-10000 basis points)
    event ReputationUpdated(address indexed prover, uint256 newScore);

    // === Structs ===

    /// @notice Complete prover information
    struct ProverInfo {
        address proverAddress;
        uint256 stake;
        uint256 reputation; // 0-10000 (basis points)
        uint256 totalProofs;
        uint256 failedProofs;
        uint256 totalLatency; // sum of latencies for average computation
        bool active;
        uint256 registeredAt;
    }

    // === Functions ===

    /// @notice Register as a prover with msg.value as stake
    /// @dev Requires msg.value >= minStake
    function register() external payable;

    /// @notice Deregister and withdraw remaining stake
    function deregister() external;

    /// @notice Get prover information
    /// @param prover Address of the prover
    /// @return The complete ProverInfo struct
    function getProver(address prover) external view returns (ProverInfo memory);

    /// @notice Check if a prover is currently active
    /// @param prover Address of the prover
    /// @return True if the prover is registered and active
    function isActive(address prover) external view returns (bool);

    /// @notice Update a prover's reputation based on proof outcome
    /// @param prover Address of the prover
    /// @param latencyMs Time in ms from request to proof submission
    /// @param success Whether the proof was verified successfully
    function updateReputation(address prover, uint256 latencyMs, bool success) external;

    /// @notice Slash a prover's stake
    /// @param prover Address of the prover to slash
    /// @param amount Amount of stake to slash
    /// @param reason Human-readable slashing reason
    function slash(address prover, uint256 amount, string calldata reason) external;
}
