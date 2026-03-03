// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProverRegistry} from "./interfaces/IProverRegistry.sol";

/// @title ProverRegistry
/// @author Sincerin Protocol
/// @notice Manages prover registration, staking, reputation scoring, and slashing
/// @dev Provers stake native tokens to register, earn reputation through successful proof
///      generation, and face slashing for misbehavior. Reputation uses a weighted moving
///      average based on latency performance (0-10000 basis points). The Coordinator
///      contract is the sole authority for reputation updates and slashing.
contract ProverRegistry is IProverRegistry {
    // =========================================================================
    //                              CONSTANTS
    // =========================================================================

    /// @notice Maximum reputation score (100.00% in basis points)
    uint256 private constant MAX_REPUTATION = 10_000;

    /// @notice Initial reputation score for newly registered provers (50.00%)
    uint256 private constant INITIAL_REPUTATION = 5_000;

    /// @notice Reputation penalty applied on proof failure (5.00%)
    uint256 private constant FAILURE_PENALTY = 500;

    /// @notice Multiplier applied to targetLatencyMs to determine the worst acceptable latency
    /// @dev Latencies at or above targetLatencyMs * LATENCY_CEILING_MULTIPLIER score 0
    uint256 private constant LATENCY_CEILING_MULTIPLIER = 5;

    // =========================================================================
    //                              STATE VARIABLES
    // =========================================================================

    /// @notice Address of the Coordinator contract authorized to update reputation and slash
    address public coordinator;

    /// @notice Address of the contract owner (can set coordinator, update parameters)
    address public owner;

    /// @notice Minimum stake required to register as a prover (in wei)
    uint256 public minStake;

    /// @notice Target proof generation latency in milliseconds
    /// @dev Provers meeting this target receive maximum latency score (10000)
    uint256 public targetLatencyMs;

    /// @notice Mapping from prover address to their complete information
    mapping(address => ProverInfo) private s_provers;

    /// @notice Array of all prover addresses that have ever registered
    /// @dev Used for enumeration. Includes inactive provers.
    address[] private s_proverList;

    // =========================================================================
    //                              MODIFIERS
    // =========================================================================

    /// @notice Restricts access to the Coordinator contract
    modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert Unauthorized();
        _;
    }

    /// @notice Restricts access to the contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // =========================================================================
    //                              CONSTRUCTOR
    // =========================================================================

    /// @notice Deploys the ProverRegistry with initial configuration
    /// @param _minStake Minimum native token stake required for prover registration (wei)
    /// @param _targetLatencyMs Target proof generation latency in milliseconds
    constructor(uint256 _minStake, uint256 _targetLatencyMs) {
        owner = msg.sender;
        minStake = _minStake;
        targetLatencyMs = _targetLatencyMs;
    }

    // =========================================================================
    //                          ADMIN FUNCTIONS
    // =========================================================================

    /// @notice Sets the Coordinator contract address
    /// @dev Only callable by the owner. The Coordinator is the sole authority for
    ///      reputation updates and slashing operations.
    /// @param _coordinator Address of the Coordinator contract
    function setCoordinator(address _coordinator) external onlyOwner {
        coordinator = _coordinator;
    }

    // =========================================================================
    //                        REGISTRATION FUNCTIONS
    // =========================================================================

    /// @inheritdoc IProverRegistry
    function register() external payable {
        // --- Checks ---
        if (s_provers[msg.sender].active) revert ProverAlreadyRegistered();
        if (msg.value < minStake) revert InsufficientStake();

        // --- Effects ---
        // Check if this is a re-registration (prover existed before but deregistered)
        bool isNewProver = s_provers[msg.sender].registeredAt == 0;

        s_provers[msg.sender] = ProverInfo({
            proverAddress: msg.sender,
            stake: msg.value,
            reputation: INITIAL_REPUTATION,
            totalProofs: 0,
            failedProofs: 0,
            totalLatency: 0,
            active: true,
            registeredAt: block.timestamp
        });

        if (isNewProver) {
            s_proverList.push(msg.sender);
        }

        emit ProverRegistered(msg.sender, msg.value);
    }

    /// @inheritdoc IProverRegistry
    function deregister() external {
        ProverInfo storage prover = s_provers[msg.sender];

        // --- Checks ---
        if (!prover.active) revert ProverNotFound();

        // --- Effects ---
        uint256 stakeToReturn = prover.stake;
        prover.stake = 0;
        prover.active = false;

        emit ProverDeregistered(msg.sender);

        // --- Interactions ---
        (bool sent,) = payable(msg.sender).call{value: stakeToReturn}("");
        if (!sent) revert TransferFailed();
    }

    // =========================================================================
    //                        REPUTATION FUNCTIONS
    // =========================================================================

    /// @inheritdoc IProverRegistry
    /// @dev Reputation scoring logic:
    ///      - On failure: reputation reduced by FAILURE_PENALTY (floored at 0)
    ///      - On success: latencyScore computed as linear interpolation between
    ///        MAX_REPUTATION (at or below targetLatencyMs) and 0 (at or above
    ///        targetLatencyMs * LATENCY_CEILING_MULTIPLIER)
    ///      - Weighted moving average: newRep = (oldRep * (totalProofs - 1) + latencyScore) / totalProofs
    ///      - Capped at MAX_REPUTATION
    function updateReputation(address prover, uint256 latencyMs, bool success) external onlyCoordinator {
        ProverInfo storage info = s_provers[prover];

        // --- Checks ---
        if (!info.active) revert ProverNotFound();

        // --- Effects ---
        info.totalProofs += 1;
        info.totalLatency += latencyMs;

        if (!success) {
            info.failedProofs += 1;

            // Reduce reputation by FAILURE_PENALTY, floor at 0
            // Safe to use unchecked: we explicitly handle underflow with the conditional
            if (info.reputation <= FAILURE_PENALTY) {
                info.reputation = 0;
            } else {
                unchecked {
                    info.reputation -= FAILURE_PENALTY;
                }
            }
        } else {
            // Compute latency score: linear interpolation [targetLatencyMs, targetLatencyMs * 5]
            // -> [MAX_REPUTATION, 0]
            uint256 latencyScore = _computeLatencyScore(latencyMs);

            // Weighted moving average incorporating the new score
            // newRep = (oldRep * (totalProofs - 1) + latencyScore) / totalProofs
            //
            // Overflow analysis for unchecked block:
            // - info.reputation <= 10_000 (MAX_REPUTATION)
            // - (totalProofs - 1) is safe because totalProofs >= 1 (incremented above)
            // - oldRep * (totalProofs - 1): max is 10_000 * (2^256 - 2), but practically
            //   totalProofs will never approach 2^256. Even at 10^18 proofs:
            //   10_000 * 10^18 = 10^22, well within uint256.
            // - latencyScore <= 10_000
            // - Division by totalProofs >= 1, safe from div-by-zero
            uint256 newReputation;
            unchecked {
                uint256 previousProofs = info.totalProofs - 1;
                newReputation = (info.reputation * previousProofs + latencyScore) / info.totalProofs;
            }

            // Cap at MAX_REPUTATION
            info.reputation = newReputation > MAX_REPUTATION ? MAX_REPUTATION : newReputation;
        }

        emit ReputationUpdated(prover, info.reputation);
    }

    // =========================================================================
    //                          SLASHING FUNCTIONS
    // =========================================================================

    /// @inheritdoc IProverRegistry
    /// @dev Reduces the prover's stake by the specified amount. If the remaining stake
    ///      falls below minStake, the prover is automatically deactivated. Slashed funds
    ///      are held by this contract (can be extended for treasury/burn in future).
    function slash(address prover, uint256 amount, string calldata reason) external onlyCoordinator {
        ProverInfo storage info = s_provers[prover];

        // --- Checks ---
        if (info.registeredAt == 0) revert ProverNotFound();

        // --- Effects ---
        // Cap slash amount to available stake to prevent underflow
        uint256 actualSlash = amount > info.stake ? info.stake : amount;
        unchecked {
            // Safe: actualSlash <= info.stake by the line above
            info.stake -= actualSlash;
        }

        // Deactivate prover if remaining stake is below minimum
        if (info.stake < minStake) {
            info.active = false;
        }

        emit ProverSlashed(prover, actualSlash, reason);
    }

    // =========================================================================
    //                           VIEW FUNCTIONS
    // =========================================================================

    /// @inheritdoc IProverRegistry
    function getProver(address prover) external view returns (ProverInfo memory) {
        return s_provers[prover];
    }

    /// @inheritdoc IProverRegistry
    function isActive(address prover) external view returns (bool) {
        return s_provers[prover].active;
    }

    /// @notice Returns the total number of provers that have ever registered
    /// @dev Includes inactive/deregistered provers. Use isActive() to filter.
    /// @return The length of the prover list
    function getProverCount() external view returns (uint256) {
        return s_proverList.length;
    }

    // =========================================================================
    //                        INTERNAL FUNCTIONS
    // =========================================================================

    /// @notice Computes a latency score based on proof generation time
    /// @dev Linear interpolation between MAX_REPUTATION (at or below targetLatencyMs)
    ///      and 0 (at or above targetLatencyMs * LATENCY_CEILING_MULTIPLIER).
    ///      Formula: score = MAX_REPUTATION * (ceiling - latencyMs) / (ceiling - targetLatencyMs)
    /// @param latencyMs The proof generation latency in milliseconds
    /// @return score The latency score in basis points (0-10000)
    function _computeLatencyScore(uint256 latencyMs) internal view returns (uint256 score) {
        // At or below target: perfect score
        if (latencyMs <= targetLatencyMs) {
            return MAX_REPUTATION;
        }

        uint256 ceiling = targetLatencyMs * LATENCY_CEILING_MULTIPLIER;

        // At or above ceiling: zero score
        if (latencyMs >= ceiling) {
            return 0;
        }

        // Linear interpolation between target and ceiling
        // Multiply before divide to preserve precision (t11s pattern)
        //
        // Overflow analysis for unchecked:
        // - MAX_REPUTATION = 10_000
        // - (ceiling - latencyMs) < ceiling = targetLatencyMs * 5
        // - Product: 10_000 * targetLatencyMs * 5 = 50_000 * targetLatencyMs
        // - For targetLatencyMs up to ~10^71, this is safe within uint256
        // - Denominator (ceiling - targetLatencyMs) = targetLatencyMs * 4, always > 0
        //   because LATENCY_CEILING_MULTIPLIER > 1
        unchecked {
            score = (MAX_REPUTATION * (ceiling - latencyMs)) / (ceiling - targetLatencyMs);
        }
    }
}
