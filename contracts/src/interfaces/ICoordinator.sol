// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICoordinator
/// @notice Coordinator interface for proof request management and verification
/// @dev Entry point for dApps requesting ZK proof generation and verification
interface ICoordinator {
    // === Errors ===
    error InvalidCircuitId();
    error InsufficientFee();
    error ProverNotRegistered();
    error ProofAlreadyVerified();
    error VerificationFailed();
    error RequestNotFound();
    error Unauthorized();
    error InvalidDeadline();
    error InvalidStatus();
    error RequestExpired();
    error TransferFailed();

    // === Events ===

    /// @notice Emitted when a new proof request is created
    /// @param requestId Unique identifier for this request
    /// @param circuitId The circuit to prove
    /// @param requester Address that created the request
    /// @param maxFee Maximum fee offered (msg.value)
    /// @param deadline Unix timestamp after which the request expires
    event ProofRequested(
        bytes32 indexed requestId,
        bytes32 indexed circuitId,
        address indexed requester,
        uint256 maxFee,
        uint256 deadline
    );

    /// @notice Emitted when a prover is assigned to a request
    /// @param requestId The proof request being assigned
    /// @param prover The prover assigned to generate the proof
    event ProofAssigned(bytes32 indexed requestId, address indexed prover);

    /// @notice Emitted when a proof is successfully verified
    /// @param requestId The original request
    /// @param proofId Unique identifier for the verified proof
    /// @param circuitId The circuit that was proved
    /// @param timestamp When verification occurred
    event ProofVerified(bytes32 indexed requestId, bytes32 indexed proofId, bytes32 circuitId, uint256 timestamp);

    /// @notice Emitted when a proof submission is rejected
    /// @param requestId The request that was rejected
    /// @param prover The prover whose proof was rejected
    /// @param reason Human-readable rejection reason
    event ProofRejected(bytes32 indexed requestId, address indexed prover, string reason);

    // === Structs ===

    /// @notice Status of a proof request
    enum ProofStatus {
        Pending,
        Assigned,
        Proving,
        Verified,
        Failed,
        Expired
    }

    /// @notice Complete proof request data
    struct ProofRequest {
        bytes32 requestId;
        bytes32 circuitId;
        address requester;
        uint256 maxFee;
        uint256 deadline;
        address assignedProver;
        ProofStatus status;
        uint256 createdAt;
    }

    // === Functions ===

    /// @notice Submit a proof request for a specific circuit
    /// @param circuitId The identifier of the circuit to prove
    /// @param publicInputsHash Hash of the public inputs for the proof
    /// @param deadline Unix timestamp after which the request expires
    /// @return requestId Unique identifier for this proof request
    function requestProof(bytes32 circuitId, bytes32 publicInputsHash, uint256 deadline)
        external
        payable
        returns (bytes32 requestId);

    /// @notice Submit a proof for verification
    /// @param requestId The proof request to fulfill
    /// @param proof Raw UltraHonk proof bytes
    /// @param publicInputs ABI-encoded public inputs matching the circuit
    function submitProof(bytes32 requestId, bytes calldata proof, bytes calldata publicInputs) external;

    /// @notice Get details of a proof request
    /// @param requestId The request to query
    /// @return The full ProofRequest struct
    function getRequest(bytes32 requestId) external view returns (ProofRequest memory);
}
