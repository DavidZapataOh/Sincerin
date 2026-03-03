// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IProofRegistry
/// @notice Registry interface for storing and verifying ZK proof inclusion
/// @dev Backed by a Merkle tree managed via native precompiles
interface IProofRegistry {
    // === Errors ===
    error ProofNotFound();
    error InvalidMerkleProof();
    error AlreadyRegistered();
    error InsertionFailed();
    error Unauthorized();

    // === Events ===

    /// @notice Emitted when a proof is registered in the Merkle tree
    /// @param proofId Unique identifier for the proof
    /// @param circuitId The circuit that was proved
    /// @param leafIndex Index of the leaf in the Merkle tree
    /// @param newRoot New Merkle root after insertion
    event ProofRegistered(bytes32 indexed proofId, bytes32 indexed circuitId, uint256 leafIndex, bytes32 newRoot);

    // === Functions ===

    /// @notice Register a verified proof in the Merkle tree
    /// @param proofId Unique proof identifier
    /// @param circuitId The circuit that was proved
    /// @param publicInputsHash Hash of the public inputs
    /// @param timestamp When the proof was verified
    /// @return leafIndex Index of the inserted leaf
    function registerProof(bytes32 proofId, bytes32 circuitId, bytes32 publicInputsHash, uint256 timestamp)
        external
        returns (uint256 leafIndex);

    /// @notice Check if a proof is verified via Merkle inclusion
    /// @param proofId The proof to check
    /// @param merkleProof Array of sibling hashes from leaf to root
    /// @return True if the proof is in the Merkle tree
    function isVerified(bytes32 proofId, bytes32[] calldata merkleProof) external view returns (bool);

    /// @notice Get metadata for a registered proof
    /// @param proofId The proof to query
    /// @return circuitId The circuit identifier
    /// @return timestamp When the proof was verified
    /// @return leafIndex Position in the Merkle tree
    function getProofMetadata(bytes32 proofId)
        external
        view
        returns (bytes32 circuitId, uint256 timestamp, uint256 leafIndex);

    /// @notice Get the current Merkle root
    /// @return The root hash of the proof registry tree
    function getMerkleRoot() external view returns (bytes32);
}
