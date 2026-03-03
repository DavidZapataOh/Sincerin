// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofRegistry} from "./interfaces/IProofRegistry.sol";

/// @title ProofRegistry
/// @notice Solidity interface to the native Merkle tree precompiles for storing
///         and verifying ZK proof hashes on the Sincerin L1.
/// @dev The actual Merkle tree state lives inside the Go precompiles
///      (MerkleTreeInsert at 0x03...04, MerkleTreeVerify at 0x03...05).
///      This contract is a thin coordination layer that:
///        1. Enforces access control (only Coordinator can register proofs)
///        2. Maintains an indexed metadata mapping for proof lookups
///        3. Tracks the current Merkle root for cross-chain settlement
///
///      The precompiles use Poseidon hashing internally, providing ZK-friendly
///      Merkle proofs at ~500 gas (insert) and ~300 gas (verify) -- orders of
///      magnitude cheaper than pure-EVM Merkle operations.
///
/// @author Sincerin Protocol
contract ProofRegistry is IProofRegistry {
    // =========================================================================
    //                              CONSTANTS
    // =========================================================================

    /// @dev Number of levels in the sparse Merkle tree managed by the precompile.
    ///      Supports up to 2^32 leaves.
    uint256 private constant TREE_DEPTH = 32;

    /// @dev Expected byte length returned by the MerkleTreeInsert precompile:
    ///      new_root (32 bytes) + leaf_index (32 bytes) = 64 bytes.
    uint256 private constant INSERT_RESULT_LENGTH = 64;

    /// @dev Expected byte length of the input to MerkleTreeVerify precompile:
    ///      proof_hash(32) + metadata(32) + leaf_index(32) + merkle_proof(32*32) + root(32)
    ///      = 32 + 32 + 32 + 1024 + 32 = 1152 bytes.
    uint256 private constant VERIFY_INPUT_LENGTH = 1152;

    // =========================================================================
    //                           IMMUTABLE STATE
    // =========================================================================

    /// @notice Address of the MerkleTreeInsert precompile on the Sincerin L1.
    /// @dev Fixed at 0x0300000000000000000000000000000000000004 in genesis.
    address public immutable merkleInsertPrecompile;

    /// @notice Address of the MerkleTreeVerify precompile on the Sincerin L1.
    /// @dev Fixed at 0x0300000000000000000000000000000000000005 in genesis.
    address public immutable merkleVerifyPrecompile;

    // =========================================================================
    //                            MUTABLE STATE
    // =========================================================================

    /// @notice Address of the Coordinator contract authorized to register proofs.
    /// @dev Set by the owner via `setCoordinator`. Only this address may call
    ///      `registerProof`.
    address public coordinator;

    /// @notice Owner of this contract. Can set the coordinator address.
    address public owner;

    /// @notice Metadata for each registered proof, keyed by proofId.
    /// @dev ProofMeta.exists is used as a sentinel to distinguish registered
    ///      proofs from uninitialized storage (where all fields are zero).
    mapping(bytes32 => ProofMeta) public proofMetadata;

    /// @notice Current root of the Merkle tree after the most recent insertion.
    /// @dev Updated atomically with each successful `registerProof` call.
    ///      This value is posted to settlement chains for cross-chain verification.
    bytes32 public currentRoot;

    /// @notice Total number of proofs registered in the Merkle tree.
    uint256 public totalProofs;

    // =========================================================================
    //                               STRUCTS
    // =========================================================================

    /// @notice On-chain metadata stored for each registered proof.
    /// @param circuitId Identifier of the circuit that was proved
    /// @param publicInputsHash Hash of the public inputs used in verification
    /// @param timestamp When the proof was verified (block.timestamp at verification)
    /// @param leafIndex Position of the proof's leaf in the Merkle tree
    /// @param exists Sentinel flag -- true if the proof has been registered
    struct ProofMeta {
        bytes32 circuitId;
        bytes32 publicInputsHash;
        uint256 timestamp;
        uint256 leafIndex;
        bool exists;
    }

    // =========================================================================
    //                              MODIFIERS
    // =========================================================================

    /// @dev Restricts the caller to the registered Coordinator contract.
    modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert Unauthorized();
        _;
    }

    /// @dev Restricts the caller to the contract owner.
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // =========================================================================
    //                             CONSTRUCTOR
    // =========================================================================

    /// @notice Deploy the ProofRegistry with references to the native precompiles.
    /// @param _merkleInsert Address of the MerkleTreeInsert precompile
    ///        (0x0300000000000000000000000000000000000004)
    /// @param _merkleVerify Address of the MerkleTreeVerify precompile
    ///        (0x0300000000000000000000000000000000000005)
    constructor(address _merkleInsert, address _merkleVerify) {
        merkleInsertPrecompile = _merkleInsert;
        merkleVerifyPrecompile = _merkleVerify;
        owner = msg.sender;
    }

    // =========================================================================
    //                          ADMIN FUNCTIONS
    // =========================================================================

    /// @notice Set the Coordinator contract address that is authorized to
    ///         register proofs.
    /// @dev Only callable by the contract owner. The coordinator is the sole
    ///      address permitted to call `registerProof`.
    /// @param _coordinator Address of the deployed Coordinator contract
    function setCoordinator(address _coordinator) external onlyOwner {
        coordinator = _coordinator;
    }

    // =========================================================================
    //                       STATE-CHANGING FUNCTIONS
    // =========================================================================

    /// @inheritdoc IProofRegistry
    /// @dev Flow:
    ///   1. Check proof is not already registered (idempotency guard)
    ///   2. Compute leafHash = keccak256(proofId, circuitId, publicInputsHash, timestamp)
    ///   3. Compute metadataHash = keccak256(circuitId, publicInputsHash, timestamp)
    ///   4. Call MerkleTreeInsert precompile with abi.encodePacked(leafHash, metadataHash)
    ///   5. Parse 64-byte result: newRoot (bytes32) + leafIndex (uint256)
    ///   6. Store metadata, update currentRoot, increment totalProofs
    ///   7. Emit ProofRegistered
    ///
    ///   The precompile internally computes:
    ///     leaf = PoseidonHash2(leafHash, metadataHash)
    ///   and inserts it into the sparse Merkle tree.
    function registerProof(bytes32 proofId, bytes32 circuitId, bytes32 publicInputsHash, uint256 timestamp)
        external
        onlyCoordinator
        returns (uint256 leafIndex)
    {
        // --- Checks ---
        if (proofMetadata[proofId].exists) revert AlreadyRegistered();

        // --- Compute hashes ---
        bytes32 leafHash = keccak256(abi.encodePacked(proofId, circuitId, publicInputsHash, timestamp));
        bytes32 metadataHash = keccak256(abi.encodePacked(circuitId, publicInputsHash, timestamp));

        // --- Interaction: call MerkleTreeInsert precompile ---
        // Input: proof_hash (32 bytes) || metadata (32 bytes) = 64 bytes total
        (bool success, bytes memory result) =
            merkleInsertPrecompile.staticcall(abi.encodePacked(leafHash, metadataHash));
        if (!success || result.length != INSERT_RESULT_LENGTH) {
            revert InsertionFailed();
        }

        // Parse result: new_root (bytes32 at offset 0) + leaf_index (uint256 at offset 32)
        bytes32 newRoot;
        assembly {
            newRoot := mload(add(result, 32))
            leafIndex := mload(add(result, 64))
        }

        // --- Effects ---
        currentRoot = newRoot;

        // unchecked: totalProofs will not realistically overflow uint256
        unchecked {
            ++totalProofs;
        }

        proofMetadata[proofId] = ProofMeta({
            circuitId: circuitId,
            publicInputsHash: publicInputsHash,
            timestamp: timestamp,
            leafIndex: leafIndex,
            exists: true
        });

        emit ProofRegistered(proofId, circuitId, leafIndex, newRoot);
    }

    // =========================================================================
    //                           VIEW FUNCTIONS
    // =========================================================================

    /// @inheritdoc IProofRegistry
    /// @dev Reconstructs the precompile input from stored metadata and the
    ///      caller-provided Merkle proof, then delegates verification to the
    ///      MerkleTreeVerify precompile.
    ///
    ///      Precompile input layout (1152 bytes total):
    ///        [0x00  - 0x20)  leafHash      (32 bytes)
    ///        [0x20  - 0x40)  metadataHash  (32 bytes)
    ///        [0x40  - 0x60)  leafIndex     (32 bytes, big-endian uint256)
    ///        [0x60  - 0x460) merkleProof   (32 * 32 = 1024 bytes, padded with zeros)
    ///        [0x460 - 0x480) root          (32 bytes)
    ///
    ///      The precompile returns 1 byte: 0x01 (valid) or 0x00 (invalid).
    function isVerified(bytes32 proofId, bytes32[] calldata merkleProof) external view returns (bool) {
        ProofMeta storage meta = proofMetadata[proofId];
        if (!meta.exists) return false;

        // Recompute leaf hash and metadata hash identically to registerProof
        bytes32 leafHash = keccak256(abi.encodePacked(proofId, meta.circuitId, meta.publicInputsHash, meta.timestamp));
        bytes32 metadataHash = keccak256(abi.encodePacked(meta.circuitId, meta.publicInputsHash, meta.timestamp));

        // Cache leafIndex in a stack variable to avoid storage access in assembly
        uint256 metaLeafIndex = meta.leafIndex;

        // Build the 1152-byte precompile input in memory using assembly
        // to avoid repeated abi.encodePacked allocations in a loop.
        bytes memory input = new bytes(VERIFY_INPUT_LENGTH);

        assembly {
            let ptr := add(input, 32) // skip length prefix

            // Store leafHash at offset 0x00
            mstore(ptr, leafHash)

            // Store metadataHash at offset 0x20
            mstore(add(ptr, 0x20), metadataHash)

            // Store leafIndex at offset 0x40
            mstore(add(ptr, 0x40), metaLeafIndex)
        }

        // Copy merkle proof elements (pad with zeros if fewer than TREE_DEPTH)
        uint256 proofLen = merkleProof.length;
        for (uint256 i; i < TREE_DEPTH;) {
            bytes32 sibling;
            if (i < proofLen) {
                sibling = merkleProof[i];
            }
            // else: sibling remains bytes32(0) -- zero hash for empty subtree levels

            assembly {
                // Offset within input: 32 (length) + 0x60 (header) + i * 32
                mstore(add(add(add(input, 32), 0x60), mul(i, 32)), sibling)
            }

            unchecked {
                ++i;
            }
        }

        // Store current root at the final 32-byte slot (offset 0x460)
        bytes32 root = currentRoot;
        assembly {
            mstore(add(add(input, 32), 0x460), root)
        }

        // Call MerkleTreeVerify precompile
        (bool success, bytes memory result) = merkleVerifyPrecompile.staticcall(input);

        return success && result.length > 0 && uint8(result[0]) == 0x01;
    }

    /// @inheritdoc IProofRegistry
    function getProofMetadata(bytes32 proofId)
        external
        view
        returns (bytes32 circuitId, uint256 timestamp, uint256 leafIndex)
    {
        ProofMeta storage meta = proofMetadata[proofId];
        if (!meta.exists) revert ProofNotFound();
        return (meta.circuitId, meta.timestamp, meta.leafIndex);
    }

    /// @inheritdoc IProofRegistry
    function getMerkleRoot() external view returns (bytes32) {
        return currentRoot;
    }
}
