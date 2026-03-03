// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestUtils} from "./helpers/TestUtils.sol";
import {ProofRegistry} from "../src/ProofRegistry.sol";
import {IProofRegistry} from "../src/interfaces/IProofRegistry.sol";

/// @title ProofRegistryTest
/// @notice Unit tests for the ProofRegistry contract.
///         Covers registration flow, access control, event emission, Merkle
///         precompile interactions, and metadata query functions.
/// @dev All precompile calls are mocked via forge-std `vm.mockCall` /
///      `vm.mockCallRevert` helpers inherited from TestUtils.
contract ProofRegistryTest is TestUtils {
    // =========================================================================
    //                          TEST CONSTANTS
    // =========================================================================

    /// @dev Deterministic proof parameters used across tests.
    bytes32 constant PROOF_ID = keccak256("proof-1");
    bytes32 constant CIRCUIT_ID = keccak256("proof-of-age");
    bytes32 constant PUBLIC_INPUTS_HASH = keccak256("inputs-hash-1");
    uint256 constant TIMESTAMP = 1_700_000_000;

    /// @dev Expected Merkle insert return values.
    bytes32 constant MOCK_NEW_ROOT = keccak256("mock-root-after-insert");
    uint256 constant MOCK_LEAF_INDEX = 0;

    /// @dev A second set of parameters used for multi-proof scenarios.
    bytes32 constant PROOF_ID_2 = keccak256("proof-2");
    bytes32 constant MOCK_NEW_ROOT_2 = keccak256("mock-root-after-second-insert");
    uint256 constant MOCK_LEAF_INDEX_2 = 1;

    // =========================================================================
    //                              SETUP
    // =========================================================================

    function setUp() public override {
        super.setUp();
    }

    // =========================================================================
    //                        INTERNAL HELPERS
    // =========================================================================

    /// @dev Registers a proof as the coordinator with default test parameters.
    ///      Mocks the MerkleTreeInsert precompile before calling.
    function _registerDefaultProof() internal returns (uint256 leafIndex) {
        _mockMerkleInsert(MOCK_NEW_ROOT, MOCK_LEAF_INDEX);

        vm.prank(address(coordinator));
        leafIndex = proofRegistry.registerProof(PROOF_ID, CIRCUIT_ID, PUBLIC_INPUTS_HASH, TIMESTAMP);
    }

    // =========================================================================
    //                          UNIT TESTS
    // =========================================================================

    // ----- registerProof: success path ------------------------------------

    /// @notice Verify that registerProof stores correct metadata and returns
    ///         the expected leaf index when called by the coordinator.
    function test_registerProof_success() public {
        uint256 leafIndex = _registerDefaultProof();

        assertEq(leafIndex, MOCK_LEAF_INDEX, "leafIndex mismatch");

        (bytes32 circuitId, uint256 ts, uint256 idx) = proofRegistry.getProofMetadata(PROOF_ID);

        assertEq(circuitId, CIRCUIT_ID, "circuitId mismatch");
        assertEq(ts, TIMESTAMP, "timestamp mismatch");
        assertEq(idx, MOCK_LEAF_INDEX, "stored leafIndex mismatch");
    }

    /// @notice Verify that registerProof emits ProofRegistered with all four
    ///         indexed / non-indexed parameters.
    function test_registerProof_emitsEvent() public {
        _mockMerkleInsert(MOCK_NEW_ROOT, MOCK_LEAF_INDEX);

        // Expect the event -- check all four topics + data
        vm.expectEmit(true, true, false, true, address(proofRegistry));
        emit IProofRegistry.ProofRegistered(PROOF_ID, CIRCUIT_ID, MOCK_LEAF_INDEX, MOCK_NEW_ROOT);

        vm.prank(address(coordinator));
        proofRegistry.registerProof(PROOF_ID, CIRCUIT_ID, PUBLIC_INPUTS_HASH, TIMESTAMP);
    }

    /// @notice Verify that the on-chain Merkle root is updated to the value
    ///         returned by the MerkleTreeInsert precompile.
    function test_registerProof_updatesRoot() public {
        bytes32 rootBefore = proofRegistry.currentRoot();
        assertEq(rootBefore, bytes32(0), "root should be zero before any insert");

        _registerDefaultProof();

        bytes32 rootAfter = proofRegistry.currentRoot();
        assertEq(rootAfter, MOCK_NEW_ROOT, "root not updated to mock value");
    }

    /// @notice Verify that totalProofs increments by 1 for each registration.
    function test_registerProof_incrementsTotalProofs() public {
        assertEq(proofRegistry.totalProofs(), 0, "totalProofs should start at 0");

        _registerDefaultProof();
        assertEq(proofRegistry.totalProofs(), 1, "totalProofs should be 1");

        // Register a second distinct proof
        _mockMerkleInsert(MOCK_NEW_ROOT_2, MOCK_LEAF_INDEX_2);
        vm.prank(address(coordinator));
        proofRegistry.registerProof(PROOF_ID_2, CIRCUIT_ID, PUBLIC_INPUTS_HASH, TIMESTAMP + 1);
        assertEq(proofRegistry.totalProofs(), 2, "totalProofs should be 2");
    }

    // ----- registerProof: revert paths ------------------------------------

    /// @notice Registering the same proofId twice must revert with
    ///         AlreadyRegistered.
    function test_registerProof_revertsIfAlreadyRegistered() public {
        _registerDefaultProof();

        // The mock is still active -- attempt a duplicate registration
        vm.prank(address(coordinator));
        vm.expectRevert(IProofRegistry.AlreadyRegistered.selector);
        proofRegistry.registerProof(PROOF_ID, CIRCUIT_ID, PUBLIC_INPUTS_HASH, TIMESTAMP);
    }

    /// @notice A non-coordinator address must be rejected with Unauthorized.
    function test_registerProof_revertsIfNotCoordinator() public {
        _mockMerkleInsert(MOCK_NEW_ROOT, MOCK_LEAF_INDEX);

        vm.prank(stranger);
        vm.expectRevert(IProofRegistry.Unauthorized.selector);
        proofRegistry.registerProof(PROOF_ID, CIRCUIT_ID, PUBLIC_INPUTS_HASH, TIMESTAMP);
    }

    /// @notice If the MerkleTreeInsert precompile reverts, registerProof must
    ///         propagate the failure as InsertionFailed.
    function test_registerProof_revertsIfPrecompileFails() public {
        vm.mockCallRevert(MERKLE_INSERT_PRECOMPILE, bytes(""), bytes("precompile failure"));

        vm.prank(address(coordinator));
        vm.expectRevert(IProofRegistry.InsertionFailed.selector);
        proofRegistry.registerProof(PROOF_ID, CIRCUIT_ID, PUBLIC_INPUTS_HASH, TIMESTAMP);
    }

    // ----- isVerified -----------------------------------------------------

    /// @notice isVerified returns true when both MerkleTreeInsert and
    ///         MerkleTreeVerify precompiles succeed.
    function test_isVerified_returnsTrueOnSuccess() public {
        // First register the proof so metadata exists
        _registerDefaultProof();

        // Mock the verify precompile to return 0x01 (valid)
        _mockMerkleVerifySuccess();

        // Supply an empty Merkle proof -- the precompile is mocked anyway
        bytes32[] memory merkleProof = new bytes32[](0);
        bool verified = proofRegistry.isVerified(PROOF_ID, merkleProof);

        assertTrue(verified, "isVerified should return true");
    }

    /// @notice isVerified returns false for a proofId that was never registered
    ///         (no metadata exists, early return before precompile call).
    function test_isVerified_returnsFalseIfNotRegistered() public {
        bytes32 unknownId = keccak256("non-existent-proof");
        bytes32[] memory merkleProof = new bytes32[](0);

        bool verified = proofRegistry.isVerified(unknownId, merkleProof);
        assertFalse(verified, "isVerified should return false for unknown proof");
    }

    /// @notice isVerified returns false when the MerkleTreeVerify precompile
    ///         returns 0x00 (invalid inclusion).
    function test_isVerified_returnsFalseIfVerifyFails() public {
        // Register the proof so metadata exists
        _registerDefaultProof();

        // Mock the verify precompile to return 0x00 (invalid)
        _mockMerkleVerifyFailure();

        bytes32[] memory merkleProof = new bytes32[](0);
        bool verified = proofRegistry.isVerified(PROOF_ID, merkleProof);

        assertFalse(verified, "isVerified should return false when verify fails");
    }

    // ----- getProofMetadata -----------------------------------------------

    /// @notice getProofMetadata returns correct values after registration.
    function test_getProofMetadata_success() public {
        _registerDefaultProof();

        (bytes32 circuitId, uint256 ts, uint256 idx) = proofRegistry.getProofMetadata(PROOF_ID);

        assertEq(circuitId, CIRCUIT_ID, "circuitId mismatch");
        assertEq(ts, TIMESTAMP, "timestamp mismatch");
        assertEq(idx, MOCK_LEAF_INDEX, "leafIndex mismatch");
    }

    /// @notice getProofMetadata reverts with ProofNotFound for a non-existent
    ///         proofId.
    function test_getProofMetadata_revertsIfNotFound() public {
        bytes32 unknownId = keccak256("non-existent-proof");

        vm.expectRevert(IProofRegistry.ProofNotFound.selector);
        proofRegistry.getProofMetadata(unknownId);
    }
}
