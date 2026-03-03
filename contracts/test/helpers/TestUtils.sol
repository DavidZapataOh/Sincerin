// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ProverRegistry} from "../../src/ProverRegistry.sol";
import {ProofRegistry} from "../../src/ProofRegistry.sol";
import {Coordinator} from "../../src/Coordinator.sol";
import {ICoordinator} from "../../src/interfaces/ICoordinator.sol";
import {IProverRegistry} from "../../src/interfaces/IProverRegistry.sol";
import {IProofRegistry} from "../../src/interfaces/IProofRegistry.sol";

/// @title TestUtils
/// @notice Base test contract with deployment, mocking helpers, and common constants
abstract contract TestUtils is Test {
    // =========================================================================
    //                         PRECOMPILE ADDRESSES
    // =========================================================================

    address constant VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000002;
    address constant MERKLE_INSERT_PRECOMPILE = 0x0300000000000000000000000000000000000004;
    address constant MERKLE_VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000005;

    // =========================================================================
    //                         DEPLOYMENT CONSTANTS
    // =========================================================================

    uint256 constant MIN_STAKE = 1 ether;
    uint256 constant MIN_FEE = 0.001 ether;
    uint256 constant TARGET_LATENCY_MS = 5000;

    // =========================================================================
    //                          CIRCUIT CONSTANTS
    // =========================================================================

    bytes32 constant CIRCUIT_MEMBERSHIP = keccak256("proof-of-membership");
    bytes32 constant CIRCUIT_AGE = keccak256("proof-of-age");
    bytes32 constant VK_HASH_MEMBERSHIP = bytes32(uint256(0x0895));
    bytes32 constant VK_HASH_AGE = bytes32(uint256(0x1bbf));

    // =========================================================================
    //                          TEST CONTRACTS
    // =========================================================================

    ProverRegistry public proverRegistry;
    ProofRegistry public proofRegistry;
    Coordinator public coordinator;

    // =========================================================================
    //                           TEST ACTORS
    // =========================================================================

    address public owner;
    address public operator;
    address public prover1;
    address public prover2;
    address public requester;
    address public stranger;

    // =========================================================================
    //                              SETUP
    // =========================================================================

    function setUp() public virtual {
        // Create labeled actors
        owner = address(this);
        operator = makeAddr("operator");
        prover1 = makeAddr("prover1");
        prover2 = makeAddr("prover2");
        requester = makeAddr("requester");
        stranger = makeAddr("stranger");

        // Deploy contracts
        proverRegistry = new ProverRegistry(MIN_STAKE, TARGET_LATENCY_MS);
        proofRegistry = new ProofRegistry(MERKLE_INSERT_PRECOMPILE, MERKLE_VERIFY_PRECOMPILE);
        coordinator =
            new Coordinator(address(proverRegistry), address(proofRegistry), VERIFY_PRECOMPILE, operator, MIN_FEE);

        // Wire up coordinator authorization
        proverRegistry.setCoordinator(address(coordinator));
        proofRegistry.setCoordinator(address(coordinator));

        // Register circuits
        vm.startPrank(operator);
        coordinator.registerCircuit(CIRCUIT_MEMBERSHIP, VK_HASH_MEMBERSHIP);
        coordinator.registerCircuit(CIRCUIT_AGE, VK_HASH_AGE);
        vm.stopPrank();

        // Fund actors
        vm.deal(prover1, 100 ether);
        vm.deal(prover2, 100 ether);
        vm.deal(requester, 100 ether);
        vm.deal(stranger, 10 ether);
    }

    // =========================================================================
    //                       PRECOMPILE MOCK HELPERS
    // =========================================================================

    /// @dev Mock VerifyUltraHonk precompile to return success (0x01)
    function _mockVerifySuccess() internal {
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(bytes1(0x01)));
    }

    /// @dev Mock VerifyUltraHonk precompile to return failure (0x00)
    function _mockVerifyFailure() internal {
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(bytes1(0x00)));
    }

    /// @dev Mock MerkleTreeInsert precompile to return a root and leaf index
    function _mockMerkleInsert(bytes32 newRoot, uint256 leafIndex) internal {
        vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encodePacked(newRoot, leafIndex));
    }

    /// @dev Mock MerkleTreeVerify precompile to return success (0x01)
    function _mockMerkleVerifySuccess() internal {
        vm.mockCall(MERKLE_VERIFY_PRECOMPILE, bytes(""), abi.encode(bytes1(0x01)));
    }

    /// @dev Mock MerkleTreeVerify precompile to return failure (0x00)
    function _mockMerkleVerifyFailure() internal {
        vm.mockCall(MERKLE_VERIFY_PRECOMPILE, bytes(""), abi.encode(bytes1(0x00)));
    }

    // =========================================================================
    //                         ACTION HELPERS
    // =========================================================================

    /// @dev Register a prover with the given stake
    function _registerProver(address prover, uint256 stake) internal {
        vm.prank(prover);
        proverRegistry.register{value: stake}();
    }

    /// @dev Create a proof request and return the requestId
    function _createRequest(
        address _requester,
        bytes32 circuitId,
        bytes32 publicInputsHash,
        uint256 fee,
        uint256 deadline
    ) internal returns (bytes32 requestId) {
        vm.prank(_requester);
        requestId = coordinator.requestProof{value: fee}(circuitId, publicInputsHash, deadline);
    }

    /// @dev Assign a prover to a request
    function _assignProver(bytes32 requestId, address prover) internal {
        vm.prank(operator);
        coordinator.assignProver(requestId, prover);
    }

    /// @dev Full flow: create request + assign prover, returns requestId
    function _createAndAssignRequest(
        address _requester,
        address prover,
        bytes32 circuitId,
        bytes32 publicInputsHash,
        uint256 fee,
        uint256 deadline
    ) internal returns (bytes32 requestId) {
        requestId = _createRequest(_requester, circuitId, publicInputsHash, fee, deadline);
        _assignProver(requestId, prover);
    }
}
