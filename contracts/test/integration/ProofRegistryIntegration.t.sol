// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Coordinator} from "../../src/Coordinator.sol";
import {ICoordinator} from "../../src/interfaces/ICoordinator.sol";
import {ProverRegistry} from "../../src/ProverRegistry.sol";
import {ProofRegistry} from "../../src/ProofRegistry.sol";
import {IProofRegistry} from "../../src/interfaces/IProofRegistry.sol";

/// @title ProofRegistryIntegration
/// @notice Integration tests for ProofRegistry ↔ MerkleTree precompile encoding.
///
///     ENCODING FINDINGS (Sprint 2, Task 6.5):
///
///     MerkleTreeInsert (ProofRegistry.registerProof):
///       Current:  merkleInsertPrecompile.staticcall(abi.encodePacked(leafHash, metadataHash))
///       Issues:
///         1. Missing 4-byte function selector (precompile routes by selector)
///         2. Uses staticcall but precompile rejects readOnly (insert mutates tree state)
///       Fix:
///         - Use CALL instead of STATICCALL
///         - Use abi.encodeWithSelector(INSERT_SELECTOR, leafHash, metadataHash)
///         - Data layout for (bytes32, bytes32) is identical with/without encodePacked,
///           so only the selector and call type need to change.
///
///     MerkleTreeVerify (ProofRegistry.isVerified):
///       Current:  merkleVerifyPrecompile.staticcall(raw1152bytes)
///       Issues:
///         1. Missing 4-byte function selector
///       Note:
///         - The 1152-byte layout IS the correct ABI encoding for
///           (bytes32, bytes32, uint256, bytes32[32], bytes32) — all static types.
///         - Only the 4-byte selector is missing. STATICCALL is correct (verify is read-only).
///       Fix:
///         - Prepend the verify function selector to the input.
///
/// @dev Run: forge test --match-contract ProofRegistryIntegration -vvv
contract ProofRegistryIntegration is Test {
    // =========================================================================
    //                          CONSTANTS
    // =========================================================================

    address constant VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000002;
    address constant MERKLE_INSERT_PRECOMPILE = 0x0300000000000000000000000000000000000004;
    address constant MERKLE_VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000005;

    uint256 constant MIN_STAKE = 1 ether;
    uint256 constant MIN_FEE = 0.001 ether;
    uint256 constant TARGET_LATENCY_MS = 5000;
    uint256 constant TREE_DEPTH = 32;

    bytes32 constant CIRCUIT_MEMBERSHIP = keccak256("proof-of-membership");

    // =========================================================================
    //                            STATE
    // =========================================================================

    ProverRegistry proverRegistry;
    ProofRegistry proofRegistry;
    Coordinator coordinator;

    address operator;
    address prover1;
    address requester;

    bytes membershipProof;
    bytes membershipVk;
    bytes membershipPublicInputs;

    // =========================================================================
    //                           SETUP
    // =========================================================================

    function setUp() public {
        operator = makeAddr("operator");
        prover1 = makeAddr("prover1");
        requester = makeAddr("requester");

        proverRegistry = new ProverRegistry(MIN_STAKE, TARGET_LATENCY_MS);
        proofRegistry = new ProofRegistry(MERKLE_INSERT_PRECOMPILE, MERKLE_VERIFY_PRECOMPILE);
        coordinator = new Coordinator(
            address(proverRegistry), address(proofRegistry), VERIFY_PRECOMPILE, operator, MIN_FEE
        );

        proverRegistry.setCoordinator(address(coordinator));
        proofRegistry.setCoordinator(address(coordinator));

        vm.deal(prover1, 100 ether);
        vm.deal(requester, 100 ether);

        membershipProof = vm.readFileBinary("../fixtures/zk/evm/membership_proof.bin");
        membershipVk = vm.readFileBinary("../fixtures/zk/evm/membership_vk.bin");
        membershipPublicInputs = vm.readFileBinary("../fixtures/zk/evm/membership_public_inputs.bin");

        vm.startPrank(operator);
        coordinator.registerCircuit(CIRCUIT_MEMBERSHIP, keccak256(membershipVk));
        vm.stopPrank();
    }

    // =========================================================================
    //                      ENCODING DOCUMENTATION
    // =========================================================================

    /// @notice Document the correct encoding for MerkleTreeInsert precompile.
    ///         ABI: insert(bytes32 proofHash, bytes32 metadata) → (bytes32 newRoot, uint256 leafIndex)
    function test_correctInsertEncoding() public pure {
        bytes32 leafHash = keccak256(abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), uint256(1000)));
        bytes32 metadataHash = keccak256(abi.encodePacked(bytes32(uint256(2)), bytes32(uint256(3)), uint256(1000)));

        // Correct encoding: selector + abi.encode(bytes32, bytes32)
        bytes memory correctCalldata =
            abi.encodeWithSignature("insert(bytes32,bytes32)", leafHash, metadataHash);

        // Should be 4 (selector) + 64 (two bytes32) = 68 bytes
        assertEq(correctCalldata.length, 68, "insert calldata should be 68 bytes");

        // Current encoding: abi.encodePacked(leafHash, metadataHash)
        bytes memory currentCalldata = abi.encodePacked(leafHash, metadataHash);

        // Current is 64 bytes (missing 4-byte selector)
        assertEq(currentCalldata.length, 64, "current encoding is 64 bytes (no selector)");
    }

    /// @notice Document the correct encoding for MerkleTreeVerify precompile.
    ///         ABI: verify(bytes32, bytes32, uint256, bytes32[32], bytes32) → (bool)
    function test_correctVerifyEncoding() public pure {
        bytes32 leafHash = bytes32(uint256(1));
        bytes32 metadataHash = bytes32(uint256(2));
        uint256 leafIndex = 0;
        bytes32[32] memory merkleProof;
        bytes32 root = bytes32(uint256(0xdead));

        // Correct encoding with selector
        bytes memory correctCalldata = abi.encodeWithSignature(
            "verify(bytes32,bytes32,uint256,bytes32[32],bytes32)",
            leafHash,
            metadataHash,
            leafIndex,
            merkleProof,
            root
        );

        // Should be 4 (selector) + 1152 (data) = 1156 bytes
        assertEq(correctCalldata.length, 1156, "verify calldata should be 1156 bytes");
    }

    // =========================================================================
    //                     MERKLE INSERT TESTS
    // =========================================================================

    /// @notice Test registerProof with mocked MerkleInsert — validates contract logic
    function test_registerProof_fullFlow() public {
        // Mock both precompiles
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
        bytes32 mockRoot = bytes32(uint256(0xabcd));
        uint256 mockLeafIndex = 0;
        vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(mockRoot, mockLeafIndex));

        // Register prover + create + assign + submit
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(membershipPublicInputs);
        vm.prank(requester);
        bytes32 requestId = coordinator.requestProof{value: 0.01 ether}(
            CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours
        );

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        vm.prank(prover1);
        coordinator.submitProof(requestId, membershipProof, membershipVk, membershipPublicInputs);

        // Verify proof was registered
        assertEq(proofRegistry.totalProofs(), 1, "should have 1 proof");
        assertEq(proofRegistry.currentRoot(), mockRoot, "root should match mock");
    }

    /// @notice Test multiple proof registrations maintain consistency
    function test_multipleProofs_merkleConsistency() public {
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));

        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 prevRoot;
        for (uint256 i = 0; i < 5; i++) {
            bytes32 mockRoot = bytes32(uint256(0x1000 + i));
            vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(mockRoot, i));

            bytes32 pubInputsHash = keccak256(abi.encodePacked("inputs", i));
            vm.prank(requester);
            bytes32 requestId = coordinator.requestProof{value: 0.01 ether}(
                CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours
            );

            vm.prank(operator);
            coordinator.assignProver(requestId, prover1);

            // Use different proof bytes for each to avoid proofId collision
            bytes memory proof = abi.encodePacked(membershipProof, bytes32(uint256(i)));
            vm.prank(prover1);
            coordinator.submitProof(requestId, proof, membershipVk, abi.encodePacked(pubInputsHash));

            bytes32 newRoot = proofRegistry.currentRoot();
            assertTrue(newRoot != prevRoot, "root should change with each insert");
            prevRoot = newRoot;
        }

        assertEq(proofRegistry.totalProofs(), 5, "should have 5 proofs");
    }

    // =========================================================================
    //                     GAS BENCHMARKS
    // =========================================================================

    /// @notice Gas benchmark: registerProof (via coordinator.submitProof)
    function test_gasReport_registerProof() public {
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
        vm.mockCall(
            MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(0xdead)), uint256(0))
        );

        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(membershipPublicInputs);
        vm.prank(requester);
        bytes32 requestId = coordinator.requestProof{value: 0.01 ether}(
            CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours
        );

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        // Measure the full submitProof which includes registerProof internally
        vm.prank(prover1);
        uint256 gasBefore = gasleft();
        coordinator.submitProof(requestId, membershipProof, membershipVk, membershipPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("submitProof+registerProof gas (mocked precompiles)", gasUsed);
    }

    /// @notice Gas benchmark: isVerified
    function test_gasReport_isVerified() public {
        // Setup: register a proof first
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
        vm.mockCall(
            MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(0xdead)), uint256(0))
        );
        vm.mockCall(MERKLE_VERIFY_PRECOMPILE, bytes(""), abi.encode(true));

        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(membershipPublicInputs);
        vm.prank(requester);
        bytes32 requestId = coordinator.requestProof{value: 0.01 ether}(
            CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours
        );

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        vm.prank(prover1);
        coordinator.submitProof(requestId, membershipProof, membershipVk, membershipPublicInputs);

        // Get proofId
        bytes32 proofId = keccak256(abi.encodePacked(requestId, keccak256(membershipProof)));

        // Measure isVerified gas
        bytes32[] memory dummyMerkleProof = new bytes32[](TREE_DEPTH);
        uint256 gasBefore = gasleft();
        proofRegistry.isVerified(proofId, dummyMerkleProof);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("isVerified gas (mocked precompile)", gasUsed);
    }
}
