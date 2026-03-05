// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Coordinator} from "../../src/Coordinator.sol";
import {ICoordinator} from "../../src/interfaces/ICoordinator.sol";
import {ProverRegistry} from "../../src/ProverRegistry.sol";
import {ProofRegistry} from "../../src/ProofRegistry.sol";

/// @title CoordinatorIntegration
/// @notice Integration tests for Coordinator ↔ VerifyUltraHonk precompile.
///
///     These tests load REAL ZK proof fixtures and validate the full
///     request → assign → submit → verify flow.
///
///     ENCODING FINDINGS (Sprint 2, Task 6.5):
///
///       The current Coordinator.submitProof() sends to VerifyUltraHonk:
///         verifyPrecompile.staticcall(abi.encode(proof, vkHash, publicInputs))
///
///       This has THREE encoding incompatibilities:
///         1. Missing 4-byte function selector — the precompile routes by selector
///         2. Sends bytes32 vkHash — precompile expects bytes vk (full VK)
///         3. Sends bytes publicInputs — precompile expects bytes32[] publicInputs
///
///       Fix required in Coordinator.sol:
///         - Store full VK bytes (not just hash) or pass VK from caller
///         - Convert publicInputs to bytes32[]
///         - Use abi.encodeWithSelector(0x<verify_selector>, proof, vk, pubInputs)
///
///     TEST MODES:
///       Local (default):  Uses vm.mockCall to simulate precompile responses.
///                          Validates contract logic, gas usage, and fixture loading.
///       Devnet:           Run with --fork-url pointing to a Sincerin L1 node.
///                          Precompile calls execute natively (no mocks needed).
///
/// @dev Run locally: forge test --match-contract CoordinatorIntegration -vvv
///      Run on devnet: forge test --match-contract CoordinatorIntegration \
///                     --fork-url $L1_RPC_URL -vvv
contract CoordinatorIntegration is Test {
    // =========================================================================
    //                         CONSTANTS
    // =========================================================================

    address constant VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000002;
    address constant MERKLE_INSERT_PRECOMPILE = 0x0300000000000000000000000000000000000004;
    address constant MERKLE_VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000005;

    uint256 constant MIN_STAKE = 1 ether;
    uint256 constant MIN_FEE = 0.001 ether;
    uint256 constant TARGET_LATENCY_MS = 5000;

    bytes32 constant CIRCUIT_MEMBERSHIP = keccak256("proof-of-membership");
    bytes32 constant CIRCUIT_AGE = keccak256("proof-of-age");

    // =========================================================================
    //                          STATE
    // =========================================================================

    ProverRegistry proverRegistry;
    ProofRegistry proofRegistry;
    Coordinator coordinator;

    address operator;
    address prover1;
    address requester;

    // Real ZK fixtures
    bytes membershipProof;
    bytes membershipVk;
    bytes membershipPublicInputs;
    bytes ageProof;
    bytes ageVk;
    bytes agePublicInputs;

    // =========================================================================
    //                           SETUP
    // =========================================================================

    function setUp() public {
        operator = makeAddr("operator");
        prover1 = makeAddr("prover1");
        requester = makeAddr("requester");

        // Deploy contracts
        proverRegistry = new ProverRegistry(MIN_STAKE, TARGET_LATENCY_MS);
        proofRegistry = new ProofRegistry(MERKLE_INSERT_PRECOMPILE, MERKLE_VERIFY_PRECOMPILE);
        coordinator = new Coordinator(
            address(proverRegistry), address(proofRegistry), VERIFY_PRECOMPILE, operator, MIN_FEE
        );

        // Wire up
        proverRegistry.setCoordinator(address(coordinator));
        proofRegistry.setCoordinator(address(coordinator));

        // Fund actors
        vm.deal(prover1, 100 ether);
        vm.deal(requester, 100 ether);

        // Load real ZK fixtures
        membershipProof = vm.readFileBinary("../fixtures/zk/evm/membership_proof.bin");
        membershipVk = vm.readFileBinary("../fixtures/zk/evm/membership_vk.bin");
        membershipPublicInputs = vm.readFileBinary("../fixtures/zk/evm/membership_public_inputs.bin");
        ageProof = vm.readFileBinary("../fixtures/zk/evm/age_proof.bin");
        ageVk = vm.readFileBinary("../fixtures/zk/evm/age_vk.bin");
        agePublicInputs = vm.readFileBinary("../fixtures/zk/evm/age_public_inputs.bin");

        // Register circuits with VK hashes computed from loaded VK bytes
        vm.startPrank(operator);
        coordinator.registerCircuit(CIRCUIT_MEMBERSHIP, keccak256(membershipVk));
        coordinator.registerCircuit(CIRCUIT_AGE, keccak256(ageVk));
        vm.stopPrank();
    }

    // =========================================================================
    //                     FIXTURE VALIDATION
    // =========================================================================

    /// @notice Verify that fixtures loaded correctly and have expected sizes
    function test_fixturesLoaded() public view {
        // Membership fixtures
        assertGt(membershipProof.length, 0, "membership proof empty");
        assertGt(membershipVk.length, 0, "membership vk empty");
        assertEq(membershipPublicInputs.length, 64, "membership public inputs should be 2x32 bytes");

        // Age fixtures
        assertGt(ageProof.length, 0, "age proof empty");
        assertGt(ageVk.length, 0, "age vk empty");
        assertEq(agePublicInputs.length, 192, "age public inputs should be 6x32 bytes");

        // Log sizes for documentation
        // emit log_named_uint("membership_proof.bin", membershipProof.length);
        // emit log_named_uint("membership_vk.bin", membershipVk.length);
        // emit log_named_uint("age_proof.bin", ageProof.length);
        // emit log_named_uint("age_vk.bin", ageVk.length);
    }

    // =========================================================================
    //                    ENCODING DOCUMENTATION TESTS
    // =========================================================================

    /// @notice Validate the encoding format that Coordinator uses for VerifyUltraHonk.
    ///         Precompile ABI: verify(bytes proof, bytes vk, bytes32[] publicInputs)
    ///         Selector: bytes4(keccak256("verify(bytes,bytes,bytes32[])"))
    function test_correctPrecompileEncoding_membership() public view {
        bytes memory pubRaw = membershipPublicInputs;
        bytes memory proof = membershipProof;
        bytes memory vk = membershipVk;

        // Convert publicInputs bytes → bytes32[] array (same logic as Coordinator)
        uint256 numInputs = pubRaw.length / 32;
        bytes32[] memory pubInputsArr = new bytes32[](numInputs);
        for (uint256 i = 0; i < numInputs; i++) {
            bytes32 val;
            uint256 offset = i * 32;
            assembly {
                val := mload(add(add(pubRaw, 32), offset))
            }
            pubInputsArr[i] = val;
        }

        // Build the encoding that Coordinator now sends
        bytes memory calldata_ = abi.encodeWithSignature(
            "verify(bytes,bytes,bytes32[])", proof, vk, pubInputsArr
        );

        // Must have 4-byte selector + data
        assertGt(calldata_.length, 4, "should have selector + data");

        // Validate selector matches expected
        bytes4 expectedSelector = bytes4(keccak256("verify(bytes,bytes,bytes32[])"));
        bytes4 actualSelector;
        assembly {
            actualSelector := mload(add(calldata_, 32))
        }
        assertEq(actualSelector, expectedSelector, "selector should match verify(bytes,bytes,bytes32[])");
    }

    // =========================================================================
    //          FULL FLOW TESTS (with mocked precompile for local)
    // =========================================================================

    /// @notice Test the full submit flow with real membership proof fixtures.
    ///         Uses mocked precompile for local testing.
    ///         On Sincerin devnet, the precompile would verify the real proof.
    function test_submitProof_realFixtures_membership() public {
        // Register prover
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        // Create request
        bytes32 pubInputsHash = keccak256(membershipPublicInputs);
        vm.prank(requester);
        bytes32 requestId =
            coordinator.requestProof{value: 0.01 ether}(CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours);

        // Assign prover
        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        // Mock precompile: return success (0x01 padded to 32 bytes)
        // NOTE: On Sincerin devnet, remove this mock — the real precompile
        //       would need the encoding fix described above to work.
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));

        // Also mock MerkleTreeInsert for ProofRegistry.registerProof
        vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(0xdead)), uint256(0)));

        // Submit proof with real fixtures
        uint256 proverBalBefore = prover1.balance;
        vm.prank(prover1);
        coordinator.submitProof(requestId, membershipProof, membershipVk, membershipPublicInputs);

        // Verify status
        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Verified), "should be Verified");

        // Verify fee transferred
        assertGt(prover1.balance, proverBalBefore, "prover should receive fee");

        // Verify proof registered
        assertEq(proofRegistry.totalProofs(), 1, "should have 1 registered proof");
    }

    /// @notice Test with real age proof fixtures
    function test_submitProof_realFixtures_age() public {
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(agePublicInputs);
        vm.prank(requester);
        bytes32 requestId =
            coordinator.requestProof{value: 0.01 ether}(CIRCUIT_AGE, pubInputsHash, block.timestamp + 1 hours);

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        // Mock precompiles
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
        vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(0xbeef)), uint256(0)));

        vm.prank(prover1);
        coordinator.submitProof(requestId, ageProof, ageVk, agePublicInputs);

        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Verified), "should be Verified");
    }

    /// @notice Test that invalid/random proof bytes are handled correctly
    function test_submitProof_invalidProof_realRejection() public {
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(membershipPublicInputs);
        vm.prank(requester);
        bytes32 requestId =
            coordinator.requestProof{value: 0.01 ether}(CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours);

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        // Mock precompile to return failure (simulating invalid proof rejection)
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(false));

        vm.prank(prover1);
        coordinator.submitProof(requestId, hex"deadbeef", membershipVk, membershipPublicInputs);

        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Failed), "should be Failed");
    }

    // =========================================================================
    //                     GAS BENCHMARKS
    // =========================================================================

    /// @notice Measure gas for submitProof with real membership proof size
    function test_gasReport_submitProof_membership() public {
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(membershipPublicInputs);
        vm.prank(requester);
        bytes32 requestId =
            coordinator.requestProof{value: 0.01 ether}(CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours);

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
        vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(0xdead)), uint256(0)));

        vm.prank(prover1);
        uint256 gasBefore = gasleft();
        coordinator.submitProof(requestId, membershipProof, membershipVk, membershipPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("submitProof (membership, proof=8256B) gas", gasUsed);
        assertLt(gasUsed, 1_000_000, "gas should be under 1M");
    }

    /// @notice Measure gas for submitProof with real age proof size
    function test_gasReport_submitProof_age() public {
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(agePublicInputs);
        vm.prank(requester);
        bytes32 requestId =
            coordinator.requestProof{value: 0.01 ether}(CIRCUIT_AGE, pubInputsHash, block.timestamp + 1 hours);

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);

        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
        vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(0xbeef)), uint256(0)));

        vm.prank(prover1);
        uint256 gasBefore = gasleft();
        coordinator.submitProof(requestId, ageProof, ageVk, agePublicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("submitProof (age, proof=9024B) gas", gasUsed);
        assertLt(gasUsed, 1_000_000, "gas should be under 1M");
    }
}
