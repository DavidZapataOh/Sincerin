// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Coordinator} from "../../src/Coordinator.sol";
import {ICoordinator} from "../../src/interfaces/ICoordinator.sol";
import {ProverRegistry} from "../../src/ProverRegistry.sol";
import {IProverRegistry} from "../../src/interfaces/IProverRegistry.sol";
import {ProofRegistry} from "../../src/ProofRegistry.sol";

/// @title GasBenchmark
/// @notice Measures gas cost of all critical operations with real-sized data.
///
///     Gas estimates (from plan):
///       submitProof (membership):      ~30-50K total (20K precompile + contract)
///       submitProof (age):             ~30-50K total
///       registerProof:                 included in submitProof
///       isVerified:                    ~1-5K
///       ProverRegistry.register:       ~150-200K
///       ProverRegistry.updateReputation: ~40-80K
///
///     NOTE: Gas numbers here measure Solidity contract overhead only.
///     Precompile gas is fixed (mocked) and would be:
///       VerifyUltraHonk:  20,000
///       MerkleTreeInsert:    500
///       MerkleTreeVerify:    300
///
/// @dev Run: forge test --match-contract GasBenchmark -vvv --gas-report
contract GasBenchmark is Test {
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
    bytes32 constant CIRCUIT_AGE = keccak256("proof-of-age");

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
        ageProof = vm.readFileBinary("../fixtures/zk/evm/age_proof.bin");
        ageVk = vm.readFileBinary("../fixtures/zk/evm/age_vk.bin");
        agePublicInputs = vm.readFileBinary("../fixtures/zk/evm/age_public_inputs.bin");

        vm.startPrank(operator);
        coordinator.registerCircuit(CIRCUIT_MEMBERSHIP, keccak256(membershipVk));
        coordinator.registerCircuit(CIRCUIT_AGE, keccak256(ageVk));
        vm.stopPrank();

        // Mock precompiles for all tests
        vm.mockCall(VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
        vm.mockCall(MERKLE_INSERT_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(0xdead)), uint256(0)));
        vm.mockCall(MERKLE_VERIFY_PRECOMPILE, bytes(""), abi.encode(true));
    }

    // =========================================================================
    //                      GAS: ProverRegistry
    // =========================================================================

    /// @notice Gas for prover registration (includes staking)
    function test_gasReport_register() public {
        address newProver = makeAddr("newProver");
        vm.deal(newProver, 10 ether);

        vm.prank(newProver);
        uint256 gasBefore = gasleft();
        proverRegistry.register{value: MIN_STAKE}();
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("ProverRegistry.register gas", gasUsed);
        assertLt(gasUsed, 300_000, "register should be < 300K gas");
    }

    /// @notice Gas for reputation update (called internally by submitProof)
    function test_gasReport_updateReputation() public {
        // Register prover first
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        // updateReputation is only callable by coordinator
        vm.prank(address(coordinator));
        uint256 gasBefore = gasleft();
        proverRegistry.updateReputation(prover1, 2000, true); // 2s latency, success
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("ProverRegistry.updateReputation gas", gasUsed);
        assertLt(gasUsed, 100_000, "updateReputation should be < 100K gas");
    }

    // =========================================================================
    //                      GAS: Coordinator.submitProof
    // =========================================================================

    function _setupSubmit(bytes32 circuitId, bytes memory pubInputs) internal returns (bytes32 requestId) {
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256(pubInputs);
        vm.prank(requester);
        requestId = coordinator.requestProof{value: 0.01 ether}(circuitId, pubInputsHash, block.timestamp + 1 hours);

        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);
    }

    /// @notice submitProof gas with membership proof (8256 bytes)
    function test_gasReport_submitProof_membership() public {
        bytes32 requestId = _setupSubmit(CIRCUIT_MEMBERSHIP, membershipPublicInputs);

        vm.prank(prover1);
        uint256 gasBefore = gasleft();
        coordinator.submitProof(requestId, membershipProof, membershipVk, membershipPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("submitProof (membership, 8256B proof) gas", gasUsed);
        assertLt(gasUsed, 1_000_000, "submitProof should be < 1M gas");
    }

    /// @notice submitProof gas with age proof (9024 bytes)
    function test_gasReport_submitProof_age() public {
        bytes32 requestId = _setupSubmit(CIRCUIT_AGE, agePublicInputs);

        vm.prank(prover1);
        uint256 gasBefore = gasleft();
        coordinator.submitProof(requestId, ageProof, ageVk, agePublicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("submitProof (age, 9024B proof) gas", gasUsed);
        assertLt(gasUsed, 1_000_000, "submitProof should be < 1M gas");
    }

    // =========================================================================
    //                      GAS: ProofRegistry.isVerified
    // =========================================================================

    /// @notice isVerified gas (view function)
    function test_gasReport_isVerified() public {
        bytes32 requestId = _setupSubmit(CIRCUIT_MEMBERSHIP, membershipPublicInputs);

        vm.prank(prover1);
        coordinator.submitProof(requestId, membershipProof, membershipVk, membershipPublicInputs);

        bytes32 proofId = keccak256(abi.encodePacked(requestId, keccak256(membershipProof)));
        bytes32[] memory merkleProof = new bytes32[](TREE_DEPTH);

        uint256 gasBefore = gasleft();
        proofRegistry.isVerified(proofId, merkleProof);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("isVerified gas", gasUsed);
        assertLt(gasUsed, 50_000, "isVerified should be < 50K gas");
    }

    // =========================================================================
    //                      GAS: requestProof
    // =========================================================================

    /// @notice requestProof gas (creates a new request)
    function test_gasReport_requestProof() public {
        bytes32 pubInputsHash = keccak256("test");

        vm.prank(requester);
        uint256 gasBefore = gasleft();
        coordinator.requestProof{value: 0.01 ether}(CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("requestProof gas", gasUsed);
        assertLt(gasUsed, 200_000, "requestProof should be < 200K gas");
    }

    /// @notice assignProver gas
    function test_gasReport_assignProver() public {
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();

        bytes32 pubInputsHash = keccak256("test");
        vm.prank(requester);
        bytes32 requestId = coordinator.requestProof{value: 0.01 ether}(
            CIRCUIT_MEMBERSHIP, pubInputsHash, block.timestamp + 1 hours
        );

        vm.prank(operator);
        uint256 gasBefore = gasleft();
        coordinator.assignProver(requestId, prover1);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("assignProver gas", gasUsed);
        assertLt(gasUsed, 100_000, "assignProver should be < 100K gas");
    }

    // =========================================================================
    //                     COMPARISON TABLE
    // =========================================================================

    /// @notice Emit a summary comparison table of all gas measurements.
    ///         Run with -vvv to see the table in console output.
    function test_gasComparisonTable() public {
        // --- Register ---
        address p = makeAddr("benchProver");
        vm.deal(p, 100 ether);
        vm.prank(p);
        uint256 g1 = gasleft();
        proverRegistry.register{value: MIN_STAKE}();
        uint256 gasRegister = g1 - gasleft();

        // --- Request ---
        vm.prank(requester);
        g1 = gasleft();
        bytes32 rid = coordinator.requestProof{value: 0.01 ether}(
            CIRCUIT_MEMBERSHIP, keccak256(membershipPublicInputs), block.timestamp + 1 hours
        );
        uint256 gasRequest = g1 - gasleft();

        // --- Assign ---
        vm.prank(operator);
        g1 = gasleft();
        coordinator.assignProver(rid, p);
        uint256 gasAssign = g1 - gasleft();

        // --- Submit (membership) ---
        vm.prank(p);
        g1 = gasleft();
        coordinator.submitProof(rid, membershipProof, membershipVk, membershipPublicInputs);
        uint256 gasSubmit = g1 - gasleft();

        // --- isVerified ---
        bytes32 proofId = keccak256(abi.encodePacked(rid, keccak256(membershipProof)));
        bytes32[] memory mp = new bytes32[](TREE_DEPTH);
        g1 = gasleft();
        proofRegistry.isVerified(proofId, mp);
        uint256 gasVerify = g1 - gasleft();

        // --- Emit table ---
        emit log("=== Gas Benchmark Summary (mocked precompiles) ===");
        emit log_named_uint("  register             ", gasRegister);
        emit log_named_uint("  requestProof         ", gasRequest);
        emit log_named_uint("  assignProver         ", gasAssign);
        emit log_named_uint("  submitProof (8256B)  ", gasSubmit);
        emit log_named_uint("  isVerified           ", gasVerify);
        emit log("");
        emit log("Precompile gas (not included above, fixed cost):");
        emit log("  VerifyUltraHonk:  20,000");
        emit log("  MerkleTreeInsert:    500");
        emit log("  MerkleTreeVerify:    300");
    }
}
