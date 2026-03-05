// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestUtils} from "./helpers/TestUtils.sol";
import {Coordinator} from "../src/Coordinator.sol";
import {ICoordinator} from "../src/interfaces/ICoordinator.sol";

/// @title CoordinatorTest
/// @notice Comprehensive test suite for the Coordinator contract covering
///         construction, admin operations, request flow, assignment, proof
///         submission (success and failure), and fuzz testing.
/// @dev Inherits TestUtils which deploys all contracts, registers two circuits
///      (CIRCUIT_MEMBERSHIP and CIRCUIT_AGE), and funds test actors.
contract CoordinatorTest is TestUtils {
    // =========================================================================
    //                          TEST CONSTANTS
    // =========================================================================

    /// @dev Dummy public inputs hash used across tests
    bytes32 constant DUMMY_INPUTS_HASH = keccak256("age=18");

    /// @dev Dummy proof bytes for submitProof calls
    bytes constant DUMMY_PROOF = hex"deadbeef";

    /// @dev Dummy public inputs bytes for submitProof calls
    bytes constant DUMMY_PUBLIC_INPUTS = hex"cafebabe";

    /// @dev Default fee used in proof requests
    uint256 constant DEFAULT_FEE = 0.01 ether;

    /// @dev Default deadline offset from current block.timestamp
    uint256 constant DEADLINE_OFFSET = 1 hours;

    // =========================================================================
    //                      CONSTRUCTION & ADMIN TESTS
    // =========================================================================

    /// @notice Verify that the constructor sets all immutables and mutable state correctly
    function test_constructor_setsImmutables() public view {
        assertEq(address(coordinator.proverRegistry()), address(proverRegistry), "proverRegistry mismatch");
        assertEq(address(coordinator.proofRegistry()), address(proofRegistry), "proofRegistry mismatch");
        assertEq(coordinator.verifyPrecompile(), VERIFY_PRECOMPILE, "verifyPrecompile mismatch");
        assertEq(coordinator.operator(), operator, "operator mismatch");
        assertEq(coordinator.minFee(), MIN_FEE, "minFee mismatch");
    }

    /// @notice Constructor must revert with ZeroAddress if any address parameter is zero
    function test_constructor_revertsOnZeroAddress() public {
        // Zero proverRegistry
        vm.expectRevert(Coordinator.ZeroAddress.selector);
        new Coordinator(address(0), address(proofRegistry), VERIFY_PRECOMPILE, operator, MIN_FEE);

        // Zero proofRegistry
        vm.expectRevert(Coordinator.ZeroAddress.selector);
        new Coordinator(address(proverRegistry), address(0), VERIFY_PRECOMPILE, operator, MIN_FEE);

        // Zero verifyPrecompile
        vm.expectRevert(Coordinator.ZeroAddress.selector);
        new Coordinator(address(proverRegistry), address(proofRegistry), address(0), operator, MIN_FEE);

        // Zero operator
        vm.expectRevert(Coordinator.ZeroAddress.selector);
        new Coordinator(address(proverRegistry), address(proofRegistry), VERIFY_PRECOMPILE, address(0), MIN_FEE);
    }

    /// @notice Operator can register a new circuit with valid circuitId and vkHash
    function test_registerCircuit_success() public {
        bytes32 newCircuitId = keccak256("proof-of-balance");
        bytes32 newVkHash = bytes32(uint256(0xaabb));

        vm.expectEmit(true, true, false, false);
        emit Coordinator.CircuitRegistered(newCircuitId, newVkHash);

        vm.prank(operator);
        coordinator.registerCircuit(newCircuitId, newVkHash);

        assertEq(coordinator.registeredCircuits(newCircuitId), newVkHash, "circuit vkHash not stored");
    }

    /// @notice A non-operator address cannot register circuits
    function test_registerCircuit_revertsIfNotOperator() public {
        bytes32 newCircuitId = keccak256("proof-of-balance");
        bytes32 newVkHash = bytes32(uint256(0xaabb));

        vm.expectRevert(ICoordinator.Unauthorized.selector);
        vm.prank(stranger);
        coordinator.registerCircuit(newCircuitId, newVkHash);
    }

    /// @notice Cannot register a circuit that already has a non-zero vkHash
    function test_registerCircuit_revertsIfAlreadyRegistered() public {
        // CIRCUIT_MEMBERSHIP was already registered in setUp()
        bytes32 anotherVkHash = bytes32(uint256(0xffff));

        vm.expectRevert(Coordinator.CircuitAlreadyRegistered.selector);
        vm.prank(operator);
        coordinator.registerCircuit(CIRCUIT_MEMBERSHIP, anotherVkHash);
    }

    /// @notice Operator can transfer operator role to a new address
    function test_setOperator_success() public {
        address newOperator = makeAddr("newOperator");

        vm.expectEmit(true, true, false, false);
        emit Coordinator.OperatorUpdated(operator, newOperator);

        vm.prank(operator);
        coordinator.setOperator(newOperator);

        assertEq(coordinator.operator(), newOperator, "operator not updated");
    }

    /// @notice Operator can update the minimum fee
    function test_setMinFee_success() public {
        uint256 newMinFee = 0.05 ether;

        vm.expectEmit(false, false, false, true);
        emit Coordinator.MinFeeUpdated(MIN_FEE, newMinFee);

        vm.prank(operator);
        coordinator.setMinFee(newMinFee);

        assertEq(coordinator.minFee(), newMinFee, "minFee not updated");
    }

    // =========================================================================
    //                          REQUEST FLOW TESTS
    // =========================================================================

    /// @notice Successfully create a proof request and verify struct fields + event
    function test_requestProof_success() public {
        uint256 fee = DEFAULT_FEE;
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;

        // Expect the ProofRequested event
        // We cannot predict requestId easily, so check topic 2 (circuitId) and topic 3 (requester)
        vm.expectEmit(false, true, true, false);
        emit ICoordinator.ProofRequested(bytes32(0), CIRCUIT_MEMBERSHIP, requester, fee, deadline);

        vm.prank(requester);
        bytes32 requestId = coordinator.requestProof{value: fee}(CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, deadline);

        // Verify the request struct
        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(req.requestId, requestId, "requestId mismatch");
        assertEq(req.circuitId, CIRCUIT_MEMBERSHIP, "circuitId mismatch");
        assertEq(req.requester, requester, "requester mismatch");
        assertEq(req.maxFee, fee, "maxFee mismatch");
        assertEq(req.deadline, deadline, "deadline mismatch");
        assertEq(req.assignedProver, address(0), "assignedProver should be zero");
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Pending), "status should be Pending");
        assertEq(req.createdAt, block.timestamp, "createdAt mismatch");

        // Verify public inputs hash stored
        assertEq(coordinator.getRequestPublicInputsHash(requestId), DUMMY_INPUTS_HASH, "publicInputsHash mismatch");

        // Verify nonce incremented
        assertEq(coordinator.nonces(requester), 1, "nonce should be 1 after first request");
    }

    /// @notice Request reverts if the circuitId is not registered
    function test_requestProof_revertsIfInvalidCircuit() public {
        bytes32 unregisteredCircuit = keccak256("proof-of-unicorn");
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;

        vm.expectRevert(ICoordinator.InvalidCircuitId.selector);
        vm.prank(requester);
        coordinator.requestProof{value: DEFAULT_FEE}(unregisteredCircuit, DUMMY_INPUTS_HASH, deadline);
    }

    /// @notice Request reverts if fee is below minFee
    function test_requestProof_revertsIfInsufficientFee() public {
        uint256 tooLowFee = MIN_FEE - 1;
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;

        vm.expectRevert(ICoordinator.InsufficientFee.selector);
        vm.prank(requester);
        coordinator.requestProof{value: tooLowFee}(CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, deadline);
    }

    /// @notice Request reverts if deadline is not in the future
    function test_requestProof_revertsIfInvalidDeadline() public {
        // Deadline equal to current timestamp (not strictly in the future)
        uint256 deadlineNow = block.timestamp;

        vm.expectRevert(ICoordinator.InvalidDeadline.selector);
        vm.prank(requester);
        coordinator.requestProof{value: DEFAULT_FEE}(CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, deadlineNow);

        // Deadline in the past
        uint256 deadlinePast = block.timestamp - 1;

        vm.expectRevert(ICoordinator.InvalidDeadline.selector);
        vm.prank(requester);
        coordinator.requestProof{value: DEFAULT_FEE}(CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, deadlinePast);
    }

    // =========================================================================
    //                          ASSIGNMENT TESTS
    // =========================================================================

    /// @notice Operator can assign an active prover to a pending request
    function test_assignProver_success() public {
        // Register prover so they are active in ProverRegistry
        _registerProver(prover1, MIN_STAKE);

        // Create a pending request
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;
        bytes32 requestId = _createRequest(requester, CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, DEFAULT_FEE, deadline);

        // Expect ProofAssigned event
        vm.expectEmit(true, true, false, false);
        emit ICoordinator.ProofAssigned(requestId, prover1);

        // Assign
        _assignProver(requestId, prover1);

        // Verify the request was updated
        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(req.assignedProver, prover1, "assignedProver mismatch");
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Assigned), "status should be Assigned");
    }

    /// @notice A non-operator cannot assign provers
    function test_assignProver_revertsIfNotOperator() public {
        _registerProver(prover1, MIN_STAKE);

        uint256 deadline = block.timestamp + DEADLINE_OFFSET;
        bytes32 requestId = _createRequest(requester, CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, DEFAULT_FEE, deadline);

        vm.expectRevert(ICoordinator.Unauthorized.selector);
        vm.prank(stranger);
        coordinator.assignProver(requestId, prover1);
    }

    /// @notice Cannot assign an inactive / unregistered prover
    function test_assignProver_revertsIfProverNotActive() public {
        // prover1 is NOT registered, so isActive returns false
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;
        bytes32 requestId = _createRequest(requester, CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, DEFAULT_FEE, deadline);

        vm.expectRevert(ICoordinator.ProverNotRegistered.selector);
        vm.prank(operator);
        coordinator.assignProver(requestId, prover1);
    }

    // =========================================================================
    //                          SUBMIT PROOF TESTS
    // =========================================================================

    /// @notice Full happy path: request -> assign -> mock precompiles -> submit
    ///         Verifies status=Verified, fee transferred to prover, and events emitted
    function test_submitProof_success() public {
        // 1. Register prover
        _registerProver(prover1, MIN_STAKE);

        // 2. Create and assign request
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;
        bytes32 requestId =
            _createAndAssignRequest(requester, prover1, CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, DEFAULT_FEE, deadline);

        // 3. Mock precompiles
        _mockVerifySuccess();
        _mockMerkleInsert(bytes32(uint256(1)), 0);

        // 4. Record prover balance before submission
        uint256 proverBalanceBefore = prover1.balance;

        // 5. Submit proof as the assigned prover
        vm.prank(prover1);
        coordinator.submitProof(requestId, DUMMY_PROOF, vkMembership, DUMMY_PUBLIC_INPUTS);

        // 6. Verify request status is Verified
        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Verified), "status should be Verified");

        // 7. Verify fee transferred to prover
        uint256 proverBalanceAfter = prover1.balance;
        assertEq(proverBalanceAfter - proverBalanceBefore, DEFAULT_FEE, "prover should have received the fee");

        // 8. Verify the proof was registered in ProofRegistry
        assertEq(proofRegistry.totalProofs(), 1, "proof should be registered in ProofRegistry");
    }

    /// @notice Verification failure: mock verify returns 0x00, status should be Failed,
    ///         no fee transfer to prover
    function test_submitProof_failure() public {
        // 1. Register prover
        _registerProver(prover1, MIN_STAKE);

        // 2. Create and assign request
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;
        bytes32 requestId =
            _createAndAssignRequest(requester, prover1, CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, DEFAULT_FEE, deadline);

        // 3. Mock verify to FAIL, no need to mock Merkle insert (should not be reached)
        _mockVerifyFailure();

        // 4. Record prover balance
        uint256 proverBalanceBefore = prover1.balance;

        // 5. Expect ProofRejected event
        vm.expectEmit(true, true, false, false);
        emit ICoordinator.ProofRejected(requestId, prover1, "verification_failed");

        // 6. Submit proof
        vm.prank(prover1);
        coordinator.submitProof(requestId, DUMMY_PROOF, vkMembership, DUMMY_PUBLIC_INPUTS);

        // 7. Verify status is Failed
        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Failed), "status should be Failed");

        // 8. Verify NO fee was transferred
        assertEq(prover1.balance, proverBalanceBefore, "prover balance should be unchanged on failure");

        // 9. Verify no proof registered in ProofRegistry
        assertEq(proofRegistry.totalProofs(), 0, "no proof should be registered on failure");
    }

    /// @notice Only the assigned prover can submit a proof, not a different prover
    function test_submitProof_revertsIfNotAssignedProver() public {
        // Register both provers
        _registerProver(prover1, MIN_STAKE);
        _registerProver(prover2, MIN_STAKE);

        // Create and assign to prover1
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;
        bytes32 requestId =
            _createAndAssignRequest(requester, prover1, CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, DEFAULT_FEE, deadline);

        _mockVerifySuccess();
        _mockMerkleInsert(bytes32(uint256(1)), 0);

        // prover2 tries to submit -- should revert Unauthorized
        vm.expectRevert(ICoordinator.Unauthorized.selector);
        vm.prank(prover2);
        coordinator.submitProof(requestId, DUMMY_PROOF, vkMembership, DUMMY_PUBLIC_INPUTS);
    }

    /// @notice Cannot submit a proof after the request deadline has passed
    function test_submitProof_revertsIfExpired() public {
        // Register prover
        _registerProver(prover1, MIN_STAKE);

        // Create and assign request with a deadline 1 hour from now
        uint256 deadline = block.timestamp + DEADLINE_OFFSET;
        bytes32 requestId =
            _createAndAssignRequest(requester, prover1, CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, DEFAULT_FEE, deadline);

        // Warp past the deadline
        vm.warp(deadline + 1);

        _mockVerifySuccess();
        _mockMerkleInsert(bytes32(uint256(1)), 0);

        vm.expectRevert(ICoordinator.RequestExpired.selector);
        vm.prank(prover1);
        coordinator.submitProof(requestId, DUMMY_PROOF, vkMembership, DUMMY_PUBLIC_INPUTS);
    }

    // =========================================================================
    //                              FUZZ TESTS
    // =========================================================================

    /// @notice Any fee at or above minFee should create a valid request
    /// @param fee Fuzzed fee amount bounded between minFee and 10 ether
    function testFuzz_requestProof_anyFeeAboveMin(uint256 fee) public {
        fee = bound(fee, MIN_FEE, 10 ether);

        uint256 deadline = block.timestamp + DEADLINE_OFFSET;

        vm.prank(requester);
        bytes32 requestId = coordinator.requestProof{value: fee}(CIRCUIT_MEMBERSHIP, DUMMY_INPUTS_HASH, deadline);

        // Verify the request was stored with the correct fee
        ICoordinator.ProofRequest memory req = coordinator.getRequest(requestId);
        assertEq(req.maxFee, fee, "maxFee should match the sent value");
        assertEq(uint8(req.status), uint8(ICoordinator.ProofStatus.Pending), "status should be Pending");
        assertEq(req.circuitId, CIRCUIT_MEMBERSHIP, "circuitId mismatch");
    }
}
