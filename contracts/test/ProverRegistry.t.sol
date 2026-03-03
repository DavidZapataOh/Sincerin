// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestUtils} from "./helpers/TestUtils.sol";
import {IProverRegistry} from "../src/interfaces/IProverRegistry.sol";
import {ProverRegistry} from "../src/ProverRegistry.sol";

/// @title ProverRegistryTest
/// @notice Comprehensive unit and fuzz tests for ProverRegistry
/// @dev Inherits TestUtils for shared deployment, actors, and helpers.
///      Uses vm.prank(address(coordinator)) to call onlyCoordinator functions
///      directly on the shared proverRegistry instance.
contract ProverRegistryTest is TestUtils {
    // =========================================================================
    //                          CONSTANTS (mirrored)
    // =========================================================================

    /// @dev Mirrors ProverRegistry.MAX_REPUTATION (private constant)
    uint256 private constant MAX_REPUTATION = 10_000;

    /// @dev Mirrors ProverRegistry.INITIAL_REPUTATION (private constant)
    uint256 private constant INITIAL_REPUTATION = 5_000;

    /// @dev Mirrors ProverRegistry.FAILURE_PENALTY (private constant)
    uint256 private constant FAILURE_PENALTY = 500;

    /// @dev Mirrors ProverRegistry.LATENCY_CEILING_MULTIPLIER (private constant)
    uint256 private constant LATENCY_CEILING_MULTIPLIER = 5;

    // =========================================================================
    //                       REGISTRATION — UNIT TESTS
    // =========================================================================

    /// @notice Register with exact minStake, verify all ProverInfo fields
    function test_register_success() public {
        _registerProver(prover1, MIN_STAKE);

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertEq(info.proverAddress, prover1, "proverAddress mismatch");
        assertEq(info.stake, MIN_STAKE, "stake mismatch");
        assertEq(info.reputation, INITIAL_REPUTATION, "reputation should be INITIAL_REPUTATION");
        assertEq(info.totalProofs, 0, "totalProofs should be 0");
        assertEq(info.failedProofs, 0, "failedProofs should be 0");
        assertEq(info.totalLatency, 0, "totalLatency should be 0");
        assertTrue(info.active, "prover should be active");
        assertEq(info.registeredAt, block.timestamp, "registeredAt mismatch");
        assertEq(proverRegistry.getProverCount(), 1, "proverCount should be 1");
    }

    /// @notice Registration emits ProverRegistered with correct parameters
    function test_register_emitsEvent() public {
        vm.expectEmit(true, false, false, true, address(proverRegistry));
        emit IProverRegistry.ProverRegistered(prover1, MIN_STAKE);

        _registerProver(prover1, MIN_STAKE);
    }

    /// @notice Re-registering while active reverts with ProverAlreadyRegistered
    function test_register_revertsIfAlreadyActive() public {
        _registerProver(prover1, MIN_STAKE);

        vm.expectRevert(IProverRegistry.ProverAlreadyRegistered.selector);
        vm.prank(prover1);
        proverRegistry.register{value: MIN_STAKE}();
    }

    /// @notice Registration below minStake reverts with InsufficientStake
    function test_register_revertsIfInsufficientStake() public {
        uint256 belowMin = MIN_STAKE - 1;

        vm.expectRevert(IProverRegistry.InsufficientStake.selector);
        vm.prank(prover1);
        proverRegistry.register{value: belowMin}();
    }

    /// @notice Deregister then re-register the same address -- verify clean state
    function test_register_reRegistration() public {
        // First registration
        _registerProver(prover1, MIN_STAKE);

        // Deregister
        vm.prank(prover1);
        proverRegistry.deregister();

        // Re-register with a different stake
        uint256 newStake = 2 ether;
        vm.prank(prover1);
        proverRegistry.register{value: newStake}();

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertEq(info.stake, newStake, "stake should reflect new registration");
        assertEq(info.reputation, INITIAL_REPUTATION, "reputation should reset to INITIAL");
        assertEq(info.totalProofs, 0, "totalProofs should reset to 0");
        assertEq(info.failedProofs, 0, "failedProofs should reset to 0");
        assertEq(info.totalLatency, 0, "totalLatency should reset to 0");
        assertTrue(info.active, "prover should be active after re-registration");

        // Prover count should NOT increase on re-registration
        assertEq(proverRegistry.getProverCount(), 1, "proverCount should still be 1");
    }

    /// @notice Register with excess stake (above minStake), verify full msg.value stored
    function test_register_excessStake() public {
        uint256 excessStake = 5 ether;
        _registerProver(prover1, excessStake);

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);
        assertEq(info.stake, excessStake, "full msg.value should be stored as stake");
    }

    // =========================================================================
    //                     DEREGISTRATION — UNIT TESTS
    // =========================================================================

    /// @notice Deregister returns stake to prover and sets active = false
    function test_deregister_success() public {
        _registerProver(prover1, MIN_STAKE);

        uint256 balanceBefore = prover1.balance;

        vm.prank(prover1);
        proverRegistry.deregister();

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertFalse(info.active, "prover should be inactive after deregistration");
        assertEq(info.stake, 0, "stake should be 0 after deregistration");
        assertEq(prover1.balance, balanceBefore + MIN_STAKE, "stake should be returned");
    }

    /// @notice Deregistration emits ProverDeregistered event
    function test_deregister_emitsEvent() public {
        _registerProver(prover1, MIN_STAKE);

        vm.expectEmit(true, false, false, false, address(proverRegistry));
        emit IProverRegistry.ProverDeregistered(prover1);

        vm.prank(prover1);
        proverRegistry.deregister();
    }

    /// @notice Deregister by a non-registered address or already-deregistered prover reverts
    function test_deregister_revertsIfNotActive() public {
        // Stranger never registered
        vm.expectRevert(IProverRegistry.ProverNotFound.selector);
        vm.prank(stranger);
        proverRegistry.deregister();

        // Register then deregister, then try again
        _registerProver(prover1, MIN_STAKE);

        vm.prank(prover1);
        proverRegistry.deregister();

        vm.expectRevert(IProverRegistry.ProverNotFound.selector);
        vm.prank(prover1);
        proverRegistry.deregister();
    }

    // =========================================================================
    //                       REPUTATION — UNIT TESTS
    // =========================================================================

    /// @notice Perfect latency (<= targetLatencyMs) yields MAX_REPUTATION latency score.
    ///         After one successful proof: newRep = (5000 * 0 + 10000) / 1 = 10000
    function test_updateReputation_success_perfectLatency() public {
        _registerProver(prover1, MIN_STAKE);

        // Call updateReputation as coordinator with latency at target
        vm.prank(address(coordinator));
        proverRegistry.updateReputation(prover1, TARGET_LATENCY_MS, true);

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertEq(info.totalProofs, 1, "totalProofs should be 1");
        assertEq(info.totalLatency, TARGET_LATENCY_MS, "totalLatency mismatch");
        // First proof: newRep = (INITIAL_REPUTATION * 0 + MAX_REPUTATION) / 1 = MAX_REPUTATION
        assertEq(info.reputation, MAX_REPUTATION, "reputation should be MAX after perfect latency");
    }

    /// @notice Latency between target and ceiling yields a partial latency score.
    ///         midpoint = target + (ceiling - target) / 2 = target + target*2 = target*3
    ///         latencyScore = 10000 * (ceiling - mid) / (ceiling - target)
    ///                      = 10000 * (5*target - 3*target) / (5*target - target)
    ///                      = 10000 * 2 / 4 = 5000
    ///         After one proof: newRep = (5000*0 + 5000) / 1 = 5000
    function test_updateReputation_success_degradedLatency() public {
        _registerProver(prover1, MIN_STAKE);

        // midpoint latency: 3 * targetLatencyMs = 15000ms
        uint256 midLatency = TARGET_LATENCY_MS * 3;

        vm.prank(address(coordinator));
        proverRegistry.updateReputation(prover1, midLatency, true);

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        // latencyScore = 10000 * (25000 - 15000) / (25000 - 5000) = 10000 * 10000 / 20000 = 5000
        uint256 expectedScore = 5000;
        // newRep = (5000 * 0 + 5000) / 1 = 5000
        assertEq(info.reputation, expectedScore, "reputation should reflect degraded latency score");
        assertEq(info.totalProofs, 1, "totalProofs should be 1");
    }

    /// @notice Failure reduces reputation by FAILURE_PENALTY (500)
    function test_updateReputation_failure() public {
        _registerProver(prover1, MIN_STAKE);

        vm.prank(address(coordinator));
        proverRegistry.updateReputation(prover1, 0, false);

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertEq(info.reputation, INITIAL_REPUTATION - FAILURE_PENALTY, "reputation should decrease by FAILURE_PENALTY");
        assertEq(info.failedProofs, 1, "failedProofs should be 1");
        assertEq(info.totalProofs, 1, "totalProofs should be 1");
    }

    /// @notice Non-coordinator cannot call updateReputation
    function test_updateReputation_revertsIfNotCoordinator() public {
        _registerProver(prover1, MIN_STAKE);

        vm.expectRevert(IProverRegistry.Unauthorized.selector);
        vm.prank(stranger);
        proverRegistry.updateReputation(prover1, TARGET_LATENCY_MS, true);
    }

    // =========================================================================
    //                         SLASHING — UNIT TESTS
    // =========================================================================

    /// @notice Slash reduces stake by the specified amount
    function test_slash_reducesStake() public {
        uint256 stakeAmount = 5 ether;
        _registerProver(prover1, stakeAmount);

        uint256 slashAmount = 1 ether;

        vm.prank(address(coordinator));
        proverRegistry.slash(prover1, slashAmount, "test slash");

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertEq(info.stake, stakeAmount - slashAmount, "stake should be reduced by slash amount");
        assertTrue(info.active, "prover should remain active when stake >= minStake");
    }

    /// @notice Slashing below minStake deactivates the prover
    function test_slash_deactivatesIfBelowMinStake() public {
        _registerProver(prover1, MIN_STAKE);

        // Slash just 1 wei -- remaining stake < minStake
        uint256 slashAmount = 1;

        vm.prank(address(coordinator));
        proverRegistry.slash(prover1, slashAmount, "threshold breach");

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertFalse(info.active, "prover should be deactivated when stake < minStake");
        assertEq(info.stake, MIN_STAKE - slashAmount, "stake should reflect partial slash");
    }

    /// @notice Slashing more than available stake only takes what is available
    function test_slash_capsAtAvailableStake() public {
        _registerProver(prover1, MIN_STAKE);

        uint256 excessiveSlash = MIN_STAKE * 10;

        vm.expectEmit(true, false, false, true, address(proverRegistry));
        emit IProverRegistry.ProverSlashed(prover1, MIN_STAKE, "excessive slash");

        vm.prank(address(coordinator));
        proverRegistry.slash(prover1, excessiveSlash, "excessive slash");

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertEq(info.stake, 0, "stake should be 0 when slashed beyond balance");
        assertFalse(info.active, "prover should be deactivated");
    }

    // =========================================================================
    //                           FUZZ TESTS
    // =========================================================================

    /// @notice Any stake above minStake should produce a valid registration
    function testFuzz_register_anyStakeAboveMin(uint256 stake) public {
        stake = bound(stake, MIN_STAKE, 100 ether);

        vm.deal(prover1, stake);
        _registerProver(prover1, stake);

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertTrue(info.active, "prover should be active");
        assertEq(info.stake, stake, "stake should match deposited amount");
        assertEq(info.reputation, INITIAL_REPUTATION, "reputation should be INITIAL_REPUTATION");
        assertEq(info.registeredAt, block.timestamp, "registeredAt should match current timestamp");
    }

    /// @notice After multiple successful proofs, reputation should converge toward the latency score.
    ///         With perfect latency (score = 10000), the weighted moving average converges to 10000.
    ///         After n proofs: rep = (5000 * 0 + 10000 * n) / n = 10000 (from proof 1 onward for
    ///         the moving average formula: first proof immediately sets it to 10000, subsequent
    ///         proofs maintain it).
    function testFuzz_reputation_convergesToLatencyScore(uint8 numProofs) public {
        // At least 1 proof, cap at 100 to keep test fast
        uint256 n = bound(uint256(numProofs), 1, 100);

        _registerProver(prover1, MIN_STAKE);

        for (uint256 i; i < n;) {
            vm.prank(address(coordinator));
            proverRegistry.updateReputation(prover1, TARGET_LATENCY_MS, true);
            unchecked {
                ++i;
            }
        }

        IProverRegistry.ProverInfo memory info = proverRegistry.getProver(prover1);

        assertEq(info.totalProofs, n, "totalProofs should match iterations");
        // With perfect latency (score = MAX_REPUTATION = 10000):
        // After proof 1: (5000*0 + 10000) / 1 = 10000
        // After proof 2: (10000*1 + 10000) / 2 = 10000
        // Reputation stays at MAX_REPUTATION with perfect latency
        assertEq(info.reputation, MAX_REPUTATION, "reputation should converge to MAX with perfect latency");
    }
}
