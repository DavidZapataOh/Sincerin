// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/Coordinator.sol";
import "../src/ProverRegistry.sol";
import "../src/ProofRegistry.sol";

/// @title Deploy
/// @notice Deployment script for Sincerin L1 contracts
contract Deploy is Script {
    // Precompile addresses (fixed in genesis)
    address constant VERIFY_ULTRAHONK_PRECOMPILE = 0x0300000000000000000000000000000000000002;
    address constant MERKLE_INSERT_PRECOMPILE = 0x0300000000000000000000000000000000000004;
    address constant MERKLE_VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000005;

    // Configuration
    uint256 constant MIN_STAKE = 1 ether;
    uint256 constant MIN_FEE = 0.001 ether;
    uint256 constant TARGET_LATENCY_MS = 5000;

    // VK hashes from zk-engineer (Tarea 1.4)
    bytes32 constant MEMBERSHIP_VK_HASH = 0x0895f036276e33e6de651b1d26e55897558ecad13e27ff98f7b66c278d6ae76e;
    bytes32 constant AGE_VK_HASH = 0x1bbf67c66675bd16c52ce13fd3c079756490ca053e31e82d6266065cb3e3afe1;

    function run() external {
        vm.startBroadcast();

        // 1. Deploy ProverRegistry (no dependencies)
        ProverRegistry proverRegistry = new ProverRegistry(MIN_STAKE, TARGET_LATENCY_MS);
        console.log("ProverRegistry:", address(proverRegistry));

        // 2. Deploy ProofRegistry (needs precompile addresses)
        ProofRegistry proofRegistry = new ProofRegistry(MERKLE_INSERT_PRECOMPILE, MERKLE_VERIFY_PRECOMPILE);
        console.log("ProofRegistry:", address(proofRegistry));

        // 3. Deploy Coordinator (needs both registries + precompile)
        Coordinator coordinator = new Coordinator(
            address(proverRegistry),
            address(proofRegistry),
            VERIFY_ULTRAHONK_PRECOMPILE,
            msg.sender, // operator = deployer
            MIN_FEE
        );
        console.log("Coordinator:", address(coordinator));

        // 4. Set Coordinator as authorized caller on both registries
        proofRegistry.setCoordinator(address(coordinator));
        proverRegistry.setCoordinator(address(coordinator));

        // 5. Register initial circuits
        bytes32 membershipCircuitId = keccak256("proof-of-membership");
        bytes32 ageCircuitId = keccak256("proof-of-age");

        coordinator.registerCircuit(membershipCircuitId, MEMBERSHIP_VK_HASH);
        coordinator.registerCircuit(ageCircuitId, AGE_VK_HASH);

        console.log("Circuits registered:");
        console.log("  proof-of-membership:", vm.toString(membershipCircuitId));
        console.log("  proof-of-age:", vm.toString(ageCircuitId));

        vm.stopBroadcast();
    }
}
