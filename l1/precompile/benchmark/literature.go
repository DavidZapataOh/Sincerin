package benchmark

// Literature-sourced gas costs for EVM operations equivalent to Sincerin precompiles.
// Used for comparison when compiled Solidity bytecode is not available.

// Poseidon2 hash_2 gas costs in various EVM implementations.
const (
	// GasPoseidon2Yul is the gas cost for hash_2 in the Yul implementation.
	// Source: github.com/zemse/poseidon2-evm benchmarks
	GasPoseidon2Yul uint64 = 20_304

	// GasPoseidon2Huff is the gas cost in the Huff implementation (lower bound).
	// Source: github.com/zemse/poseidon2-evm benchmarks
	GasPoseidon2Huff uint64 = 14_845

	// GasPoseidon2Solidity is the gas cost in plain (unoptimized) Solidity.
	// Source: OpenZeppelin Arbitrum Stylus benchmark, zemse/poseidon2-evm
	GasPoseidon2Solidity uint64 = 220_244
)

// Merkle tree gas costs (Poseidon-based, estimated from hash costs + storage).
const (
	// GasMerkleInsertEVM is the estimated gas for a depth-32 Merkle insert using Poseidon2 Yul.
	// Computation: 33 hashes (1 leaf + 32 path) × 20,304 + SSTORE overhead (~30,000).
	// Source: ethresear.ch Poseidon Merkle benchmarks + zemse hash cost
	GasMerkleInsertEVM uint64 = 33*GasPoseidon2Yul + 30_000 // ~700,032

	// GasMerkleVerifyEVM is the estimated gas for a depth-32 Merkle verify using Poseidon2 Yul.
	// Computation: 33 hashes (1 leaf + 32 path) × 20,304 + calldata/memory overhead (~5,000).
	// This is a view function (no SSTORE).
	// Source: ethresear.ch Poseidon Merkle benchmarks + zemse hash cost
	GasMerkleVerifyEVM uint64 = 33*GasPoseidon2Yul + 5_000 // ~675,032
)

// ZK proof verification gas costs.
const (
	// GasUltraHonkEVM is the estimated gas for UltraHonk proof verification in Solidity.
	// UltraHonk uses sumcheck + Shplemini + KZG pairing.
	// No published benchmarks exist; estimated from UltraPlonk (~550K gas) and
	// the additional complexity of the sumcheck protocol.
	// Source: Aztec forum, UltraPlonk benchmarks, Nebra analysis
	GasUltraHonkEVM uint64 = 500_000

	// UsUltraHonkEVM is the estimated wall-clock time (μs) for UltraHonk verification in Solidity.
	// PLONK-family Solidity verifiers take ~150-300ms due to heavy EC operations (MSM, pairing).
	// The gas-to-time ratio for EC precompiles differs greatly from arithmetic opcodes,
	// so this cannot be extrapolated from Poseidon2 measurements.
	// Conservative estimate: ~150ms = 150,000μs.
	// Source: Aztec benchmarks, Polygon zkEVM verifier measurements
	UsUltraHonkEVM float64 = 150_000

	// GasGroth16EVM is the well-known gas cost for Groth16 verification on Ethereum.
	// Formula: ~207,700 + 7,160 × num_public_inputs (with calldata).
	// Source: hackmd.io/@nebra-one/ByoMB8Zf6
	GasGroth16EVM uint64 = 200_000
)

// ComparisonRow represents one row of the benchmark comparison table.
type ComparisonRow struct {
	Operation      string
	PrecompileGas  uint64
	PrecompileUs   float64 // microseconds
	EVMGas         uint64
	EVMUs          float64 // microseconds (measured or estimated)
	GasRatio       float64
	SpeedRatio     float64
	Source         string // "measured" or "literature"
}
