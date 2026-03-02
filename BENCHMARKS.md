# Sincerin L1 — Precompile Performance Benchmarks

Native Go precompiles vs equivalent Solidity/Yul execution in the EVM interpreter.

## Results

```
╔══════════════════════════════╦═══════════════╦═══════════════╦══════════╦═══════════════╦═══════════════╦════════════╗
║ Operation                    ║   Precomp.Gas ║       EVM Gas ║    Gas Δ ║  Precomp.Time ║      EVM Time ║    Speed Δ ║
╠══════════════════════════════╬═══════════════╬═══════════════╬══════════╬═══════════════╬═══════════════╬════════════╣
║ Poseidon2 hash_2             ║           250 ║        19,607 ║      78x ║          7 μs ║         65 μs ║        9x  ║
║ MerkleTree Insert (d=32)     ║           500 ║       700,032 ║   1,400x ║        278 μs ║        2.6 ms ║        9x  ║
║ MerkleTree Verify (d=32)     ║           300 ║       675,032 ║   2,250x ║        230 μs ║        2.5 ms ║       11x  ║
║ UltraHonk Verify             ║        20,000 ║       500,000 ║      25x ║        2.5 ms ║       150 ms  ║       60x  ║
╚══════════════════════════════╩═══════════════╩═══════════════╩══════════╩═══════════════╩═══════════════╩════════════╝
```

**Gas Savings**: 25x - 2,250x cheaper than equivalent EVM execution.
**Speed**: 6x - 60x faster wall-clock time.

## Why This Matters

Every ZK application on Sincerin benefits from these savings:

| Use case | Without precompiles | With Sincerin L1 | Savings |
|----------|-------------------|-------------------|---------|
| Verify a ZK proof on-chain | ~500,000 gas (~$0.50) | 20,000 gas (~$0.02) | **25x** |
| Insert into a Merkle tree | ~700,000 gas (~$0.70) | 500 gas (~$0.0005) | **1,400x** |
| Verify a Merkle proof | ~675,000 gas (~$0.67) | 300 gas (~$0.0003) | **2,250x** |
| Hash with Poseidon2 | ~20,000 gas (~$0.02) | 250 gas (~$0.00025) | **78x** |

*Gas costs at 1 gwei base fee. USD estimates at ETH ~$2,000 for reference.*

## Precompiles

| Precompile | Address | Gas Cost | Description |
|------------|---------|----------|-------------|
| VerifyUltraHonk | `0x0300...0002` | 20,000 | Verify Noir/Barretenberg UltraHonk ZK proofs |
| PoseidonHash | `0x0300...0003` | 200 + 50/input | ZK-friendly hash (BN254, compatible with Noir) |
| MerkleTreeInsert | `0x0300...0004` | 500 | Append to depth-32 Sparse Merkle Tree |
| MerkleTreeVerify | `0x0300...0005` | 300 | Verify Merkle inclusion proof |

## Methodology

### Measured (Poseidon2)

The Poseidon2 comparison is **directly measured** — we execute the same operation in two ways:

1. **Native precompile**: Our Go implementation called via the precompile interface
2. **EVM Yul bytecode**: The `zemse/poseidon2-evm` Yul contract executed in subnet-evm's EVM interpreter via `core/vm/runtime.Call()`

Both produce **identical output** for all test vectors, confirming parameter compatibility (BN254, t=4, Rf=8, Rp=56).

### Literature (Merkle, UltraHonk)

For operations without compiled Solidity bytecode available:

- **Merkle Insert/Verify**: Gas = 33 Poseidon hashes x 20,304 + storage overhead. Wall-clock extrapolated from measured Poseidon2 ratio.
- **UltraHonk Verify**: Gas ~500K estimated from UltraPlonk benchmarks (Aztec). Wall-clock ~150ms from published PLONK Solidity verifier measurements.

## Reproduce

```bash
cd l1

# Comparison table
go test -v -run TestComparisonTable ./precompile/benchmark/

# Correctness validation (Yul == Go)
go test -v -run TestPoseidon2Yul ./precompile/benchmark/

# Go benchmarks (precise ns/op)
go test -bench=. -benchtime=3s ./precompile/benchmark/

# All precompile tests (59 tests across 8 packages)
go test ./crypto/... ./precompile/... ./genesis/
```

## Go Benchmark Output

```
goos: darwin
goarch: arm64
cpu: Apple M4
BenchmarkPrecompile_PoseidonHash2    6,909 ns/op
BenchmarkPrecompile_MerkleInsert   277,747 ns/op
BenchmarkPrecompile_MerkleVerify   230,177 ns/op
BenchmarkEVM_PoseidonHash2_Yul      65,117 ns/op
```

## Sources

| Data point | Source |
|------------|--------|
| Poseidon2 Yul gas (20,304) | [zemse/poseidon2-evm](https://github.com/zemse/poseidon2-evm) |
| Poseidon2 Huff gas (14,845) | [zemse/poseidon2-evm](https://github.com/zemse/poseidon2-evm) |
| Poseidon2 Solidity gas (220,244) | OpenZeppelin / Arbitrum Stylus benchmarks |
| UltraHonk EVM gas (~500K) | Aztec UltraPlonk benchmarks |
| Groth16 reference (~200K) | [Ethereum ecPairing precompile](https://hackmd.io/@nebra-one/ByoMB8Zf6) |
