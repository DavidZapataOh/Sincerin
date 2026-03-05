# Integration Tests

Tests that validate the interaction between Solidity contracts and Go precompiles, using real ZK proof fixtures.

## Test Files

| File | Purpose | Tests |
|------|---------|-------|
| `CoordinatorIntegration.t.sol` | Coordinator ↔ VerifyUltraHonk | 7 |
| `ProofRegistryIntegration.t.sol` | ProofRegistry ↔ MerkleTree | 6 |
| `GasBenchmark.t.sol` | Gas measurements for all operations | 8 |

## Running

```bash
# Local (mocked precompiles)
forge test --match-path "test/integration/*" -vvv

# With gas report
forge test --match-path "test/integration/*" -vvv --gas-report

# Full suite (includes Go encoding tests)
./scripts/devnet/run-integration-tests.sh
```

## Go Encoding Compatibility Tests

Complementary tests in Go that validate encoding compatibility without a node:

```bash
cd l1 && go test -v -run TestSolidityEncodingCompat ./precompile/contracts/
```

## Encoding Findings

The integration tests discovered encoding incompatibilities between contracts and precompiles:

### Coordinator → VerifyUltraHonk

**Current**: `verifyPrecompile.staticcall(abi.encode(proof, vkHash, publicInputs))`

Issues:
1. Missing 4-byte function selector (precompile routes by selector)
2. Sends `bytes32 vkHash` — precompile expects `bytes vk` (full VK bytes)
3. Sends `bytes publicInputs` — precompile expects `bytes32[] publicInputs`

### ProofRegistry → MerkleTreeInsert

**Current**: `merkleInsertPrecompile.staticcall(abi.encodePacked(leafHash, metadataHash))`

Issues:
1. Missing 4-byte function selector
2. Uses `staticcall` — precompile rejects read-only mode (insert mutates state)

### ProofRegistry → MerkleTreeVerify

**Current**: `merkleVerifyPrecompile.staticcall(raw1152bytes)`

Issues:
1. Missing 4-byte function selector (data layout is otherwise correct)

## Gas Report (mocked precompiles)

| Operation | Gas (contract only) | + Precompile | Total |
|-----------|--------------------:|-------------:|------:|
| register | ~166K | — | ~166K |
| requestProof | ~187K | — | ~187K |
| assignProver | ~26K | — | ~26K |
| submitProof (membership, 8KB) | ~800K | +20,500 | ~820K |
| submitProof (age, 9KB) | ~855K | +20,500 | ~876K |
| isVerified | ~16K | +300 | ~16K |
| updateReputation | ~48K | — | ~48K |

Note: High submitProof gas is primarily from calldata costs (~8-9KB proof data × 16 gas/byte ≈ 130-145K calldata gas).
