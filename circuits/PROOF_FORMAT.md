# UltraHonk Proof Format — Sincerin Circuits

**Nargo**: 1.0.0-beta.19
**Barretenberg**: 4.0.0-nightly.20260120
**Proof System**: UltraHonk

---

## Overview

Barretenberg generates proofs in a binary format consisting of serialized BN254 group elements (G1 points) and scalar field elements. The proof, verification key, and public inputs are stored in separate files.

## File Layout

### Proof File (`proof`)

| Section | Size | Description |
|---|---|---|
| Proof body | ~16,256 bytes | Serialized UltraHonk proof containing G1 commitment points and evaluation scalars |

Total proof size for both circuits: **16,256 bytes** (fixed for UltraHonk regardless of circuit size).

The proof body contains:
- Commitment points: G1 elements on BN254 (64 bytes each uncompressed: 32-byte x + 32-byte y)
- Evaluation scalars: BN254 scalar field elements (32 bytes each)

### Public Inputs File (`public_inputs`)

Public inputs are serialized as consecutive 32-byte big-endian BN254 field elements, ordered as they appear in the circuit's function signature (public inputs only).

**proof-of-membership** (2 public inputs = 64 bytes):
```
[0] root             — 32 bytes, big-endian Field
[1] nullifier        — 32 bytes, big-endian Field
```

**proof-of-age** (6 public inputs = 192 bytes):
```
[0] threshold_age            — 32 bytes, big-endian u32 zero-padded
[1] current_timestamp        — 32 bytes, big-endian Field
[2] issuer_pubkey            — 32 bytes, big-endian Field
[3] identity_registry_root   — 32 bytes, big-endian Field
[4] credential_commitment    — 32 bytes, big-endian Field
[5] is_over_threshold        — 32 bytes, 0x01 for true, 0x00 for false
```

### Verification Key File (`vk`)

| Field | Size | Description |
|---|---|---|
| VK binary | 3,680 bytes | Serialized UltraHonk verification key |

The VK contains:
- Circuit size (uint32)
- Number of public inputs (uint32)
- Selector commitments (G1 points)
- Sigma commitments
- ID commitments
- Other structural data

### VK Hash File (`vk_hash`)

A 32-byte Poseidon2 hash of the verification key. Used as circuit identifier on-chain.

**proof-of-membership**: `0895f036276e33e6de651b1d26e55897558ecad13e27ff98f7b66c278d6ae76e`
**proof-of-age**: `1bbf67c66675bd16c52ce13fd3c079756490ca053e31e82d6266065cb3e3afe1`

## Verification Command

```bash
bb verify -k <vk_path> -p <proof_path> -i <public_inputs_path>
```

Exit code 0 = valid, non-zero = invalid.

## Integration Notes

### For VerifyUltraHonk Precompile (Go)

The precompile receives:
1. The proof bytes (from `proof` file)
2. The public inputs bytes (from `public_inputs` file)
3. The VK bytes (from `vk` file) or a VK hash to look up a registered VK

The precompile must deserialize these using the same BN254 curve parameters as Barretenberg.

### For the SDK (TypeScript / bb.js WASM)

The ACIR JSON files (`target/*.json`) are the input to bb.js for client-side proving. The SDK loads the ACIR, generates the witness from user inputs, and produces the same proof format.

### For the Prover Node (Rust)

The prover node invokes `bb prove` as a subprocess:
```bash
bb prove -b <acir_json> -w <witness_gz> -o <output_dir> --write_vk
```

This generates `proof`, `public_inputs`, `vk`, and `vk_hash` in the output directory.