# ZK Engineer Agent Memory

## Reference Implementations Found

### UltraHonk Verifier (Rust) - zkVerify / Horizen Labs
- Repo: https://github.com/miquelcabot/ultrahonk_verifier
- Package name: `ultrahonk-no-std`
- Supports both Plain and ZK proof types
- Reference files saved at: `l1/precompile/contracts/verifyultrahonk/reference/*.rs`
- Key dep: `ark-bn254-ext` from `zkVerify/accelerated-bn-cryptography` (tag v0.6.0)

### UltraPlonk Verifier (Rust) - zkVerify (predecessor)
- Repo: https://github.com/zkVerify/ultraplonk_verifier
- Older version (UltraPlonk, not UltraHonk)

## Critical Implementation Details

### Proof Deserialization Order (IMPORTANT: w4 comes late!)
Plain: w1, w2, w3, lookup_read_counts, lookup_read_tags, w4, lookup_inverses, z_perm, sumcheck, gemini, shplonk, kzg
ZK adds: libra_commitments[0], libra_sum (after z_perm), libra_evaluation + libra_commitments[1,2] + gemini_masking (after sumcheck_evals), libra_poly_evals (after gemini_a_evals)

### VK vs Proof Point Encoding
- VK G1 points: standard affine (x, y) each 32 bytes BE = 64 bytes per point
- Proof G1 points: split format (x_0, x_1, y_0, y_1) each 32 bytes = 128 bytes per point
  - Reconstruct: x = x_0 | (x_1 << 136), y = y_0 | (y_1 << 136)

### Transcript Challenge Generation
- Uses Keccak256 with BE 32-byte field element encoding
- split_challenge: lower 128 bits and upper 128 bits interpreted as Fr
- pub_inputs_offset hardcoded to 1 in verifier (not taken from VK)

### Key Constants
- CONST_PROOF_SIZE_LOG_N = 28, NUMBER_OF_ENTITIES = 40, NUMBER_UNSHIFTED = 35
- NUMBER_OF_SUBRELATIONS = 26, NUMBER_OF_ALPHAS = 25
- VK_SIZE = 1760 bytes, PLAIN_PROOF_SIZE and ZK_PROOF_SIZE computed from constants
- BATCHED_RELATION_PARTIAL_LENGTH = 8 (Plain) or 9 (ZK)

### G2 SRS Points (hardcoded, same as Barretenberg)
- SRS_G2 and SRS_G2_VK are fixed 128-byte constants
- Encoded per EIP-197: (x_c1, x_c0, y_c1, y_c0) each 32 bytes

## Project Notes
- `gh` CLI not available in this environment; use WebFetch/WebSearch instead
- Reference directory: `l1/precompile/contracts/verifyultrahonk/reference/`
