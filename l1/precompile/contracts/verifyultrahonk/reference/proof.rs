// Copyright 2022 Aztec
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Source: https://github.com/miquelcabot/ultrahonk_verifier/blob/main/src/proof.rs
// Extracted: struct definitions, deserialization order, key functions

// =============================================================================
// PROOF POINT REPRESENTATION
// =============================================================================

/// G1 proof points are encoded with split x,y coordinates.
/// x = x_0 | (x_1 << 136), y = y_0 | (y_1 << 136)
/// Each component is stored as a 32-byte big-endian U256.
/// Total size per G1ProofPoint: 128 bytes (4 x 32)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct G1ProofPoint {
    pub x_0: U256,
    pub x_1: U256,
    pub y_0: U256,
    pub y_1: U256,
}

// =============================================================================
// PROOF TYPES
// =============================================================================

#[derive(Debug, Eq, PartialEq)]
pub enum ProofType {
    Plain(Box<[u8; PLAIN_PROOF_SIZE]>),
    ZK(Box<[u8; ZK_PROOF_SIZE]>),
}

#[derive(Debug)]
pub(crate) enum ParsedProof {
    Plain(Box<PlainProof>),
    ZK(Box<ZKProof>),
}

// =============================================================================
// PLAIN PROOF (non-ZK)
// =============================================================================

#[derive(Debug, Eq, PartialEq)]
pub struct PlainProof {
    // Wire commitments (4 G1 points = 4 * 128 bytes)
    pub w1: G1ProofPoint,
    pub w2: G1ProofPoint,
    pub w3: G1ProofPoint,
    pub w4: G1ProofPoint,
    // Lookup helpers (3 G1 points)
    pub lookup_read_counts: G1ProofPoint,
    pub lookup_read_tags: G1ProofPoint,
    pub lookup_inverses: G1ProofPoint,
    // Grand permutation polynomial (1 G1 point)
    pub z_perm: G1ProofPoint,
    // Sumcheck: CONST_PROOF_SIZE_LOG_N rounds, each with BATCHED_RELATION_PARTIAL_LENGTH Fr elements
    pub sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    // Sumcheck evaluations: NUMBER_OF_ENTITIES (40) Fr elements
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    // Gemini fold commitments: CONST_PROOF_SIZE_LOG_N - 1 G1 points
    pub gemini_fold_comms: [G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1],
    // Gemini evaluations: CONST_PROOF_SIZE_LOG_N Fr elements
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Shplonk quotient commitment (1 G1 point)
    pub shplonk_q: G1ProofPoint,
    // KZG quotient commitment (1 G1 point)
    pub kzg_quotient: G1ProofPoint,
}

// =============================================================================
// ZK PROOF
// =============================================================================

#[derive(Debug, Eq, PartialEq)]
pub struct ZKProof {
    // Wire commitments (4 G1 points)
    pub w1: G1ProofPoint,
    pub w2: G1ProofPoint,
    pub w3: G1ProofPoint,
    pub w4: G1ProofPoint,
    // Lookup helpers (3 G1 points)
    pub lookup_read_counts: G1ProofPoint,
    pub lookup_read_tags: G1ProofPoint,
    pub lookup_inverses: G1ProofPoint,
    // Grand permutation polynomial (1 G1 point)
    pub z_perm: G1ProofPoint,
    // Libra commitments (3 G1 points) -- ZK-specific
    pub libra_commitments: [G1ProofPoint; LIBRA_COMMITMENTS],
    // Libra sum (1 Fr element) -- ZK-specific
    pub libra_sum: Fr,
    // Sumcheck: CONST_PROOF_SIZE_LOG_N rounds, each with ZK_BATCHED_RELATION_PARTIAL_LENGTH elements
    pub sumcheck_univariates: [[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    // Sumcheck evaluations: NUMBER_OF_ENTITIES (40) Fr elements
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    // Libra evaluation (1 Fr element) -- ZK-specific
    pub libra_evaluation: Fr,
    // Gemini masking polynomial commitment (1 G1 point) -- ZK-specific
    pub gemini_masking_poly: G1ProofPoint,
    // Gemini masking evaluation (1 Fr element) -- ZK-specific
    pub gemini_masking_eval: Fr,
    // Gemini fold commitments: CONST_PROOF_SIZE_LOG_N - 1 G1 points
    pub gemini_fold_comms: [G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1],
    // Gemini evaluations: CONST_PROOF_SIZE_LOG_N Fr elements
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Libra polynomial evaluations (4 Fr elements) -- ZK-specific
    pub libra_poly_evals: [Fr; LIBRA_EVALUATIONS],
    // Shplonk quotient commitment (1 G1 point)
    pub shplonk_q: G1ProofPoint,
    // KZG quotient commitment (1 G1 point)
    pub kzg_quotient: G1ProofPoint,
}

// =============================================================================
// DESERIALIZATION ORDER
// =============================================================================

// PlainProof deserialization order (from TryFrom<&[u8]>):
//   1. w1 (128 bytes - G1ProofPoint)
//   2. w2 (128 bytes)
//   3. w3 (128 bytes)
//   4. lookup_read_counts (128 bytes)
//   5. lookup_read_tags (128 bytes)
//   6. w4 (128 bytes)           <-- NOTE: w4 comes AFTER lookup helpers!
//   7. lookup_inverses (128 bytes)
//   8. z_perm (128 bytes)
//   9. sumcheck_univariates (28 * 8 * 32 = 7168 bytes)
//  10. sumcheck_evaluations (40 * 32 = 1280 bytes)
//  11. gemini_fold_comms (27 * 128 = 3456 bytes)
//  12. gemini_a_evaluations (28 * 32 = 896 bytes)
//  13. shplonk_q (128 bytes)
//  14. kzg_quotient (128 bytes)

// ZKProof deserialization order (from TryFrom<&[u8]>):
//   1. w1 (128 bytes)
//   2. w2 (128 bytes)
//   3. w3 (128 bytes)
//   4. lookup_read_counts (128 bytes)
//   5. lookup_read_tags (128 bytes)
//   6. w4 (128 bytes)           <-- NOTE: w4 comes AFTER lookup helpers!
//   7. lookup_inverses (128 bytes)
//   8. z_perm (128 bytes)
//   9. libra_commitments[0] (128 bytes)     <-- ZK-specific
//  10. libra_sum (32 bytes)                 <-- ZK-specific
//  11. sumcheck_univariates (28 * 9 * 32 = 8064 bytes)  <-- 9 not 8 for ZK
//  12. sumcheck_evaluations (40 * 32 = 1280 bytes)
//  13. libra_evaluation (32 bytes)          <-- ZK-specific
//  14. libra_commitments[1] (128 bytes)     <-- ZK-specific
//  15. libra_commitments[2] (128 bytes)     <-- ZK-specific
//  16. gemini_masking_poly (128 bytes)      <-- ZK-specific
//  17. gemini_masking_eval (32 bytes)       <-- ZK-specific
//  18. gemini_fold_comms (27 * 128 = 3456 bytes)
//  19. gemini_a_evaluations (28 * 32 = 896 bytes)
//  20. libra_poly_evals (4 * 32 = 128 bytes)  <-- ZK-specific
//  21. shplonk_q (128 bytes)
//  22. kzg_quotient (128 bytes)

// =============================================================================
// READING UTILITIES
// =============================================================================

fn read_g1_proof_point(data: &mut &[u8]) -> Result<G1ProofPoint, ProofError> {
    const CHUNK_SIZE: usize = 128;
    let chunk: [_; CHUNK_SIZE] = data
        .split_off(..CHUNK_SIZE)
        .ok_or(ProofError::InvalidSliceLength {
            expected_length: CHUNK_SIZE,
            actual_length: data.len(),
        })?
        .try_into()
        .unwrap();

    G1ProofPoint::try_from(chunk).map_err(|_| ProofError::OtherError {
        message: "Failed reading G1 Proof Point".to_string(),
    })
}

fn read_fr(data: &mut &[u8]) -> Result<Fr, ProofError> {
    const CHUNK_SIZE: usize = 32;
    let chunk = data
        .split_off(..CHUNK_SIZE)
        .ok_or(ProofError::InvalidSliceLength {
            expected_length: CHUNK_SIZE,
            actual_length: data.len(),
        })?;

    Ok(Fr::from_be_bytes_mod_order(chunk))
}

// =============================================================================
// POINT CONVERSION (proof format -> affine curve point)
// =============================================================================

/// Converts a G1ProofPoint (split representation) to an actual affine curve point.
/// x = x_0 | (x_1 << 136), y = y_0 | (y_1 << 136)
/// If (x, y) = (0, 0), returns the point at infinity.
/// Validates that the point is on the BN254 curve.
pub(crate) fn convert_proof_point<H: CurveHooks>(
    g1_proof_point: G1ProofPoint,
) -> Result<G1<H>, GroupError> {
    const N: u32 = 136;
    let x = Fq::from_bigint(g1_proof_point.x_0.bitor(g1_proof_point.x_1.shl(N)))
        .expect("Should always succeed");
    let y = Fq::from_bigint(g1_proof_point.y_0.bitor(g1_proof_point.y_1.shl(N)))
        .expect("Should always succeed");

    if x == Fq::ZERO && y == Fq::ZERO {
        return Ok(G1::<H>::identity());
    }

    let point = G1::<H>::new_unchecked(x, y);

    if !point.is_on_curve() {
        return Err(GroupError::NotOnCurve);
    }

    debug_assert!(point.is_in_correct_subgroup_assuming_on_curve());

    Ok(point)
}

// =============================================================================
// HasCommonProofData TRAIT
// =============================================================================

pub(crate) trait HasCommonProofData {
    fn w1(&self) -> &G1ProofPoint;
    fn w2(&self) -> &G1ProofPoint;
    fn w3(&self) -> &G1ProofPoint;
    fn w4(&self) -> &G1ProofPoint;
    fn lookup_read_counts(&self) -> &G1ProofPoint;
    fn lookup_read_tags(&self) -> &G1ProofPoint;
    fn lookup_inverses(&self) -> &G1ProofPoint;
    fn z_perm(&self) -> &G1ProofPoint;
    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a>;
    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES];
    fn gemini_fold_comms(&self) -> &[G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1];
    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N];
    fn shplonk_q(&self) -> &G1ProofPoint;
    fn kzg_quotient(&self) -> &G1ProofPoint;
}

// =============================================================================
// WIRE ENUM (indices into sumcheck_evaluations)
// =============================================================================

// The 40 entities in sumcheck_evaluations are indexed as follows:
// Index  0: Q_M
// Index  1: Q_C
// Index  2: Q_L
// Index  3: Q_R
// Index  4: Q_O
// Index  5: Q_4
// Index  6: Q_LOOKUP
// Index  7: Q_ARITH
// Index  8: Q_RANGE (Q_DELTARANGE)
// Index  9: Q_ELLIPTIC
// Index 10: Q_AUX
// Index 11: Q_POSEIDON2_EXTERNAL
// Index 12: Q_POSEIDON2_INTERNAL
// Index 13: SIGMA_1
// Index 14: SIGMA_2
// Index 15: SIGMA_3
// Index 16: SIGMA_4
// Index 17: ID_1
// Index 18: ID_2
// Index 19: ID_3
// Index 20: ID_4
// Index 21: TABLE_1
// Index 22: TABLE_2
// Index 23: TABLE_3
// Index 24: TABLE_4
// Index 25: LAGRANGE_FIRST
// Index 26: LAGRANGE_LAST
// Index 27: W_L (w1)
// Index 28: W_R (w2)
// Index 29: W_O (w3)
// Index 30: W_4 (w4)
// Index 31: Z_PERM
// Index 32: LOOKUP_INVERSES
// Index 33: LOOKUP_READ_COUNTS
// Index 34: LOOKUP_READ_TAGS
// --- Shifted (5 entities) ---
// Index 35: W_L_SHIFT
// Index 36: W_R_SHIFT
// Index 37: W_O_SHIFT
// Index 38: W_4_SHIFT
// Index 39: Z_PERM_SHIFT
//
// NUMBER_UNSHIFTED = 35 (indices 0-34)
// NUMBER_OF_ENTITIES = 40 (indices 0-39)
