// Copyright 2022 Aztec
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Source: https://github.com/miquelcabot/ultrahonk_verifier/blob/main/src/key.rs

pub const VK_SIZE: usize = 1760;
// VK Layout: 4 * u64 (32 bytes) + 27 * G1 points (27 * 64 = 1728 bytes) = 1760 bytes

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey<H: CurveHooks> {
    // Misc Params (4 u64 values, each stored as big-endian 8 bytes)
    pub circuit_size: u64,         // must be power of 2
    pub log_circuit_size: u64,     // must equal log2(circuit_size)
    pub num_public_inputs: u64,
    pub pub_inputs_offset: u64,    // NOTE: May end up being removed in the future
    // Selectors (13 G1 points, each 64 bytes: 32 bytes x, 32 bytes y, big-endian)
    pub q_m: G1<H>,
    pub q_c: G1<H>,
    pub q_l: G1<H>,
    pub q_r: G1<H>,
    pub q_o: G1<H>,
    pub q_4: G1<H>,
    pub q_lookup: G1<H>,
    pub q_arith: G1<H>,
    pub q_deltarange: G1<H>,
    pub q_elliptic: G1<H>,
    pub q_aux: G1<H>,
    pub q_poseidon2external: G1<H>,
    pub q_poseidon2internal: G1<H>,
    // Copy Constraints (4 G1 points)
    pub s_1: G1<H>,
    pub s_2: G1<H>,
    pub s_3: G1<H>,
    pub s_4: G1<H>,
    // Copy Identity (4 G1 points)
    pub id_1: G1<H>,
    pub id_2: G1<H>,
    pub id_3: G1<H>,
    pub id_4: G1<H>,
    // Precomputed Lookup Table (4 G1 points)
    pub t_1: G1<H>,
    pub t_2: G1<H>,
    pub t_3: G1<H>,
    pub t_4: G1<H>,
    // Fixed first and last (2 G1 points)
    pub lagrange_first: G1<H>,
    pub lagrange_last: G1<H>,
}

// VK Deserialization order:
//   Bytes [0..8]:      circuit_size (u64 big-endian)
//   Bytes [8..16]:     log_circuit_size (u64 big-endian)
//   Bytes [16..24]:    num_public_inputs (u64 big-endian)
//   Bytes [24..32]:    pub_inputs_offset (u64 big-endian)
//   Bytes [32..96]:    q_m (G1 affine: 32 bytes x + 32 bytes y)
//   Bytes [96..160]:   q_c
//   Bytes [160..224]:  q_l
//   Bytes [224..288]:  q_r
//   Bytes [288..352]:  q_o
//   Bytes [352..416]:  q_4
//   Bytes [416..480]:  q_lookup
//   Bytes [480..544]:  q_arith
//   Bytes [544..608]:  q_deltarange
//   Bytes [608..672]:  q_elliptic
//   Bytes [672..736]:  q_aux
//   Bytes [736..800]:  q_poseidon2external
//   Bytes [800..864]:  q_poseidon2internal
//   Bytes [864..928]:  s_1
//   Bytes [928..992]:  s_2
//   Bytes [992..1056]: s_3
//   Bytes [1056..1120]: s_4
//   Bytes [1120..1184]: id_1
//   Bytes [1184..1248]: id_2
//   Bytes [1248..1312]: id_3
//   Bytes [1312..1376]: id_4
//   Bytes [1376..1440]: t_1
//   Bytes [1440..1504]: t_2
//   Bytes [1504..1568]: t_3
//   Bytes [1568..1632]: t_4
//   Bytes [1632..1696]: lagrange_first
//   Bytes [1696..1760]: lagrange_last
//
// G1 point format in VK: standard affine (x, y) each 32 bytes big-endian
// NOTE: This differs from proof points which use the split (x_0, x_1, y_0, y_1) format!
//
// Validation:
//   - circuit_size must be > 0 and a power of 2
//   - log_circuit_size must equal log2(circuit_size)
//   - Each G1 point must be on the BN254 curve (or (0,0) for point at infinity)
