// Copyright 2022 Aztec
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Source: https://github.com/miquelcabot/ultrahonk_verifier/blob/main/src/types.rs

// Re-exports from ark_bn254_ext:
// pub use ark_bn254_ext::{Fq, Fq2, Fr, FrConfig};

// Type aliases:
// pub type U256 = <Fr as PrimeField>::BigInt;          // 256-bit big integer (4 x u64 limbs)
// pub type G1<H> = sw::Affine<ark_bn254_ext::g1::Config<H>>;  // BN254 G1 affine point
// pub type G2<H> = sw::Affine<ark_bn254_ext::g2::Config<H>>;  // BN254 G2 affine point
// pub type Bn254<H> = ark_models_ext::bn::Bn<ark_bn254_ext::Config<H>>;  // BN254 pairing engine

// Dependencies:
// [dependencies]
// ark-bn254-ext = { git = "https://github.com/zkVerify/accelerated-bn-cryptography.git", tag = "v0.6.0" }
// ark-models-ext = { git = "https://github.com/zkVerify/accelerated-bn-cryptography.git", tag = "v0.6.0" }
// ark-bn254 = "0.5.0"
// ark-ec = "0.5.0"
// ark-ff = "0.5.0"
// ark-std = "0.5.0"
// sha3 = "0.10.8"       # Keccak256
// snafu = "0.8.3"       # Error handling
// hex-literal = "0.4.1" # Hex constants

// Key field parameters (BN254):
// Fr order:  21888242871839275222246405745257275088548364400416034343698204186575808495617
// Fq order:  21888242871839275222246405745257275088696311157297823662689037894645226208583
// Fr is a 254-bit prime field (fits in 4 x 64-bit limbs)
