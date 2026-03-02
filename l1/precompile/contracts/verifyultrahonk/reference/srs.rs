// Copyright 2022 Aztec
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Source: https://github.com/miquelcabot/ultrahonk_verifier/blob/main/src/srs.rs

// Noir uses the following fixed G2 points as SRS when computing the pairing
// near the end of the protocol. See:
// https://github.com/AztecProtocol/barretenberg/blob/4306250af7b46d804168b59b37cec65303acbc63/sol/src/honk/utils.sol#L92-L108
// In addition, Noir encodes G2 points in this SRS according to the following
// specification:
// https://eips.ethereum.org/EIPS/eip-197#encoding

pub static SRS_G2: [u8; 128] = hex_literal::hex!(
    "
    198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
    1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
    090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
    12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
    "
);

// G2 point from VK
pub static SRS_G2_VK: [u8; 128] = hex_literal::hex!(
    "
    260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1
    0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0
    04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4
    22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55
    "
);

// G2 point encoding (EIP-197):
// Fq2 elements encoded as (imaginary, real) each 32 bytes
// So for a G2 point (x, y) where x = x_c0 + x_c1*i, y = y_c0 + y_c1*i:
//   Bytes [0..32]:   x_c1 (imaginary part of x)
//   Bytes [32..64]:  x_c0 (real part of x)
//   Bytes [64..96]:  y_c1 (imaginary part of y)
//   Bytes [96..128]: y_c0 (real part of y)
//
// In the Rust code, read_g2 reads them as:
//   x_c1 = data[0..32]
//   x_c0 = data[32..64]
//   y_c1 = data[64..96]
//   y_c0 = data[96..128]
//   x = Fq2::new(x_c0, x_c1)
//   y = Fq2::new(y_c0, y_c1)
