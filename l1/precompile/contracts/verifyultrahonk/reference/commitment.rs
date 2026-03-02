// Copyright 2022 Aztec
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Source: https://github.com/miquelcabot/ultrahonk_verifier/blob/main/src/commitment.rs
// COMPLETE file contents

use ark_bn254_ext::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp};

use crate::constants::CONST_PROOF_SIZE_LOG_N;

const TWO: Fr = MontFp!("2");

pub(crate) fn compute_squares(r: Fr) -> [Fr; CONST_PROOF_SIZE_LOG_N] {
    let mut squares = [r; CONST_PROOF_SIZE_LOG_N];

    for i in 1..CONST_PROOF_SIZE_LOG_N {
        squares[i] = squares[i - 1].square();
    }

    squares
}

// Compute the evaluations  Al(r^{2^l}) for l = 0, ..., m-1.
pub(crate) fn compute_fold_pos_evaluations(
    sumcheck_u_challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    batched_eval_accumulator: &mut Fr,
    gemini_evaluations: &[Fr; CONST_PROOF_SIZE_LOG_N],
    gemini_eval_challenge_powers: &[Fr; CONST_PROOF_SIZE_LOG_N],
    log_size: u64,
) -> [Fr; CONST_PROOF_SIZE_LOG_N] {
    let mut fold_pos_evaluations = [Fr::ZERO; CONST_PROOF_SIZE_LOG_N];

    for i in (1..=CONST_PROOF_SIZE_LOG_N).rev() {
        let challenge_power = gemini_eval_challenge_powers[i - 1];
        let u = sumcheck_u_challenges[i - 1];

        let mut batched_eval_round_acc = challenge_power * (*batched_eval_accumulator) * TWO
            - gemini_evaluations[i - 1] * (challenge_power * (Fr::ONE - u) - u);
        // Divide by the denominator
        batched_eval_round_acc *= (challenge_power * (Fr::ONE - u) + u)
            .inverse()
            .expect("challenge_power * (Fr::ONE - u) + u should be invertible w.h.p.");
        if i as u64 <= log_size {
            *batched_eval_accumulator = batched_eval_round_acc;
            fold_pos_evaluations[i - 1] = batched_eval_round_acc;
        }
    }

    fold_pos_evaluations
}
