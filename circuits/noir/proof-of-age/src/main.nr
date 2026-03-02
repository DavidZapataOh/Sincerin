use sincerin_poseidon;
use sincerin_merkle;

/// Seconds in a year (365.25 days)
global SECONDS_PER_YEAR: u64 = 31557600;

/// Number of Poseidon hash rounds in the credential commitment chain.
/// Tuned to bring the total circuit size to approximately 50K gates.
global COMMITMENT_ROUNDS: u32 = 570;

/// Proof of Age Circuit
///
/// Proves that a user meets a minimum age threshold without revealing
/// their exact birthdate or identity. Uses structural split proving
/// to keep the witness on the client side.
///
/// Public inputs:
///   - threshold_age: minimum age in years (e.g. 18)
///   - current_timestamp: current Unix timestamp
///   - issuer_pubkey: issuer's public key (Poseidon MAC key for MVP)
///   - identity_registry_root: Merkle root of the identity registry
///   - credential_commitment: hash chain commitment for the credential
///   - is_over_threshold: whether user meets the age threshold
///
/// Private inputs:
///   - birthdate: Unix timestamp of birth date
///   - identity_hash: hash of identity document
///   - signature: Poseidon MAC = hash_3(identity_hash, birthdate, issuer_pubkey)
///   - identity_index: position in registry Merkle tree
///   - identity_path: Merkle sibling hashes (depth 20)
fn main(
    // Private inputs
    birthdate: Field,
    identity_hash: Field,
    signature: Field,
    identity_index: u32,
    identity_path: [Field; 20],
    // Public inputs
    threshold_age: pub u32,
    current_timestamp: pub Field,
    issuer_pubkey: pub Field,
    identity_registry_root: pub Field,
    credential_commitment: pub Field,
    is_over_threshold: pub bool,
) {
    // ---------------------------------------------------------------
    // 1. Verify attestation signature (Poseidon MAC)
    //    The issuer signed (identity_hash, birthdate, issuer_pubkey)
    // ---------------------------------------------------------------
    let computed_signature = sincerin_poseidon::hash_3(
        identity_hash,
        birthdate,
        issuer_pubkey,
    );
    assert(computed_signature == signature, "Invalid attestation signature");

    // ---------------------------------------------------------------
    // 2. Verify identity is in the registry (Merkle inclusion proof)
    // ---------------------------------------------------------------
    let computed_root = sincerin_merkle::compute_root(
        identity_hash,
        identity_index,
        identity_path,
    );
    assert(computed_root == identity_registry_root, "Identity not in registry");

    // ---------------------------------------------------------------
    // 3. Age verification
    //    Compute age from timestamps and verify threshold
    // ---------------------------------------------------------------
    // Safety: birthdate must not be in the future
    let birthdate_u64 = birthdate as u64;
    let current_ts_u64 = current_timestamp as u64;
    assert(birthdate_u64 < current_ts_u64, "Birthdate cannot be in the future");

    let age_seconds = current_ts_u64 - birthdate_u64;
    let age_years = age_seconds / SECONDS_PER_YEAR;
    let meets_threshold = age_years >= threshold_age as u64;

    // The public is_over_threshold must match the computed result
    assert(meets_threshold == is_over_threshold, "is_over_threshold does not match computed age");

    // If the claim is that the user IS over threshold, enforce it
    if is_over_threshold {
        assert(age_years >= threshold_age as u64, "Age is below threshold");
    }

    // ---------------------------------------------------------------
    // 4. Credential commitment chain
    //    Repeatedly hash identity_hash and birthdate to create a
    //    deterministic commitment. This adds constraints to reach
    //    the target circuit size (~50K gates) and simulates a real
    //    credential commitment derivation.
    // ---------------------------------------------------------------
    let mut commitment = sincerin_poseidon::hash_2(identity_hash, birthdate);
    for _ in 1..COMMITMENT_ROUNDS {
        commitment = sincerin_poseidon::hash_2(commitment, birthdate);
    }
    assert(commitment == credential_commitment, "Invalid credential commitment");
}


// ============================================================
// Test Helpers
// ============================================================

/// Build a test Merkle tree with all-zero siblings, returning (root, path)
fn build_test_tree(leaf: Field, index: u32) -> (Field, [Field; 20]) {
    let path = [0 as Field; 20];
    let root = sincerin_merkle::compute_root(leaf, index, path);
    (root, path)
}

/// Compute the credential commitment chain for testing
fn compute_test_commitment(identity_hash: Field, birthdate: Field) -> Field {
    let mut commitment = sincerin_poseidon::hash_2(identity_hash, birthdate);
    for _ in 1..COMMITMENT_ROUNDS {
        commitment = sincerin_poseidon::hash_2(commitment, birthdate);
    }
    commitment
}


// ============================================================
// Tests
// ============================================================

#[test]
fn test_age_over_18_passes() {
    // Birth: 2000-01-01 00:00:00 UTC = 946684800
    // Current: 2026-03-01 00:00:00 UTC = 1772438400
    // Age: (1772438400 - 946684800) / 31557600 = 26 years
    let birthdate: Field = 946684800;
    let current_timestamp: Field = 1772438400;
    let issuer_pubkey: Field = 1234;
    let identity_hash: Field = 42;
    let threshold_age: u32 = 18;

    let signature = sincerin_poseidon::hash_3(identity_hash, birthdate, issuer_pubkey);
    let (root, path) = build_test_tree(identity_hash, 0);
    let commitment = compute_test_commitment(identity_hash, birthdate);

    main(
        birthdate,
        identity_hash,
        signature,
        0,        // identity_index
        path,
        threshold_age,
        current_timestamp,
        issuer_pubkey,
        root,
        commitment,
        true,     // is_over_threshold
    );
}

#[test(should_fail_with = "is_over_threshold does not match computed age")]
fn test_age_under_18_fails() {
    // Birth: 2015-01-01 00:00:00 UTC = 1420070400
    // Current: 2026-03-01 00:00:00 UTC = 1772438400
    // Age: (1772438400 - 1420070400) / 31557600 = 11 years
    let birthdate: Field = 1420070400;
    let current_timestamp: Field = 1772438400;
    let issuer_pubkey: Field = 1234;
    let identity_hash: Field = 42;
    let threshold_age: u32 = 18;

    let signature = sincerin_poseidon::hash_3(identity_hash, birthdate, issuer_pubkey);
    let (root, path) = build_test_tree(identity_hash, 0);
    let commitment = compute_test_commitment(identity_hash, birthdate);

    main(
        birthdate,
        identity_hash,
        signature,
        0,
        path,
        threshold_age,
        current_timestamp,
        issuer_pubkey,
        root,
        commitment,
        true,     // Claiming is_over_threshold=true but age is only 11
    );
}

#[test(should_fail_with = "Invalid attestation signature")]
fn test_invalid_signature_fails() {
    let birthdate: Field = 946684800;
    let current_timestamp: Field = 1772438400;
    let issuer_pubkey: Field = 1234;
    let identity_hash: Field = 42;
    let threshold_age: u32 = 18;

    // Wrong signature (not matching identity_hash, birthdate, issuer_pubkey)
    let wrong_signature: Field = 999;
    let (root, path) = build_test_tree(identity_hash, 0);
    let commitment = compute_test_commitment(identity_hash, birthdate);

    main(
        birthdate,
        identity_hash,
        wrong_signature,
        0,
        path,
        threshold_age,
        current_timestamp,
        issuer_pubkey,
        root,
        commitment,
        true,
    );
}

#[test]
fn test_age_exactly_18_passes() {
    // Birth: 2008-03-01 00:00:00 UTC = 1204329600
    // Current: 2026-03-01 00:00:00 UTC = 1772438400
    // Elapsed seconds: 1772438400 - 1204329600 = 568108800
    // Age: 568108800 / 31557600 = 18.0 (exactly)
    let birthdate: Field = 1204329600;
    let current_timestamp: Field = 1772438400;
    let issuer_pubkey: Field = 1234;
    let identity_hash: Field = 42;
    let threshold_age: u32 = 18;

    let signature = sincerin_poseidon::hash_3(identity_hash, birthdate, issuer_pubkey);
    let (root, path) = build_test_tree(identity_hash, 0);
    let commitment = compute_test_commitment(identity_hash, birthdate);

    main(
        birthdate,
        identity_hash,
        signature,
        0,
        path,
        threshold_age,
        current_timestamp,
        issuer_pubkey,
        root,
        commitment,
        true,
    );
}

#[test(should_fail_with = "Birthdate cannot be in the future")]
fn test_future_birthdate_fails() {
    // Birthdate in the future: 2030-01-01 = 1893456000
    // Current: 2026-03-01 = 1772438400
    let birthdate: Field = 1893456000;
    let current_timestamp: Field = 1772438400;
    let issuer_pubkey: Field = 1234;
    let identity_hash: Field = 42;
    let threshold_age: u32 = 18;

    let signature = sincerin_poseidon::hash_3(identity_hash, birthdate, issuer_pubkey);
    let (root, path) = build_test_tree(identity_hash, 0);
    let commitment = compute_test_commitment(identity_hash, birthdate);

    main(
        birthdate,
        identity_hash,
        signature,
        0,
        path,
        threshold_age,
        current_timestamp,
        issuer_pubkey,
        root,
        commitment,
        false,    // Not over threshold since birthdate is in future
    );
}