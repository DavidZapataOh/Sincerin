// Poseidon hash helpers for BN254 field
// Wraps the noir-lang/poseidon library for consistent usage across Sincerin circuits

use poseidon::poseidon2::Poseidon2;

/// Hash two field elements using Poseidon2
pub fn hash_2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

/// Hash three field elements using Poseidon2
pub fn hash_3(a: Field, b: Field, c: Field) -> Field {
    Poseidon2::hash([a, b, c], 3)
}

#[test]
fn test_poseidon_hash_2_deterministic() {
    let h1 = hash_2(1, 2);
    let h2 = hash_2(1, 2);
    assert(h1 == h2);
}

#[test]
fn test_poseidon_hash_2_different_inputs() {
    let h1 = hash_2(1, 2);
    let h2 = hash_2(2, 1);
    assert(h1 != h2);
}

#[test]
fn test_poseidon_hash_3_deterministic() {
    let h1 = hash_3(1, 2, 3);
    let h2 = hash_3(1, 2, 3);
    assert(h1 == h2);
}

#[test]
fn test_poseidon_hash_3_different_inputs() {
    let h1 = hash_3(1, 2, 3);
    let h2 = hash_3(3, 2, 1);
    assert(h1 != h2);
}