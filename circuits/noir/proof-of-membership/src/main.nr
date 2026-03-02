use sincerin_poseidon;
use sincerin_merkle;

/// Proof of Membership Circuit
///
/// Proves that a user is a member of a set (represented as a Merkle tree)
/// without revealing which member they are.
///
/// Public inputs:
///   - root: the Merkle tree root
///   - nullifier: prevents double-use of the same membership proof
///
/// Private inputs:
///   - leaf: the user's leaf value in the tree
///   - index: position in the tree (0 to 2^20 - 1)
///   - path_elements: sibling hashes along the Merkle path
fn main(
    leaf: Field,
    index: u32,
    path_elements: [Field; 20],
    root: pub Field,
    nullifier: pub Field,
) {
    // 1. Compute Merkle root from leaf, index, and path
    let computed_root = sincerin_merkle::compute_root(leaf, index, path_elements);
    assert(computed_root == root);

    // 2. Compute and verify nullifier = Poseidon(leaf, index)
    let computed_nullifier = sincerin_poseidon::hash_2(leaf, index as Field);
    assert(computed_nullifier == nullifier);
}

// ============================================================
// Tests
// ============================================================

/// Helper: build a minimal Merkle tree and return (root, path) for testing
/// Uses a depth-20 tree with all zero siblings except at specified positions
fn build_test_tree(leaf: Field, index: u32) -> (Field, [Field; 20]) {
    let path = [0 as Field; 20];
    let root = sincerin_merkle::compute_root(leaf, index, path);
    (root, path)
}

#[test]
fn test_membership_valid_proof() {
    let leaf: Field = 42;
    let index: u32 = 0;
    let (root, path) = build_test_tree(leaf, index);
    let nullifier = sincerin_poseidon::hash_2(leaf, index as Field);
    main(leaf, index, path, root, nullifier);
}

#[test]
fn test_membership_valid_proof_nonzero_index() {
    let leaf: Field = 123;
    let index: u32 = 7;
    let (root, path) = build_test_tree(leaf, index);
    let nullifier = sincerin_poseidon::hash_2(leaf, index as Field);
    main(leaf, index, path, root, nullifier);
}

#[test]
fn test_membership_zero_leaf() {
    let leaf: Field = 0;
    let index: u32 = 0;
    let (root, path) = build_test_tree(leaf, index);
    let nullifier = sincerin_poseidon::hash_2(leaf, index as Field);
    main(leaf, index, path, root, nullifier);
}

#[test]
fn test_membership_max_index() {
    // 2^20 - 1 = 1048575
    let leaf: Field = 99;
    let index: u32 = 1048575;
    let (root, path) = build_test_tree(leaf, index);
    let nullifier = sincerin_poseidon::hash_2(leaf, index as Field);
    main(leaf, index, path, root, nullifier);
}

#[test(should_fail)]
fn test_membership_invalid_root() {
    let leaf: Field = 42;
    let index: u32 = 0;
    let (_root, path) = build_test_tree(leaf, index);
    let nullifier = sincerin_poseidon::hash_2(leaf, index as Field);
    // Use wrong root
    let wrong_root: Field = 999;
    main(leaf, index, path, wrong_root, nullifier);
}

#[test(should_fail)]
fn test_membership_invalid_nullifier() {
    let leaf: Field = 42;
    let index: u32 = 0;
    let (root, path) = build_test_tree(leaf, index);
    // Use wrong nullifier
    let wrong_nullifier: Field = 888;
    main(leaf, index, path, root, wrong_nullifier);
}

#[test(should_fail)]
fn test_membership_wrong_index() {
    let leaf: Field = 42;
    let index: u32 = 0;
    let (root, path) = build_test_tree(leaf, index);
    let nullifier = sincerin_poseidon::hash_2(leaf, index as Field);
    // Use different index (which changes the nullifier computation in main)
    // But we pass the old nullifier, so it should fail
    main(leaf, 1, path, root, nullifier);
}