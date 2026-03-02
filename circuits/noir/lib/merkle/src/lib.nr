// Merkle tree utilities using Poseidon hash
use sincerin_poseidon;

/// Merkle tree depth for Sincerin circuits
pub global DEPTH: u32 = 20;

/// Compute Merkle root from a leaf, its index, and the sibling path.
///
/// The index bits determine whether the current node is on the left (bit=0) or right (bit=1)
/// at each level of the tree.
pub fn compute_root(leaf: Field, index: u32, path: [Field; 20]) -> Field {
    let mut current = leaf;
    for i in 0..20 {
        let bit = (index >> i) & 1;
        if bit == 0 {
            current = sincerin_poseidon::hash_2(current, path[i]);
        } else {
            current = sincerin_poseidon::hash_2(path[i], current);
        }
    }
    current
}

#[test]
fn test_compute_root_deterministic() {
    let leaf: Field = 5;
    let index: u32 = 0;
    let mut path = [0 as Field; 20];
    path[0] = 10;

    let root1 = compute_root(leaf, index, path);
    let root2 = compute_root(leaf, index, path);
    assert(root1 == root2);
}

#[test]
fn test_compute_root_different_index() {
    let leaf: Field = 5;
    let mut path = [0 as Field; 20];
    path[0] = 10;

    let root_left = compute_root(leaf, 0, path);
    let root_right = compute_root(leaf, 1, path);
    // Different positions should yield different roots
    assert(root_left != root_right);
}

#[test]
fn test_compute_root_zero_leaf() {
    let leaf: Field = 0;
    let index: u32 = 0;
    let path = [0 as Field; 20];
    // Should not panic, even with all zeros
    let _root = compute_root(leaf, index, path);
}