// Package smt implements a Sparse Merkle Tree using Poseidon2 hash over BN254.
// Depth 32, supporting up to 2^32 leaves.
package smt

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
)

const TreeDepth = 32

// SparseMerkleTree is an append-only Merkle tree using Poseidon2 hash.
type SparseMerkleTree struct {
	mu         sync.RWMutex
	nodes      map[string]fr.Element
	root       fr.Element
	nextLeaf   uint64
	zeroHashes [TreeDepth + 1]fr.Element // precomputed hashes for empty subtrees
}

// New creates a new empty SparseMerkleTree with precomputed zero hashes.
func New() *SparseMerkleTree {
	smt := &SparseMerkleTree{
		nodes: make(map[string]fr.Element),
	}

	// zeroHashes[0] = 0 (empty leaf)
	// zeroHashes[i] = Hash2(zeroHashes[i-1], zeroHashes[i-1])
	for i := 1; i <= TreeDepth; i++ {
		smt.zeroHashes[i] = poseidon2.Hash2(smt.zeroHashes[i-1], smt.zeroHashes[i-1])
	}
	smt.root = smt.zeroHashes[TreeDepth]

	return smt
}

// Root returns the current tree root.
func (smt *SparseMerkleTree) Root() fr.Element {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	return smt.root
}

// NextLeaf returns the index that the next insert will use.
func (smt *SparseMerkleTree) NextLeaf() uint64 {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	return smt.nextLeaf
}

// Insert adds a leaf value to the tree at the next available index.
// Returns the new root and the leaf index.
func (smt *SparseMerkleTree) Insert(leafValue fr.Element) (newRoot fr.Element, leafIndex uint64, err error) {
	smt.mu.Lock()
	defer smt.mu.Unlock()

	if smt.nextLeaf >= (1 << TreeDepth) {
		return fr.Element{}, 0, fmt.Errorf("tree is full: max %d leaves", 1<<TreeDepth)
	}

	index := smt.nextLeaf
	smt.nextLeaf++

	current := leafValue
	smt.setNode(0, index, current)

	for level := 0; level < TreeDepth; level++ {
		parentIndex := index / 2
		isRight := index % 2

		var left, right fr.Element
		if isRight == 0 {
			left = current
			right = smt.getNode(level, index+1)
		} else {
			left = smt.getNode(level, index-1)
			right = current
		}

		current = poseidon2.Hash2(left, right)
		smt.setNode(level+1, parentIndex, current)
		index = parentIndex
	}

	smt.root = current
	return smt.root, smt.nextLeaf - 1, nil
}

// GetProof returns the Merkle proof (sibling hashes) for a given leaf index.
func (smt *SparseMerkleTree) GetProof(leafIndex uint64) ([TreeDepth]fr.Element, error) {
	smt.mu.RLock()
	defer smt.mu.RUnlock()

	if leafIndex >= smt.nextLeaf {
		return [TreeDepth]fr.Element{}, fmt.Errorf("leaf index %d out of range (next=%d)", leafIndex, smt.nextLeaf)
	}

	var proof [TreeDepth]fr.Element
	index := leafIndex

	for level := 0; level < TreeDepth; level++ {
		if index%2 == 0 {
			proof[level] = smt.getNode(level, index+1)
		} else {
			proof[level] = smt.getNode(level, index-1)
		}
		index /= 2
	}

	return proof, nil
}

// VerifyProof verifies a Merkle inclusion proof against a root.
func VerifyProof(leafHash fr.Element, leafIndex uint64, proof [TreeDepth]fr.Element, root fr.Element) bool {
	current := leafHash
	index := leafIndex

	for level := 0; level < TreeDepth; level++ {
		if index%2 == 0 {
			current = poseidon2.Hash2(current, proof[level])
		} else {
			current = poseidon2.Hash2(proof[level], current)
		}
		index /= 2
	}

	return current.Equal(&root)
}

func nodeKey(level int, index uint64) string {
	return fmt.Sprintf("%d:%d", level, index)
}

func (smt *SparseMerkleTree) setNode(level int, index uint64, value fr.Element) {
	smt.nodes[nodeKey(level, index)] = value
}

func (smt *SparseMerkleTree) getNode(level int, index uint64) fr.Element {
	if v, ok := smt.nodes[nodeKey(level, index)]; ok {
		return v
	}
	return smt.zeroHashes[level]
}

// Reset clears the tree to its initial empty state.
func (smt *SparseMerkleTree) Reset() {
	smt.mu.Lock()
	defer smt.mu.Unlock()
	smt.nodes = make(map[string]fr.Element)
	smt.nextLeaf = 0
	smt.root = smt.zeroHashes[TreeDepth]
}
