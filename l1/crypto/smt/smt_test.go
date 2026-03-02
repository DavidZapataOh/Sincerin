package smt

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
	"github.com/stretchr/testify/require"
)

func frU64(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

func TestNew_EmptyRoot(t *testing.T) {
	tree := New()
	root := tree.Root()
	// Root of empty tree is zeroHashes[32]
	require.False(t, root.IsZero(), "empty root should not be zero (it's hash of zero hashes)")
}

func TestInsert_FirstLeaf(t *testing.T) {
	tree := New()
	leaf := poseidon2.Hash2(frU64(1), frU64(2))
	root, index, err := tree.Insert(leaf)
	require.NoError(t, err)
	require.Equal(t, uint64(0), index)
	require.False(t, root.IsZero())
}

func TestInsert_SequentialIndices(t *testing.T) {
	tree := New()
	for i := uint64(0); i < 100; i++ {
		leaf := poseidon2.Hash2(frU64(i), frU64(i+1000))
		_, index, err := tree.Insert(leaf)
		require.NoError(t, err)
		require.Equal(t, i, index, "leaf %d should have index %d", i, i)
	}
}

func TestInsert_RootChanges(t *testing.T) {
	tree := New()
	var prevRoot fr.Element
	for i := uint64(0); i < 10; i++ {
		leaf := frU64(i + 1)
		root, _, err := tree.Insert(leaf)
		require.NoError(t, err)
		require.False(t, root.Equal(&prevRoot), "root should change after insert %d", i)
		prevRoot = root
	}
}

func TestInsert_Deterministic(t *testing.T) {
	// Two trees with same inserts should produce same roots
	tree1 := New()
	tree2 := New()

	for i := uint64(0); i < 10; i++ {
		leaf := frU64(i + 42)
		root1, _, _ := tree1.Insert(leaf)
		root2, _, _ := tree2.Insert(leaf)
		require.True(t, root1.Equal(&root2), "roots should match at insert %d", i)
	}
}

func TestGetProof_AndVerify(t *testing.T) {
	tree := New()

	// Insert some leaves
	leaves := make([]fr.Element, 10)
	for i := 0; i < 10; i++ {
		leaves[i] = poseidon2.Hash2(frU64(uint64(i)), frU64(uint64(i)+100))
		tree.Insert(leaves[i])
	}

	finalRoot := tree.Root()

	// Verify each leaf
	for i := 0; i < 10; i++ {
		proof, err := tree.GetProof(uint64(i))
		require.NoError(t, err)
		valid := VerifyProof(leaves[i], uint64(i), proof, finalRoot)
		require.True(t, valid, "leaf %d should verify against final root", i)
	}
}

func TestVerifyProof_InvalidProof(t *testing.T) {
	tree := New()
	leaf := frU64(42)
	tree.Insert(leaf)

	proof, err := tree.GetProof(0)
	require.NoError(t, err)

	root := tree.Root()

	// Flip a bit in the proof
	proof[0].Add(&proof[0], new(fr.Element).SetUint64(1))

	valid := VerifyProof(leaf, 0, proof, root)
	require.False(t, valid, "should not verify with corrupted proof")
}

func TestVerifyProof_WrongRoot(t *testing.T) {
	tree := New()
	leaf := frU64(42)
	tree.Insert(leaf)

	proof, _ := tree.GetProof(0)

	// Use a wrong root
	wrongRoot := frU64(999)
	valid := VerifyProof(leaf, 0, proof, wrongRoot)
	require.False(t, valid, "should not verify against wrong root")
}

func TestVerifyProof_WrongLeafIndex(t *testing.T) {
	tree := New()
	leaf := frU64(42)
	tree.Insert(leaf)

	proof, _ := tree.GetProof(0)
	root := tree.Root()

	// Use wrong leaf index
	valid := VerifyProof(leaf, 1, proof, root)
	require.False(t, valid, "should not verify with wrong leaf index")
}

func TestInsertAndVerify_100Leaves(t *testing.T) {
	tree := New()
	leaves := make([]fr.Element, 100)

	for i := 0; i < 100; i++ {
		leaves[i] = poseidon2.Hash2(frU64(uint64(i)), frU64(uint64(i)*7+3))
		tree.Insert(leaves[i])
	}

	finalRoot := tree.Root()

	for i := 0; i < 100; i++ {
		proof, err := tree.GetProof(uint64(i))
		require.NoError(t, err)
		valid := VerifyProof(leaves[i], uint64(i), proof, finalRoot)
		require.True(t, valid, "leaf %d should verify against final root", i)
	}
}

func TestInsert_InvalidInput(t *testing.T) {
	tree := New()
	_, err := tree.GetProof(0) // No leaves inserted
	require.Error(t, err)
}

func TestReset(t *testing.T) {
	tree := New()
	emptyRoot := tree.Root()

	tree.Insert(frU64(1))
	require.NotEqual(t, emptyRoot, tree.Root())

	tree.Reset()
	require.True(t, emptyRoot.Equal(addrOf(tree.Root())), "root should match empty after reset")
	require.Equal(t, uint64(0), tree.NextLeaf())
}

func addrOf(e fr.Element) *fr.Element { return &e }

func BenchmarkInsert(b *testing.B) {
	tree := New()
	leaf := frU64(42)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Insert(leaf)
	}
}

func BenchmarkVerifyProof(b *testing.B) {
	tree := New()
	for i := 0; i < 1000; i++ {
		tree.Insert(frU64(uint64(i)))
	}
	proof, _ := tree.GetProof(500)
	root := tree.Root()
	leaf := frU64(500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyProof(leaf, 500, proof, root)
	}
}
