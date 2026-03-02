package merkletreeinsert

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
	"github.com/sincerin/l1/crypto/smt"
	"github.com/stretchr/testify/require"
)

func resetTree() {
	GlobalSMT.Reset()
}

func makeInsertInput(proofHash, metadata [32]byte) []byte {
	input, err := MerkleTreeInsertABI.Pack("insert", proofHash, metadata)
	if err != nil {
		panic(err)
	}
	// Remove 4-byte function selector
	return input[4:]
}

func frToBytes32(e fr.Element) [32]byte {
	b := e.Bytes()
	var result [32]byte
	copy(result[:], b[:])
	return result
}

func TestInsert_FirstLeaf(t *testing.T) {
	resetTree()

	var proofHash, metadata [32]byte
	proofHash[31] = 1
	metadata[31] = 2

	input := makeInsertInput(proofHash, metadata)
	result, gas, err := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)
	require.Equal(t, uint64(10000-GasMerkleTreeInsert), gas)
	require.NotNil(t, result)

	// Unpack result
	outputs, err := MerkleTreeInsertABI.Unpack("insert", result)
	require.NoError(t, err)
	require.Len(t, outputs, 2)

	newRoot := outputs[0].([32]byte)
	leafIndex := outputs[1].(*big.Int)

	require.True(t, leafIndex.Cmp(big.NewInt(0)) == 0, "leafIndex should be 0, got %s", leafIndex)
	require.NotEqual(t, [32]byte{}, newRoot, "root should not be zero")
}

func TestInsert_SequentialIndices(t *testing.T) {
	resetTree()

	for i := 0; i < 20; i++ {
		var proofHash, metadata [32]byte
		proofHash[31] = byte(i)
		metadata[31] = byte(i + 100)

		input := makeInsertInput(proofHash, metadata)
		result, _, err := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, false)
		require.NoError(t, err)

		outputs, err := MerkleTreeInsertABI.Unpack("insert", result)
		require.NoError(t, err)
		leafIndex := outputs[1].(*big.Int)
		require.True(t, leafIndex.Cmp(big.NewInt(int64(i))) == 0, "leaf %d should have index %d, got %s", i, i, leafIndex)
	}
}

func TestInsert_RootChanges(t *testing.T) {
	resetTree()

	var prevRoot [32]byte
	for i := 0; i < 5; i++ {
		var proofHash, metadata [32]byte
		proofHash[31] = byte(i + 1)

		input := makeInsertInput(proofHash, metadata)
		result, _, err := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, false)
		require.NoError(t, err)

		outputs, _ := MerkleTreeInsertABI.Unpack("insert", result)
		newRoot := outputs[0].([32]byte)
		require.NotEqual(t, prevRoot, newRoot, "root should change after insert %d", i)
		prevRoot = newRoot
	}
}

func TestInsert_Deterministic(t *testing.T) {
	// Insert same values twice, roots should match
	resetTree()
	var proofHash, metadata [32]byte
	proofHash[31] = 42
	metadata[31] = 99

	input := makeInsertInput(proofHash, metadata)
	result1, _, _ := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, false)
	outputs1, _ := MerkleTreeInsertABI.Unpack("insert", result1)
	root1 := outputs1[0].([32]byte)

	resetTree()
	result2, _, _ := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, false)
	outputs2, _ := MerkleTreeInsertABI.Unpack("insert", result2)
	root2 := outputs2[0].([32]byte)

	require.Equal(t, root1, root2, "same inputs should produce same root")
}

func TestInsert_ReadOnlyFails(t *testing.T) {
	resetTree()
	var proofHash, metadata [32]byte
	input := makeInsertInput(proofHash, metadata)
	_, _, err := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, true)
	require.Error(t, err, "insert should fail in read-only mode")
}

func TestInsert_InsufficientGas(t *testing.T) {
	resetTree()
	var proofHash, metadata [32]byte
	input := makeInsertInput(proofHash, metadata)
	_, _, err := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 100, false)
	require.Error(t, err, "should fail with insufficient gas")
}

func TestInsertAndVerify_CrossPrecompile(t *testing.T) {
	resetTree()

	// Insert 10 leaves
	leaves := make([]fr.Element, 10)
	for i := 0; i < 10; i++ {
		var ph fr.Element
		ph.SetUint64(uint64(i))
		var md fr.Element
		md.SetUint64(uint64(i) + 100)

		leaves[i] = poseidon2.Hash2(ph, md)

		phBytes := frToBytes32(ph)
		mdBytes := frToBytes32(md)
		input := makeInsertInput(phBytes, mdBytes)
		_, _, err := merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, false)
		require.NoError(t, err)
	}

	// Verify each leaf using the SMT directly
	finalRoot := GlobalSMT.Root()
	for i := 0; i < 10; i++ {
		proof, err := GlobalSMT.GetProof(uint64(i))
		require.NoError(t, err)
		valid := smt.VerifyProof(leaves[i], uint64(i), proof, finalRoot)
		require.True(t, valid, "leaf %d should verify", i)
	}
}

func BenchmarkInsertPrecompile(b *testing.B) {
	resetTree()
	var proofHash, metadata [32]byte
	proofHash[31] = 42
	input := makeInsertInput(proofHash, metadata)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merkleTreeInsert(nil, [20]byte{}, ContractAddress, input, 10000, false)
	}
}
