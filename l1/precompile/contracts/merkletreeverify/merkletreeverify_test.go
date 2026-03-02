package merkletreeverify

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
	"github.com/sincerin/l1/crypto/smt"
	"github.com/stretchr/testify/require"
)

func frToBytes32(e fr.Element) [32]byte {
	b := e.Bytes()
	var result [32]byte
	copy(result[:], b[:])
	return result
}

func makeVerifyInput(proofHash, metadata [32]byte, leafIndex uint64, proof [smt.TreeDepth]fr.Element, root fr.Element) []byte {
	var proofArr [32][32]byte
	for i := 0; i < smt.TreeDepth; i++ {
		proofArr[i] = frToBytes32(proof[i])
	}
	rootArr := frToBytes32(root)

	input, err := MerkleTreeVerifyABI.Pack("verify",
		proofHash,
		metadata,
		new(big.Int).SetUint64(leafIndex),
		proofArr,
		rootArr,
	)
	if err != nil {
		panic(err)
	}
	return input[4:] // strip 4-byte selector
}

func TestVerify_ValidProof(t *testing.T) {
	tree := smt.New()

	var ph, md fr.Element
	ph.SetUint64(42)
	md.SetUint64(99)
	leaf := poseidon2.Hash2(ph, md)

	tree.Insert(leaf)
	root := tree.Root()
	proof, err := tree.GetProof(0)
	require.NoError(t, err)

	phBytes := frToBytes32(ph)
	mdBytes := frToBytes32(md)
	input := makeVerifyInput(phBytes, mdBytes, 0, proof, root)

	result, gas, err := merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)
	require.Equal(t, uint64(10000-GasMerkleTreeVerify), gas)

	outputs, err := MerkleTreeVerifyABI.Unpack("verify", result)
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	valid := outputs[0].(bool)
	require.True(t, valid, "valid proof should verify")
}

func TestVerify_InvalidProof(t *testing.T) {
	tree := smt.New()

	var ph, md fr.Element
	ph.SetUint64(42)
	md.SetUint64(99)
	leaf := poseidon2.Hash2(ph, md)

	tree.Insert(leaf)
	root := tree.Root()
	proof, _ := tree.GetProof(0)

	// Corrupt a sibling hash
	proof[0].Add(&proof[0], new(fr.Element).SetUint64(1))

	phBytes := frToBytes32(ph)
	mdBytes := frToBytes32(md)
	input := makeVerifyInput(phBytes, mdBytes, 0, proof, root)

	result, _, err := merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)

	outputs, _ := MerkleTreeVerifyABI.Unpack("verify", result)
	valid := outputs[0].(bool)
	require.False(t, valid, "corrupted proof should not verify")
}

func TestVerify_WrongRoot(t *testing.T) {
	tree := smt.New()

	var ph, md fr.Element
	ph.SetUint64(42)
	md.SetUint64(99)
	leaf := poseidon2.Hash2(ph, md)

	tree.Insert(leaf)
	proof, _ := tree.GetProof(0)

	// Use wrong root
	var wrongRoot fr.Element
	wrongRoot.SetUint64(999)

	phBytes := frToBytes32(ph)
	mdBytes := frToBytes32(md)
	input := makeVerifyInput(phBytes, mdBytes, 0, proof, wrongRoot)

	result, _, err := merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)

	outputs, _ := MerkleTreeVerifyABI.Unpack("verify", result)
	valid := outputs[0].(bool)
	require.False(t, valid, "wrong root should not verify")
}

func TestVerify_WrongLeafIndex(t *testing.T) {
	tree := smt.New()

	var ph, md fr.Element
	ph.SetUint64(42)
	md.SetUint64(99)
	leaf := poseidon2.Hash2(ph, md)

	tree.Insert(leaf)
	root := tree.Root()
	proof, _ := tree.GetProof(0)

	phBytes := frToBytes32(ph)
	mdBytes := frToBytes32(md)
	input := makeVerifyInput(phBytes, mdBytes, 1, proof, root) // wrong index

	result, _, err := merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)

	outputs, _ := MerkleTreeVerifyABI.Unpack("verify", result)
	valid := outputs[0].(bool)
	require.False(t, valid, "wrong leaf index should not verify")
}

func TestVerify_InsufficientGas(t *testing.T) {
	tree := smt.New()
	var ph, md fr.Element
	leaf := poseidon2.Hash2(ph, md)
	tree.Insert(leaf)
	proof, _ := tree.GetProof(0)

	phBytes := frToBytes32(ph)
	mdBytes := frToBytes32(md)
	input := makeVerifyInput(phBytes, mdBytes, 0, proof, tree.Root())

	_, _, err := merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 100, false)
	require.Error(t, err)
}

func TestInsertAndVerify_Integration_100Leaves(t *testing.T) {
	tree := smt.New()
	type leafData struct {
		ph, md fr.Element
	}
	data := make([]leafData, 100)

	for i := 0; i < 100; i++ {
		data[i].ph.SetUint64(uint64(i))
		data[i].md.SetUint64(uint64(i)*7 + 3)
		leaf := poseidon2.Hash2(data[i].ph, data[i].md)
		tree.Insert(leaf)
	}

	finalRoot := tree.Root()

	for i := 0; i < 100; i++ {
		proof, err := tree.GetProof(uint64(i))
		require.NoError(t, err)

		phBytes := frToBytes32(data[i].ph)
		mdBytes := frToBytes32(data[i].md)
		input := makeVerifyInput(phBytes, mdBytes, uint64(i), proof, finalRoot)

		result, _, err := merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 10000, false)
		require.NoError(t, err)

		outputs, _ := MerkleTreeVerifyABI.Unpack("verify", result)
		valid := outputs[0].(bool)
		require.True(t, valid, "leaf %d should verify against final root", i)
	}
}

func TestVerify_ReadOnlyAllowed(t *testing.T) {
	tree := smt.New()
	var ph, md fr.Element
	leaf := poseidon2.Hash2(ph, md)
	tree.Insert(leaf)
	proof, _ := tree.GetProof(0)

	phBytes := frToBytes32(ph)
	mdBytes := frToBytes32(md)
	input := makeVerifyInput(phBytes, mdBytes, 0, proof, tree.Root())

	// Verify should work in read-only mode (it's a view function)
	result, _, err := merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 10000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func BenchmarkVerifyPrecompile(b *testing.B) {
	tree := smt.New()
	for i := 0; i < 1000; i++ {
		var ph fr.Element
		ph.SetUint64(uint64(i))
		tree.Insert(poseidon2.Hash2(ph, ph))
	}
	proof, _ := tree.GetProof(500)
	var ph fr.Element
	ph.SetUint64(500)
	phBytes := frToBytes32(ph)
	input := makeVerifyInput(phBytes, phBytes, 500, proof, tree.Root())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merkleTreeVerify(nil, [20]byte{}, ContractAddress, input, 10000, false)
	}
}
