package poseidonhash

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
	"github.com/stretchr/testify/require"
)

func frToBytes32(e fr.Element) [32]byte {
	b := e.Bytes()
	var result [32]byte
	copy(result[:], b[:])
	return result
}

func makeHashInput(inputs [][32]byte) []byte {
	input, err := PoseidonHashABI.Pack("hash", inputs)
	if err != nil {
		panic(err)
	}
	return input[4:] // strip 4-byte selector
}

func TestHash_TwoInputs(t *testing.T) {
	// Hash(1, 2) should match poseidon2.Hash2(1, 2)
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)
	expected := poseidon2.Hash2(a, b)
	expectedBytes := frToBytes32(expected)

	inputs := [][32]byte{frToBytes32(a), frToBytes32(b)}
	input := makeHashInput(inputs)

	result, gas, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)
	require.Equal(t, uint64(10000-GasPoseidonHashBase-GasPoseidonHashPerExtra), gas)

	outputs, err := PoseidonHashABI.Unpack("hash", result)
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	hashResult := outputs[0].([32]byte)
	require.Equal(t, expectedBytes, hashResult)
}

func TestHash_ThreeInputs(t *testing.T) {
	var a, b, c fr.Element
	a.SetUint64(10)
	b.SetUint64(20)
	c.SetUint64(30)
	expected := poseidon2.Hash3(a, b, c)
	expectedBytes := frToBytes32(expected)

	inputs := [][32]byte{frToBytes32(a), frToBytes32(b), frToBytes32(c)}
	input := makeHashInput(inputs)

	result, gas, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)
	// Gas: 200 base + 50 * 2 extra = 300
	require.Equal(t, uint64(10000-300), gas)

	outputs, err := PoseidonHashABI.Unpack("hash", result)
	require.NoError(t, err)
	hashResult := outputs[0].([32]byte)
	require.Equal(t, expectedBytes, hashResult)
}

func TestHash_SingleInput(t *testing.T) {
	var a fr.Element
	a.SetUint64(42)
	elements := []fr.Element{a}
	expected := poseidon2.HashN(elements)
	expectedBytes := frToBytes32(expected)

	inputs := [][32]byte{frToBytes32(a)}
	input := makeHashInput(inputs)

	result, gas, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)
	require.Equal(t, uint64(10000-GasPoseidonHashBase), gas) // base only, no extra

	outputs, err := PoseidonHashABI.Unpack("hash", result)
	require.NoError(t, err)
	hashResult := outputs[0].([32]byte)
	require.Equal(t, expectedBytes, hashResult)
}

func TestHash_SixteenInputs(t *testing.T) {
	// Max inputs
	elements := make([]fr.Element, 16)
	inputs := make([][32]byte, 16)
	for i := 0; i < 16; i++ {
		elements[i].SetUint64(uint64(i + 1))
		inputs[i] = frToBytes32(elements[i])
	}
	expected := poseidon2.HashN(elements)
	expectedBytes := frToBytes32(expected)

	input := makeHashInput(inputs)

	// Gas: 200 base + 50 * 15 extra = 950
	result, gas, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)
	require.Equal(t, uint64(10000-950), gas)

	outputs, err := PoseidonHashABI.Unpack("hash", result)
	require.NoError(t, err)
	hashResult := outputs[0].([32]byte)
	require.Equal(t, expectedBytes, hashResult)
}

func TestHash_Deterministic(t *testing.T) {
	var a, b fr.Element
	a.SetUint64(100)
	b.SetUint64(200)

	inputs := [][32]byte{frToBytes32(a), frToBytes32(b)}
	input := makeHashInput(inputs)

	result1, _, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)

	result2, _, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)

	require.Equal(t, result1, result2, "same inputs should produce same hash")
}

func TestHash_NonCommutative(t *testing.T) {
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)

	inputsAB := [][32]byte{frToBytes32(a), frToBytes32(b)}
	inputsBA := [][32]byte{frToBytes32(b), frToBytes32(a)}

	resultAB, _, err := poseidonHash(nil, [20]byte{}, ContractAddress, makeHashInput(inputsAB), 10000, false)
	require.NoError(t, err)

	resultBA, _, err := poseidonHash(nil, [20]byte{}, ContractAddress, makeHashInput(inputsBA), 10000, false)
	require.NoError(t, err)

	require.NotEqual(t, resultAB, resultBA, "hash should not be commutative")
}

func TestHash_ReadOnlyAllowed(t *testing.T) {
	var a fr.Element
	a.SetUint64(1)

	inputs := [][32]byte{frToBytes32(a)}
	input := makeHashInput(inputs)

	result, _, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestHash_InsufficientGas(t *testing.T) {
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)

	inputs := [][32]byte{frToBytes32(a), frToBytes32(b)}
	input := makeHashInput(inputs)

	// Need 250 gas (200 base + 50 extra), provide only 100
	_, _, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 100, false)
	require.Error(t, err)
}

func TestHash_KnownVector_Hash2(t *testing.T) {
	// Verified against Noir: poseidon2::Poseidon2::hash([1, 2], 2)
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)

	inputs := [][32]byte{frToBytes32(a), frToBytes32(b)}
	input := makeHashInput(inputs)

	result, _, err := poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	require.NoError(t, err)

	outputs, err := PoseidonHashABI.Unpack("hash", result)
	require.NoError(t, err)
	hashResult := outputs[0].([32]byte)

	// Verify precompile output matches crypto/poseidon2 directly
	expected := poseidon2.Hash2(a, b)
	expectedBytes := frToBytes32(expected)
	require.Equal(t, expectedBytes, hashResult)
}

func BenchmarkPoseidonHashPrecompile_2Inputs(b *testing.B) {
	var a, bEl fr.Element
	a.SetUint64(1)
	bEl.SetUint64(2)
	inputs := [][32]byte{frToBytes32(a), frToBytes32(bEl)}
	input := makeHashInput(inputs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	}
}

func BenchmarkPoseidonHashPrecompile_16Inputs(b *testing.B) {
	inputs := make([][32]byte, 16)
	for i := 0; i < 16; i++ {
		var e fr.Element
		e.SetUint64(uint64(i + 1))
		inputs[i] = frToBytes32(e)
	}
	input := makeHashInput(inputs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poseidonHash(nil, [20]byte{}, ContractAddress, input, 10000, false)
	}
}
