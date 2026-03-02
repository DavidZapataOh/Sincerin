package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func setFr(s string) fr.Element {
	var e fr.Element
	e.SetString(s)
	return e
}

func setFrU64(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

// TestPermutation_KnownVector tests the raw permutation against the Barretenberg test vector.
// Input: [0, 1, 2, 3] → Output: [known0, known1, known2, known3]
func TestPermutation_KnownVector(t *testing.T) {
	state := [T]fr.Element{
		setFrU64(0),
		setFrU64(1),
		setFrU64(2),
		setFrU64(3),
	}
	Permutation(&state)

	expected := [T]fr.Element{
		setFr("0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737"),
		setFr("0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662"),
		setFr("0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb"),
		setFr("0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a"),
	}

	for i := 0; i < T; i++ {
		require.True(t, state[i].Equal(&expected[i]),
			"state[%d]: got %s, expected %s", i, state[i].String(), expected[i].String())
	}
}

// TestHash2_KnownVectors tests Hash2 against values computed by Noir.
func TestHash2_KnownVectors(t *testing.T) {
	tests := []struct {
		name     string
		a, b     fr.Element
		expected fr.Element
	}{
		{
			name:     "hash_2(1, 2)",
			a:        setFrU64(1),
			b:        setFrU64(2),
			expected: setFr("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383"),
		},
		{
			name:     "hash_2(2, 1)",
			a:        setFrU64(2),
			b:        setFrU64(1),
			expected: setFr("0x176ad1cae93876a4632bc6431edd92ba205845f7e9aa369840c790f261640d1a"),
		},
		{
			name:     "hash_2(0, 0)",
			a:        setFrU64(0),
			b:        setFrU64(0),
			expected: setFr("0x0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1"),
		},
		{
			name:     "hash_2(1, 1)",
			a:        setFrU64(1),
			b:        setFrU64(1),
			expected: setFr("0x1df6080e5bf5cefb3e40daf91cfcc5a267781505471aa058c0b205986774f978"),
		},
		{
			name:     "hash_2(0x1234, 0x5678)",
			a:        setFrU64(0x1234),
			b:        setFrU64(0x5678),
			expected: setFr("0x16f7134c79a95ba4713b52ea3b23a265d55eacbf5b657c9295414c75518f3c60"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Hash2(tt.a, tt.b)
			require.True(t, result.Equal(&tt.expected),
				"got %s, expected %s", result.String(), tt.expected.String())
		})
	}
}

// TestHash3_KnownVector tests Hash3 against a value computed by Noir.
func TestHash3_KnownVector(t *testing.T) {
	a := setFrU64(1)
	b := setFrU64(2)
	c := setFrU64(3)
	expected := setFr("0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8")

	result := Hash3(a, b, c)
	require.True(t, result.Equal(&expected),
		"got %s, expected %s", result.String(), expected.String())
}

// TestHashN_MatchesHash2 verifies HashN with 2 inputs gives same result as Hash2.
func TestHashN_MatchesHash2(t *testing.T) {
	a := setFrU64(1)
	b := setFrU64(2)

	h2 := Hash2(a, b)
	hN := HashN([]fr.Element{a, b})

	require.True(t, h2.Equal(&hN),
		"Hash2 (%s) != HashN (%s)", h2.String(), hN.String())
}

// TestHashN_MatchesHash3 verifies HashN with 3 inputs gives same result as Hash3.
func TestHashN_MatchesHash3(t *testing.T) {
	a := setFrU64(1)
	b := setFrU64(2)
	c := setFrU64(3)

	h3 := Hash3(a, b, c)
	hN := HashN([]fr.Element{a, b, c})

	require.True(t, h3.Equal(&hN),
		"Hash3 (%s) != HashN (%s)", h3.String(), hN.String())
}

// TestHash2_NonCommutative verifies that Hash2(a,b) != Hash2(b,a).
func TestHash2_NonCommutative(t *testing.T) {
	a := setFrU64(1)
	b := setFrU64(2)

	h1 := Hash2(a, b)
	h2 := Hash2(b, a)

	require.False(t, h1.Equal(&h2), "Hash2 should not be commutative")
}

// TestSBox verifies x^5 computation.
func TestSBox(t *testing.T) {
	x := setFrU64(3) // 3^5 = 243
	sBoxSingle(&x)
	expected := setFrU64(243)
	require.True(t, x.Equal(&expected), "3^5 should be 243, got %s", x.String())
}

// TestHashN_BarretenbergStdlib verifies against test vectors from barretenberg stdlib.
func TestHashN_BarretenbergStdlib(t *testing.T) {
	// hash([0]) = 0x2710144414c3a5f2354f4c08d52ed655b9fe253b4bf12cb9ad3de693d9b1db11
	result := HashN([]fr.Element{setFrU64(0)})
	expected := setFr("0x2710144414c3a5f2354f4c08d52ed655b9fe253b4bf12cb9ad3de693d9b1db11")
	require.True(t, result.Equal(&expected),
		"hash([0]): got %s, expected %s", result.String(), expected.String())

	// hash([0, 0, 0]) = 0x2a5de47ed300af27b706aaa14762fc468f5cfc16cd8116eb6b09b0f2643ca2b9
	result = HashN([]fr.Element{setFrU64(0), setFrU64(0), setFrU64(0)})
	expected = setFr("0x2a5de47ed300af27b706aaa14762fc468f5cfc16cd8116eb6b09b0f2643ca2b9")
	require.True(t, result.Equal(&expected),
		"hash([0,0,0]): got %s, expected %s", result.String(), expected.String())
}

func BenchmarkPermutation(b *testing.B) {
	state := [T]fr.Element{setFrU64(0), setFrU64(1), setFrU64(2), setFrU64(3)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Permutation(&state)
	}
}

func BenchmarkHash2(b *testing.B) {
	a := setFrU64(1)
	bv := setFrU64(2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash2(a, bv)
	}
}
