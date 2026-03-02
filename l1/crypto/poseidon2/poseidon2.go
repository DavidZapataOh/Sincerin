// Package poseidon2 implements the Poseidon2 hash function over the BN254 scalar field,
// compatible with Noir/Barretenberg (Aztec). Parameters: t=4, d=5, rF=8, rP=56.
package poseidon2

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// Permutation applies the Poseidon2 permutation to a 4-element state in place.
func Permutation(state *[T]fr.Element) {
	// Initial external matrix multiplication
	matMulExternal(state)

	// First rF/2 = 4 full rounds
	for r := 0; r < RoundsF/2; r++ {
		addRoundConstants(state, r)
		sBoxFull(state)
		matMulExternal(state)
	}

	// rP = 56 partial rounds
	for r := RoundsF / 2; r < RoundsF/2+RoundsP; r++ {
		state[0].Add(&state[0], &roundConstants[r][0])
		sBoxSingle(&state[0])
		matMulInternal(state)
	}

	// Last rF/2 = 4 full rounds
	for r := RoundsF/2 + RoundsP; r < RoundsF+RoundsP; r++ {
		addRoundConstants(state, r)
		sBoxFull(state)
		matMulExternal(state)
	}
}

// Hash2 computes Poseidon2 hash of two field elements using a sponge construction.
// Matches Noir's std::hash::poseidon2::Poseidon2::hash([a, b], 2).
func Hash2(a, b fr.Element) fr.Element {
	var state [T]fr.Element
	// IV = input_length * 2^64
	state[Rate].SetUint64(2)
	var shift fr.Element
	shift.SetString("18446744073709551616") // 2^64
	state[Rate].Mul(&state[Rate], &shift)

	// Absorb: both elements fit in cache (size 2 < rate 3), so add and permute on squeeze
	state[0].Add(&state[0], &a)
	state[1].Add(&state[1], &b)
	Permutation(&state)

	return state[0]
}

// Hash3 computes Poseidon2 hash of three field elements.
// Matches Noir's std::hash::poseidon2::Poseidon2::hash([a, b, c], 3).
func Hash3(a, b, c fr.Element) fr.Element {
	var state [T]fr.Element
	// IV = 3 * 2^64
	state[Rate].SetUint64(3)
	var shift fr.Element
	shift.SetString("18446744073709551616") // 2^64
	state[Rate].Mul(&state[Rate], &shift)

	// Absorb: 3 elements fill the rate exactly, so duplex immediately
	state[0].Add(&state[0], &a)
	state[1].Add(&state[1], &b)
	state[2].Add(&state[2], &c)
	Permutation(&state)

	// Cache is empty on squeeze, no additional permutation needed
	return state[0]
}

// HashN computes Poseidon2 hash of N field elements using the sponge construction.
// Matches Noir's std::hash::poseidon2::Poseidon2::hash(inputs, N).
func HashN(inputs []fr.Element) fr.Element {
	n := len(inputs)
	if n == 0 {
		var state [T]fr.Element
		Permutation(&state)
		return state[0]
	}

	var state [T]fr.Element
	// IV = n * 2^64
	state[Rate].SetUint64(uint64(n))
	var shift fr.Element
	shift.SetString("18446744073709551616") // 2^64
	state[Rate].Mul(&state[Rate], &shift)

	cacheSize := 0
	for _, inp := range inputs {
		state[cacheSize].Add(&state[cacheSize], &inp)
		cacheSize++
		if cacheSize == Rate {
			Permutation(&state)
			cacheSize = 0
		}
	}

	// Squeeze: if cache has remaining elements, permute
	if cacheSize != 0 {
		Permutation(&state)
	}

	return state[0]
}

func addRoundConstants(state *[T]fr.Element, round int) {
	for i := 0; i < T; i++ {
		state[i].Add(&state[i], &roundConstants[round][i])
	}
}

func sBoxFull(state *[T]fr.Element) {
	for i := 0; i < T; i++ {
		sBoxSingle(&state[i])
	}
}

// sBoxSingle applies x^5 to a single field element.
func sBoxSingle(x *fr.Element) {
	var x2, x4 fr.Element
	x2.Square(x)
	x4.Square(&x2)
	x.Mul(x, &x4)
}

// matMulExternal multiplies the state by the Barretenberg external 4x4 MDS matrix.
// Matrix: [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
// From poseidon2_permutation.hpp matrix_multiplication_4x4().
func matMulExternal(state *[T]fr.Element) {
	var s0, s1, s2, s3 fr.Element
	s0.Set(&state[0])
	s1.Set(&state[1])
	s2.Set(&state[2])
	s3.Set(&state[3])

	// Matching zemse/poseidon2-evm Solidity implementation exactly:
	var t0, t1, t2, t3, t4, t5, t6, t7 fr.Element

	t0.Add(&s0, &s1)  // A + B
	t1.Add(&s2, &s3)  // C + D
	t2.Double(&s1)     // 2B
	t2.Add(&t2, &t1)  // 2B + C + D
	t3.Double(&s3)     // 2D
	t3.Add(&t3, &t0)  // 2D + A + B

	t4.Double(&t1)     // 2*(C+D)
	t4.Double(&t4)     // 4*(C+D) = 4C + 4D
	t4.Add(&t4, &t3)   // A + B + 4C + 6D

	t5.Double(&t0)     // 2*(A+B)
	t5.Double(&t5)     // 4*(A+B) = 4A + 4B
	t5.Add(&t5, &t2)   // 4A + 6B + C + D

	t6.Add(&t3, &t5)   // (2D+A+B) + (4A+6B+C+D) = 5A + 7B + C + 3D
	t7.Add(&t2, &t4)   // (2B+C+D) + (A+B+4C+6D) = A + 3B + 5C + 7D

	state[0].Set(&t6)  // 5A + 7B + C + 3D
	state[1].Set(&t5)  // 4A + 6B + C + D
	state[2].Set(&t7)  // A + 3B + 5C + 7D
	state[3].Set(&t4)  // A + B + 4C + 6D
}

// matMulInternal multiplies the state by the internal matrix.
// result[i] = diagM1[i] * state[i] + sum(state)
func matMulInternal(state *[T]fr.Element) {
	var sum fr.Element
	for i := 0; i < T; i++ {
		sum.Add(&sum, &state[i])
	}
	for i := 0; i < T; i++ {
		var tmp fr.Element
		tmp.Mul(&state[i], &internalDiagM1[i])
		state[i].Add(&tmp, &sum)
	}
}
