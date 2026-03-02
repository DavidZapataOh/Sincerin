package poseidon2

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func printState(label string, state *[T]fr.Element) {
	fmt.Printf("=== %s ===\n", label)
	for i := 0; i < T; i++ {
		b := state[i].Bytes()
		fmt.Printf("  [%d] = 0x%x\n", i, b)
	}
}

func TestDebugPermutationAllRounds(t *testing.T) {
	state := [T]fr.Element{}
	state[0].SetUint64(0)
	state[1].SetUint64(1)
	state[2].SetUint64(2)
	state[3].SetUint64(3)

	printState("Initial", &state)

	matMulExternal(&state)
	printState("After initial matMulExternal", &state)

	// First 4 full rounds
	for r := 0; r < RoundsF/2; r++ {
		addRoundConstants(&state, r)
		printState(fmt.Sprintf("Round %d: after addRC", r), &state)
		sBoxFull(&state)
		printState(fmt.Sprintf("Round %d: after sBox", r), &state)
		matMulExternal(&state)
		printState(fmt.Sprintf("Round %d: after matMulExt", r), &state)
	}

	// First 3 partial rounds only
	for r := RoundsF / 2; r < RoundsF/2+3; r++ {
		state[0].Add(&state[0], &roundConstants[r][0])
		sBoxSingle(&state[0])
		matMulInternal(&state)
		printState(fmt.Sprintf("Partial round %d: after all", r), &state)
	}

	fmt.Println("\n--- Skipping remaining rounds for brevity ---")
}

func TestDebugMatMulExternal(t *testing.T) {
	// Matrix is [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
	// Test with [1, 0, 0, 0] → column 0 = [5, 4, 1, 1]
	state := [T]fr.Element{}
	state[0].SetUint64(1)
	matMulExternal(&state)

	var expected [T]fr.Element
	expected[0].SetUint64(5)
	expected[1].SetUint64(4)
	expected[2].SetUint64(1)
	expected[3].SetUint64(1)
	for i := 0; i < T; i++ {
		if !state[i].Equal(&expected[i]) {
			t.Errorf("[1,0,0,0] state[%d]: got %s, expected %s", i, state[i].String(), expected[i].String())
		}
	}

	// Test with [0,1,2,3]:
	// Row 0: 5*0 + 7*1 + 1*2 + 3*3 = 18
	// Row 1: 4*0 + 6*1 + 1*2 + 1*3 = 11
	// Row 2: 1*0 + 3*1 + 5*2 + 7*3 = 34
	// Row 3: 1*0 + 1*1 + 4*2 + 6*3 = 27
	state[0].SetUint64(0)
	state[1].SetUint64(1)
	state[2].SetUint64(2)
	state[3].SetUint64(3)
	matMulExternal(&state)

	expected[0].SetUint64(18)
	expected[1].SetUint64(11)
	expected[2].SetUint64(34)
	expected[3].SetUint64(27)
	for i := 0; i < T; i++ {
		if !state[i].Equal(&expected[i]) {
			t.Errorf("[0,1,2,3] state[%d]: got %s, expected %s", i, state[i].String(), expected[i].String())
		}
	}
}

func TestDebugRoundConstants(t *testing.T) {
	// Print first few round constants to verify
	fmt.Println("=== Round Constants (first 2 rounds) ===")
	for r := 0; r < 2; r++ {
		fmt.Printf("Round %d:\n", r)
		for j := 0; j < T; j++ {
			b := roundConstants[r][j].Bytes()
			fmt.Printf("  [%d] = 0x%x\n", j, b)
		}
	}

	// Print internal diagonal
	fmt.Println("\n=== Internal Diagonal (D-1) ===")
	for i := 0; i < T; i++ {
		b := internalDiagM1[i].Bytes()
		fmt.Printf("  [%d] = 0x%x\n", i, b)
	}
}

func TestDebugSBox(t *testing.T) {
	// Verify x^5 for small values
	tests := []struct {
		input    uint64
		expected uint64
	}{
		{0, 0},
		{1, 1},
		{2, 32},
		{3, 243},
	}
	for _, tt := range tests {
		var x fr.Element
		x.SetUint64(tt.input)
		sBoxSingle(&x)
		var exp fr.Element
		exp.SetUint64(tt.expected)
		if !x.Equal(&exp) {
			fmt.Printf("sbox(%d): got %s, expected %d\n", tt.input, x.String(), tt.expected)
		} else {
			fmt.Printf("sbox(%d) = %d ✓\n", tt.input, tt.expected)
		}
	}
}
