package benchmark

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ava-labs/libevm/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
	"github.com/sincerin/l1/crypto/smt"
	"github.com/sincerin/l1/params"
	"github.com/sincerin/l1/precompile/contracts/merkletreeinsert"
	"github.com/sincerin/l1/precompile/contracts/merkletreeverify"
	"github.com/sincerin/l1/precompile/contracts/poseidonhash"

	_ "github.com/sincerin/l1/precompile/registry"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	params.RegisterExtras()
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func frToBytes32(e fr.Element) [32]byte {
	b := e.Bytes()
	var result [32]byte
	copy(result[:], b[:])
	return result
}

func makePoseidonHashInput(inputs [][32]byte) []byte {
	input, err := poseidonhash.PoseidonHashABI.Pack("hash", inputs)
	if err != nil {
		panic(err)
	}
	return input // keep selector — Run() expects full calldata
}

func makeMerkleInsertInput(proofHash, metadata [32]byte) []byte {
	input, err := merkletreeinsert.MerkleTreeInsertABI.Pack("insert", proofHash, metadata)
	if err != nil {
		panic(err)
	}
	return input
}

func makeMerkleVerifyInput(proofHash, metadata [32]byte, leafIndex uint64, proof [smt.TreeDepth]fr.Element, root fr.Element) []byte {
	var proofArr [32][32]byte
	for i := 0; i < smt.TreeDepth; i++ {
		proofArr[i] = frToBytes32(proof[i])
	}
	rootArr := frToBytes32(root)
	input, err := merkletreeverify.MerkleTreeVerifyABI.Pack("verify",
		proofHash, metadata,
		new(big.Int).SetUint64(leafIndex),
		proofArr, rootArr,
	)
	if err != nil {
		panic(err)
	}
	return input // keep selector — Run() expects full calldata
}

// ---------------------------------------------------------------------------
// Correctness: Yul bytecode produces same hash as Go implementation
// ---------------------------------------------------------------------------

func TestPoseidon2Yul_MatchesGoImpl(t *testing.T) {
	require.True(t, len(poseidon2YulBytecode) > 0, "Yul bytecode should be loaded")

	statedb := NewEVMState()

	// hash_2(1, 2)
	calldata := EncodeHash2Calldata(big.NewInt(1), big.NewInt(2))
	result := RunPoseidon2InEVM(statedb, calldata, 1_000_000)
	require.NoError(t, result.Err, "EVM execution should succeed")
	require.Len(t, result.Output, 32, "output should be 32 bytes")

	// Compare with Go implementation
	var a, b fr.Element
	a.SetUint64(1)
	b.SetUint64(2)
	expected := poseidon2.Hash2(a, b)
	expectedBytes := frToBytes32(expected)

	var evmResult [32]byte
	copy(evmResult[:], result.Output)
	require.Equal(t, expectedBytes, evmResult, "Yul and Go Poseidon2 should produce identical results")

	t.Logf("Poseidon2 hash_2(1,2) = 0x%x", result.Output)
	t.Logf("EVM gas used: %d", result.GasUsed)
	t.Logf("EVM wall-clock: %v", result.WallClock)
}

func TestPoseidon2Yul_MultipleVectors(t *testing.T) {
	statedb := NewEVMState()

	tests := []struct {
		a, b uint64
	}{
		{0, 0},
		{1, 1},
		{42, 99},
		{0x1234, 0x5678},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("hash_2(%d,%d)", tt.a, tt.b), func(t *testing.T) {
			calldata := EncodeHash2Calldata(new(big.Int).SetUint64(tt.a), new(big.Int).SetUint64(tt.b))
			result := RunPoseidon2InEVM(statedb, calldata, 1_000_000)
			require.NoError(t, result.Err)

			var aFr, bFr fr.Element
			aFr.SetUint64(tt.a)
			bFr.SetUint64(tt.b)
			expected := poseidon2.Hash2(aFr, bFr)
			expectedBytes := frToBytes32(expected)

			var evmResult [32]byte
			copy(evmResult[:], result.Output)
			require.Equal(t, expectedBytes, evmResult)
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmarks: Precompile (native Go) side
// ---------------------------------------------------------------------------

func BenchmarkPrecompile_PoseidonHash2(b *testing.B) {
	var aFr, bFr fr.Element
	aFr.SetUint64(1)
	bFr.SetUint64(2)
	inputs := [][32]byte{frToBytes32(aFr), frToBytes32(bFr)}
	input := makePoseidonHashInput(inputs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poseidonhash.PoseidonHashPrecompile.Run(nil, common.Address{}, poseidonhash.ContractAddress, input, 10_000, false)
	}
}

func BenchmarkPrecompile_MerkleInsert(b *testing.B) {
	merkletreeinsert.GlobalSMT.Reset()
	var proofHash, metadata [32]byte
	proofHash[31] = 42
	input := makeMerkleInsertInput(proofHash, metadata)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merkletreeinsert.MerkleTreeInsertPrecompile.Run(nil, common.Address{}, merkletreeinsert.ContractAddress, input, 10_000, false)
	}
}

func BenchmarkPrecompile_MerkleVerify(b *testing.B) {
	// Setup: build tree with 1000 leaves and get a proof
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
	input := makeMerkleVerifyInput(phBytes, phBytes, 500, proof, tree.Root())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merkletreeverify.MerkleTreeVerifyPrecompile.Run(nil, common.Address{}, merkletreeverify.ContractAddress, input, 10_000, false)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks: EVM interpreter side (Poseidon2 Yul bytecode)
// ---------------------------------------------------------------------------

func BenchmarkEVM_PoseidonHash2_Yul(b *testing.B) {
	statedb := NewEVMState()
	calldata := EncodeHash2Calldata(big.NewInt(1), big.NewInt(2))

	// Warm up: first call has cold account access cost
	RunPoseidon2InEVM(statedb, calldata, 1_000_000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RunPoseidon2InEVM(statedb, calldata, 1_000_000)
	}
}

// ---------------------------------------------------------------------------
// Comparison Table: all operations side by side
// ---------------------------------------------------------------------------

func TestComparisonTable(t *testing.T) {
	const iterations = 1000

	rows := []ComparisonRow{}

	// --- Poseidon2 hash_2: MEASURED ---
	{
		var aFr, bFr fr.Element
		aFr.SetUint64(1)
		bFr.SetUint64(2)
		inputs := [][32]byte{frToBytes32(aFr), frToBytes32(bFr)}
		precompileInput := makePoseidonHashInput(inputs)

		// Measure precompile
		start := time.Now()
		for i := 0; i < iterations; i++ {
			poseidonhash.PoseidonHashPrecompile.Run(nil, common.Address{}, poseidonhash.ContractAddress, precompileInput, 10_000, false)
		}
		precompileTotal := time.Since(start)
		precompileUs := float64(precompileTotal.Microseconds()) / float64(iterations)

		// Measure EVM Yul
		statedb := NewEVMState()
		calldata := EncodeHash2Calldata(big.NewInt(1), big.NewInt(2))
		// Warm up
		RunPoseidon2InEVM(statedb, calldata, 1_000_000)

		start = time.Now()
		var totalGas uint64
		for i := 0; i < iterations; i++ {
			r := RunPoseidon2InEVM(statedb, calldata, 1_000_000)
			totalGas += r.GasUsed
		}
		evmTotal := time.Since(start)
		evmUs := float64(evmTotal.Microseconds()) / float64(iterations)
		evmGas := totalGas / uint64(iterations)

		precompileGas := uint64(poseidonhash.GasPoseidonHashBase + poseidonhash.GasPoseidonHashPerExtra)
		rows = append(rows, ComparisonRow{
			Operation:     "Poseidon2 hash_2",
			PrecompileGas: precompileGas,
			PrecompileUs:  precompileUs,
			EVMGas:        evmGas,
			EVMUs:         evmUs,
			GasRatio:      float64(evmGas) / float64(precompileGas),
			SpeedRatio:    evmUs / precompileUs,
			Source:        "measured (Yul)",
		})
	}

	// --- MerkleTree Insert: LITERATURE + measured precompile ---
	{
		merkletreeinsert.GlobalSMT.Reset()
		var proofHash, metadata [32]byte
		proofHash[31] = 42
		input := makeMerkleInsertInput(proofHash, metadata)

		start := time.Now()
		for i := 0; i < iterations; i++ {
			merkletreeinsert.MerkleTreeInsertPrecompile.Run(nil, common.Address{}, merkletreeinsert.ContractAddress, input, 10_000, false)
		}
		precompileTotal := time.Since(start)
		precompileUs := float64(precompileTotal.Microseconds()) / float64(iterations)

		precompileGas := merkletreeinsert.GasMerkleTreeInsert
		rows = append(rows, ComparisonRow{
			Operation:     "MerkleTree Insert (d=32)",
			PrecompileGas: precompileGas,
			PrecompileUs:  precompileUs,
			EVMGas:        GasMerkleInsertEVM,
			EVMUs:         0, // estimated below
			GasRatio:      float64(GasMerkleInsertEVM) / float64(precompileGas),
			Source:        "literature",
		})
	}

	// --- MerkleTree Verify: LITERATURE + measured precompile ---
	{
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
		input := makeMerkleVerifyInput(phBytes, phBytes, 500, proof, tree.Root())

		start := time.Now()
		for i := 0; i < iterations; i++ {
			merkletreeverify.MerkleTreeVerifyPrecompile.Run(nil, common.Address{}, merkletreeverify.ContractAddress, input, 10_000, false)
		}
		precompileTotal := time.Since(start)
		precompileUs := float64(precompileTotal.Microseconds()) / float64(iterations)

		precompileGas := merkletreeverify.GasMerkleTreeVerify
		rows = append(rows, ComparisonRow{
			Operation:     "MerkleTree Verify (d=32)",
			PrecompileGas: precompileGas,
			PrecompileUs:  precompileUs,
			EVMGas:        GasMerkleVerifyEVM,
			EVMUs:         0, // estimated below
			GasRatio:      float64(GasMerkleVerifyEVM) / float64(precompileGas),
			Source:        "literature",
		})
	}

	// --- VerifyUltraHonk: LITERATURE ---
	{
		rows = append(rows, ComparisonRow{
			Operation:     "UltraHonk Verify",
			PrecompileGas: 20_000,
			PrecompileUs:  2500, // ~2.5ms from benchmarks
			EVMGas:        GasUltraHonkEVM,
			EVMUs:         UsUltraHonkEVM, // hardcoded — EC-heavy, can't extrapolate from Poseidon2
			GasRatio:      float64(GasUltraHonkEVM) / 20_000,
			SpeedRatio:    UsUltraHonkEVM / 2500,
			Source:        "literature",
		})
	}

	// Estimate EVM wall-clock for literature rows using the measured Poseidon2 ratio
	if len(rows) > 0 && rows[0].EVMUs > 0 && rows[0].PrecompileUs > 0 {
		// Use the measured gas-to-time ratio from Poseidon2 Yul
		usPerGas := rows[0].EVMUs / float64(rows[0].EVMGas)
		for i := 1; i < len(rows); i++ {
			if rows[i].EVMUs == 0 {
				rows[i].EVMUs = usPerGas * float64(rows[i].EVMGas)
				rows[i].SpeedRatio = rows[i].EVMUs / rows[i].PrecompileUs
			}
		}
	}

	// Print table
	t.Logf("")
	t.Logf("╔══════════════════════════════╦═══════════════╦═══════════════╦══════════╦═══════════════╦═══════════════╦════════════╦═════════════════╗")
	t.Logf("║ %-28s ║ %13s ║ %13s ║ %8s ║ %13s ║ %13s ║ %10s ║ %-15s ║", "Operation", "Precomp.Gas", "EVM Gas", "Gas Δ", "Precomp.Time", "EVM Time", "Speed Δ", "Source")
	t.Logf("╠══════════════════════════════╬═══════════════╬═══════════════╬══════════╬═══════════════╬═══════════════╬════════════╬═════════════════╣")
	for _, r := range rows {
		evmTimeStr := "N/A"
		speedStr := "N/A"
		if r.EVMUs > 0 {
			if r.EVMUs >= 1000 {
				evmTimeStr = fmt.Sprintf("%.1f ms", r.EVMUs/1000)
			} else {
				evmTimeStr = fmt.Sprintf("%.0f μs", r.EVMUs)
			}
		}
		if r.SpeedRatio > 0 {
			speedStr = fmt.Sprintf("%.0fx", r.SpeedRatio)
		}

		precompileTimeStr := ""
		if r.PrecompileUs >= 1000 {
			precompileTimeStr = fmt.Sprintf("%.1f ms", r.PrecompileUs/1000)
		} else {
			precompileTimeStr = fmt.Sprintf("%.0f μs", r.PrecompileUs)
		}

		t.Logf("║ %-28s ║ %13s ║ %13s ║ %7.0fx ║ %13s ║ %13s ║ %9s  ║ %-15s ║",
			r.Operation,
			fmt.Sprintf("%d", r.PrecompileGas),
			fmt.Sprintf("%d", r.EVMGas),
			r.GasRatio,
			precompileTimeStr,
			evmTimeStr,
			speedStr,
			r.Source,
		)
	}
	t.Logf("╚══════════════════════════════╩═══════════════╩═══════════════╩══════════╩═══════════════╩═══════════════╩════════════╩═════════════════╝")
	t.Logf("")
	t.Logf("Notes:")
	t.Logf("  - 'measured' = actually executed in the EVM interpreter (zemse/poseidon2-evm Yul bytecode)")
	t.Logf("  - 'literature' = gas from published benchmarks, wall-clock extrapolated from measured Poseidon2 ratio")
	t.Logf("  - Gas Δ = EVM Gas / Precompile Gas (higher = more savings)")
	t.Logf("  - Speed Δ = EVM Time / Precompile Time (higher = faster native execution)")
	t.Logf("  - Poseidon2 Yul gas (20,304): github.com/zemse/poseidon2-evm")
	t.Logf("  - UltraHonk EVM (~500K): estimated from UltraPlonk ~550K (Aztec benchmarks)")
	t.Logf("  - Groth16 reference: ~200K gas (Ethereum ecPairing precompile)")
}
