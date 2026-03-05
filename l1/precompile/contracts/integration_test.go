// Package contracts_test provides encoding compatibility tests that validate
// the bytes sent by Solidity contracts match what Go precompile handlers expect.
//
// These tests run as standard Go tests (no AvalancheGo node required) and
// catch ABI encoding mismatches between contracts/ and l1/precompile/.
//
// FINDINGS (Sprint 2, Task 6.5):
//
//   Coordinator.submitProof → VerifyUltraHonk:
//     1. Missing 4-byte function selector (abi.encode instead of abi.encodeWithSelector)
//     2. Sends bytes32 vkHash but precompile expects bytes vk (full verification key)
//     3. Sends bytes publicInputs but precompile expects bytes32[] publicInputs
//
//   ProofRegistry.registerProof → MerkleTreeInsert:
//     1. Missing 4-byte function selector
//     2. Uses staticcall but precompile rejects readOnly=true (insert mutates state)
//
//   ProofRegistry.isVerified → MerkleTreeVerify:
//     1. Missing 4-byte function selector
//     (Data layout is correct — 1152 bytes matches ABI encoding for all-static types)
package contracts_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/sincerin/l1/precompile/contracts/merkletreeinsert"
	"github.com/sincerin/l1/precompile/contracts/merkletreeverify"
	"github.com/sincerin/l1/precompile/contracts/verifyultrahonk"
	"github.com/stretchr/testify/require"
)

var (
	merkleInsertAddr = common.HexToAddress("0x0300000000000000000000000000000000000004")
	merkleVerifyAddr = common.HexToAddress("0x0300000000000000000000000000000000000005")
	ultraHonkAddr    = common.HexToAddress("0x0300000000000000000000000000000000000002")
	dummyCaller      = common.Address{}
)

func fixturesDir() string {
	// l1/precompile/contracts/ → ../../../fixtures/zk/evm/
	return filepath.Join("..", "..", "..", "fixtures", "zk", "evm")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesDir(), name))
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v", name, err)
	}
	return data
}

// ===========================================================================
// MerkleTreeInsert — Encoding Compatibility
// ===========================================================================

func TestSolidityEncodingCompat_MerkleInsert(t *testing.T) {
	t.Run("CorrectABI_WithSelector", func(t *testing.T) {
		merkletreeinsert.GlobalSMT.Reset()

		var proofHash, metadata [32]byte
		proofHash[31] = 0x01
		metadata[31] = 0x02

		// Correct encoding: selector + abi.encode(bytes32, bytes32)
		packed, err := merkletreeinsert.MerkleTreeInsertABI.Pack("insert", proofHash, metadata)
		require.NoError(t, err)
		t.Logf("Correct encoding: %d bytes (4 selector + 64 data)", len(packed))

		// Call through Run() with readOnly=false (simulates CALL, not STATICCALL)
		result, gas, err := merkletreeinsert.MerkleTreeInsertPrecompile.Run(
			nil, dummyCaller, merkleInsertAddr, packed, 10000, false,
		)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, uint64(10000-500), gas, "gas should deduct GasMerkleTreeInsert=500")

		// Verify output: (bytes32 newRoot, uint256 leafIndex)
		outputs, err := merkletreeinsert.MerkleTreeInsertABI.Unpack("insert", result)
		require.NoError(t, err)
		require.Len(t, outputs, 2)

		newRoot := outputs[0].([32]byte)
		leafIndex := outputs[1].(*big.Int)
		require.Equal(t, int64(0), leafIndex.Int64())
		require.NotEqual(t, [32]byte{}, newRoot)
		t.Logf("Insert OK: root=%x… leafIndex=%d", newRoot[:8], leafIndex)
	})

	t.Run("SolidityEncoding_NoSelector_Fails", func(t *testing.T) {
		merkletreeinsert.GlobalSMT.Reset()

		// Replicate ProofRegistry.registerProof():
		//   abi.encodePacked(leafHash, metadataHash) = 64 raw bytes, NO selector
		var leafHash, metadataHash [32]byte
		leafHash[31] = 0x01
		metadataHash[31] = 0x02
		solidityEncoding := append(leafHash[:], metadataHash[:]...)
		t.Logf("Solidity encoding: %d bytes (no selector)", len(solidityEncoding))

		// Run() will interpret first 4 bytes of leafHash as a selector → no match
		_, _, err := merkletreeinsert.MerkleTreeInsertPrecompile.Run(
			nil, dummyCaller, merkleInsertAddr, solidityEncoding, 10000, false,
		)
		require.Error(t, err, "abi.encodePacked without selector should fail")
		require.Contains(t, err.Error(), "invalid function selector")
		t.Logf("Expected error: %v", err)
	})

	t.Run("CorrectABI_StaticCall_ReadOnly_Fails", func(t *testing.T) {
		merkletreeinsert.GlobalSMT.Reset()

		var proofHash, metadata [32]byte
		proofHash[31] = 0x01
		metadata[31] = 0x02

		packed, err := merkletreeinsert.MerkleTreeInsertABI.Pack("insert", proofHash, metadata)
		require.NoError(t, err)

		// readOnly=true simulates STATICCALL (what ProofRegistry currently uses)
		// MerkleTreeInsert mutates state → rejects readOnly
		_, _, err = merkletreeinsert.MerkleTreeInsertPrecompile.Run(
			nil, dummyCaller, merkleInsertAddr, packed, 10000, true,
		)
		require.Error(t, err, "insert should fail in readOnly mode (staticcall)")
		require.Contains(t, err.Error(), "read-only")
		t.Logf("Expected error: %v", err)
	})
}

// ===========================================================================
// MerkleTreeVerify — Encoding Compatibility
// ===========================================================================

func TestSolidityEncodingCompat_MerkleVerify(t *testing.T) {
	t.Run("CorrectABI_WithSelector", func(t *testing.T) {
		merkletreeinsert.GlobalSMT.Reset()

		// Step 1: Insert a leaf to get valid tree state
		var proofHash, metadata [32]byte
		proofHash[31] = 0x01
		metadata[31] = 0x02

		insertPacked, err := merkletreeinsert.MerkleTreeInsertABI.Pack("insert", proofHash, metadata)
		require.NoError(t, err)

		insertResult, _, err := merkletreeinsert.MerkleTreeInsertPrecompile.Run(
			nil, dummyCaller, merkleInsertAddr, insertPacked, 10000, false,
		)
		require.NoError(t, err)

		insertOutputs, err := merkletreeinsert.MerkleTreeInsertABI.Unpack("insert", insertResult)
		require.NoError(t, err)
		rootBytes := insertOutputs[0].([32]byte)
		leafIndex := insertOutputs[1].(*big.Int)

		// Step 2: Get Merkle proof from tree
		proof, err := merkletreeinsert.GlobalSMT.GetProof(leafIndex.Uint64())
		require.NoError(t, err)

		// Convert [32]fr.Element → [32][32]byte
		var proofArr [32][32]byte
		for i := 0; i < 32; i++ {
			b := proof[i].Bytes()
			copy(proofArr[i][:], b[:])
		}

		// Step 3: Verify with correct ABI encoding (selector included)
		verifyPacked, err := merkletreeverify.MerkleTreeVerifyABI.Pack(
			"verify", proofHash, metadata, leafIndex, proofArr, rootBytes,
		)
		require.NoError(t, err)
		t.Logf("Correct verify encoding: %d bytes (4 selector + %d data)", len(verifyPacked), len(verifyPacked)-4)

		result, gas, err := merkletreeverify.MerkleTreeVerifyPrecompile.Run(
			nil, dummyCaller, merkleVerifyAddr, verifyPacked, 10000, true,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(10000-300), gas, "gas should deduct GasMerkleTreeVerify=300")

		outputs, err := merkletreeverify.MerkleTreeVerifyABI.Unpack("verify", result)
		require.NoError(t, err)
		valid := outputs[0].(bool)
		require.True(t, valid, "Merkle proof should verify with correct ABI encoding")
	})

	t.Run("SolidityEncoding_1152Bytes_NoSelector_Fails", func(t *testing.T) {
		// Replicate ProofRegistry.isVerified() encoding:
		// 1152 bytes raw assembly, NO selector:
		//   [0x00-0x20):  leafHash      (32 bytes)
		//   [0x20-0x40):  metadataHash  (32 bytes)
		//   [0x40-0x60):  leafIndex     (32 bytes, uint256)
		//   [0x60-0x460): merkleProof   (32×32 = 1024 bytes)
		//   [0x460-0x480): root         (32 bytes)
		//
		// Note: the DATA LAYOUT matches ABI encoding for all-static types.
		// The ONLY issue is the missing 4-byte function selector.
		solidityInput := make([]byte, 1152)
		solidityInput[31] = 0x01  // leafHash
		solidityInput[63] = 0x02  // metadataHash
		solidityInput[1151] = 0x03 // root (rest is zero)
		t.Logf("Solidity encoding: %d bytes (no selector)", len(solidityInput))

		_, _, err := merkletreeverify.MerkleTreeVerifyPrecompile.Run(
			nil, dummyCaller, merkleVerifyAddr, solidityInput, 10000, true,
		)
		require.Error(t, err, "raw 1152-byte encoding (no selector) should fail")
		t.Logf("Expected error: %v", err)
	})
}

// ===========================================================================
// VerifyUltraHonk — Encoding Compatibility
// ===========================================================================

func TestSolidityEncodingCompat_VerifyUltraHonk(t *testing.T) {
	t.Run("CorrectABI_WithSelector_Membership", func(t *testing.T) {
		proofBytes := loadFixture(t, "membership_proof.bin")
		vkBytes := loadFixture(t, "membership_vk.bin")
		pubInputBytes := loadFixture(t, "membership_public_inputs.bin")

		// Convert raw bytes → [][32]byte (what the precompile ABI expects)
		count := len(pubInputBytes) / 32
		pubInputs := make([][32]byte, count)
		for i := 0; i < count; i++ {
			copy(pubInputs[i][:], pubInputBytes[i*32:(i+1)*32])
		}

		// Correct: selector + abi.encode(bytes proof, bytes vk, bytes32[] publicInputs)
		packed, err := verifyultrahonk.VerifyUltraHonkABI.Pack("verify", proofBytes, vkBytes, pubInputs)
		require.NoError(t, err)
		t.Logf("Correct encoding: %d bytes (proof=%d, vk=%d, pubInputs=%d×32)",
			len(packed), len(proofBytes), len(vkBytes), count)

		result, _, err := verifyultrahonk.VerifyUltraHonkPrecompile.Run(
			nil, dummyCaller, ultraHonkAddr, packed, 100000, true,
		)
		require.NoError(t, err)

		outputs, err := verifyultrahonk.VerifyUltraHonkABI.Unpack("verify", result)
		require.NoError(t, err)
		valid := outputs[0].(bool)
		require.True(t, valid, "membership proof should verify with correct ABI encoding")
	})

	t.Run("CorrectABI_WithSelector_Age", func(t *testing.T) {
		proofBytes := loadFixture(t, "age_proof.bin")
		vkBytes := loadFixture(t, "age_vk.bin")
		pubInputBytes := loadFixture(t, "age_public_inputs.bin")

		count := len(pubInputBytes) / 32
		pubInputs := make([][32]byte, count)
		for i := 0; i < count; i++ {
			copy(pubInputs[i][:], pubInputBytes[i*32:(i+1)*32])
		}

		packed, err := verifyultrahonk.VerifyUltraHonkABI.Pack("verify", proofBytes, vkBytes, pubInputs)
		require.NoError(t, err)

		result, _, err := verifyultrahonk.VerifyUltraHonkPrecompile.Run(
			nil, dummyCaller, ultraHonkAddr, packed, 100000, true,
		)
		require.NoError(t, err)

		outputs, err := verifyultrahonk.VerifyUltraHonkABI.Unpack("verify", result)
		require.NoError(t, err)
		valid := outputs[0].(bool)
		require.True(t, valid, "age proof should verify with correct ABI encoding")
	})

	t.Run("SolidityEncoding_WrongTypes_NoSelector_Fails", func(t *testing.T) {
		// Replicate what Coordinator.submitProof() sends:
		//
		//   verifyPrecompile.staticcall(abi.encode(proof, vkHash, publicInputs))
		//
		// where Solidity types are (bytes, bytes32, bytes) — but precompile
		// expects (bytes, bytes, bytes32[]).
		//
		// Issues:
		//   1. No function selector (abi.encode, not abi.encodeWithSelector)
		//   2. vkHash is bytes32 (32 bytes inline) — precompile expects bytes (dynamic)
		//   3. publicInputs is bytes (dynamic blob) — precompile expects bytes32[] (array)
		//
		// Manually construct abi.encode(bytes, bytes32, bytes):
		//   word 0: offset to proof   = 0x60
		//   word 1: vkHash            = inline bytes32
		//   word 2: offset to pubInputs = 0xa0
		//   word 3: proof length      = 3
		//   word 4: proof data        (padded)
		//   word 5: pubInputs length  = 2
		//   word 6: pubInputs data    (padded)

		encoded := make([]byte, 7*32) // 224 bytes

		// offset to proof data (3 words past head = 0x60)
		encoded[31] = 0x60

		// vkHash inline (word 1)
		encoded[32] = 0xFF // first byte of vkHash

		// offset to publicInputs data (5 words past start = 0xa0)
		encoded[95] = 0xa0

		// proof length = 3 (word 3)
		encoded[127] = 0x03
		// proof data
		encoded[128] = 0x01
		encoded[129] = 0x02
		encoded[130] = 0x03

		// publicInputs length = 2 (word 5)
		encoded[191] = 0x02
		// publicInputs data
		encoded[192] = 0x04
		encoded[193] = 0x05

		t.Logf("Solidity encoding abi.encode(bytes,bytes32,bytes): %d bytes, no selector", len(encoded))

		// First 4 bytes (0x00000000...) are not the verify selector → routing fails
		_, _, err := verifyultrahonk.VerifyUltraHonkPrecompile.Run(
			nil, dummyCaller, ultraHonkAddr, encoded, 100000, true,
		)
		require.Error(t, err, "Coordinator's current encoding should fail at selector routing")
		t.Logf("Expected error: %v", err)
	})

	t.Run("CorrectSelector_ButWrongTypes_Fails", func(t *testing.T) {
		// Even with the correct selector, sending bytes32 where bytes is expected
		// will produce different ABI offset layout → UnpackInput fails.
		//
		// This demonstrates that fixing JUST the selector is insufficient;
		// the Coordinator must also send full VK bytes (not hash) and
		// bytes32[] publicInputs (not raw bytes).

		// Get the verify method selector
		verifyMethod := verifyultrahonk.VerifyUltraHonkABI.Methods["verify"]
		selector := verifyMethod.ID

		// Build "correct selector + wrong body" — abi.encode(bytes32) where bytes is expected
		// The UnpackInput will try to read dynamic offsets but find static data
		wrongBody := make([]byte, 3*32) // minimal wrong encoding
		wrongBody[31] = 0x20            // would-be offset, but wrong structure

		input := append(selector, wrongBody...)

		_, _, err := verifyultrahonk.VerifyUltraHonkPrecompile.Run(
			nil, dummyCaller, ultraHonkAddr, input, 100000, true,
		)
		require.Error(t, err, "correct selector + wrong ABI types should fail unpacking")
		t.Logf("Expected error: %v", err)
	})
}

// ===========================================================================
// End-to-End: Insert + Verify through Run() — validates the full flow
// ===========================================================================

func TestSolidityEncodingCompat_InsertThenVerify_E2E(t *testing.T) {
	merkletreeinsert.GlobalSMT.Reset()

	// Insert 5 leaves through Run()
	type insertedLeaf struct {
		proofHash [32]byte
		metadata  [32]byte
		root      [32]byte
		leafIndex *big.Int
	}
	leaves := make([]insertedLeaf, 5)

	for i := 0; i < 5; i++ {
		var ph, md [32]byte
		ph[31] = byte(i + 1)
		md[31] = byte(i + 100)

		packed, err := merkletreeinsert.MerkleTreeInsertABI.Pack("insert", ph, md)
		require.NoError(t, err)

		result, _, err := merkletreeinsert.MerkleTreeInsertPrecompile.Run(
			nil, dummyCaller, merkleInsertAddr, packed, 10000, false,
		)
		require.NoError(t, err)

		outputs, err := merkletreeinsert.MerkleTreeInsertABI.Unpack("insert", result)
		require.NoError(t, err)

		leaves[i] = insertedLeaf{
			proofHash: ph,
			metadata:  md,
			root:      outputs[0].([32]byte),
			leafIndex: outputs[1].(*big.Int),
		}
		require.Equal(t, int64(i), leaves[i].leafIndex.Int64())
	}

	// Verify each leaf with the final root
	finalRoot := leaves[4].root
	for i := 0; i < 5; i++ {
		proof, err := merkletreeinsert.GlobalSMT.GetProof(uint64(i))
		require.NoError(t, err)

		var proofArr [32][32]byte
		for j := 0; j < 32; j++ {
			b := proof[j].Bytes()
			copy(proofArr[j][:], b[:])
		}

		verifyPacked, err := merkletreeverify.MerkleTreeVerifyABI.Pack(
			"verify",
			leaves[i].proofHash,
			leaves[i].metadata,
			leaves[i].leafIndex,
			proofArr,
			finalRoot,
		)
		require.NoError(t, err)

		result, _, err := merkletreeverify.MerkleTreeVerifyPrecompile.Run(
			nil, dummyCaller, merkleVerifyAddr, verifyPacked, 10000, true,
		)
		require.NoError(t, err)

		outputs, err := merkletreeverify.MerkleTreeVerifyABI.Unpack("verify", result)
		require.NoError(t, err)
		valid := outputs[0].(bool)
		require.True(t, valid, "leaf %d should verify against final root", i)
	}
	t.Logf("All 5 leaves verified successfully through Run() with correct ABI encoding")
}
