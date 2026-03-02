package verifyultrahonk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// fixturesDir returns the path to the EVM fixtures directory.
func fixturesDir() string {
	// Walk up from the test file to find the fixtures directory
	// l1/precompile/contracts/verifyultrahonk/ → ../../../../fixtures/zk/evm/
	return filepath.Join("..", "..", "..", "..", "fixtures", "zk", "evm")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesDir(), name))
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v", name, err)
	}
	return data
}

// parsePublicInputs converts raw 32-byte chunks into fr.Element slice.
func parsePublicInputs(data []byte) []fr.Element {
	count := len(data) / 32
	inputs := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		inputs[i].SetBytes(data[i*32 : (i+1)*32])
	}
	return inputs
}

// ---------------------------------------------------------------------------
// Deserialization tests
// ---------------------------------------------------------------------------

func TestDeserializeVK_Membership(t *testing.T) {
	vkBytes := loadFixture(t, "membership_vk.bin")

	vk, err := DeserializeVK(vkBytes)
	if err != nil {
		t.Fatalf("DeserializeVK: %v", err)
	}

	// Verify metadata
	if vk.LogCircuitSize != 14 {
		t.Errorf("LogCircuitSize = %d, want 14", vk.LogCircuitSize)
	}
	if vk.CircuitSize != 16384 {
		t.Errorf("CircuitSize = %d, want 16384", vk.CircuitSize)
	}
	if vk.PublicInputsSize != 18 {
		t.Errorf("PublicInputsSize = %d, want 18", vk.PublicInputsSize)
	}
	if vk.PubInputsOffset != 1 {
		t.Errorf("PubInputsOffset = %d, want 1", vk.PubInputsOffset)
	}

	// Verify first G1 point (qm) matches Solidity constant
	qmX := vk.Qm.X.String()
	expectedQmX := "2920708003160395718446916416039068494284364743050264990408199495163050480283"
	if qmX != expectedQmX {
		t.Errorf("Qm.X = %s, want %s", qmX, expectedQmX)
	}

	// Verify lagrangeFirst is the BN254 generator (1, 2)
	var expectedX, expectedY fr.Element
	expectedX.SetOne()
	expectedY.SetUint64(2)
	lfX := vk.LagrangeFirst.X.String()
	lfY := vk.LagrangeFirst.Y.String()
	if lfX != "1" {
		t.Errorf("LagrangeFirst.X = %s, want 1", lfX)
	}
	if lfY != "2" {
		t.Errorf("LagrangeFirst.Y = %s, want 2", lfY)
	}

	// Verify VKCommitments returns 28 points
	comms := vk.VKCommitments()
	if len(comms) != 28 {
		t.Errorf("VKCommitments length = %d, want 28", len(comms))
	}
}

func TestDeserializeVK_Age(t *testing.T) {
	vkBytes := loadFixture(t, "age_vk.bin")

	vk, err := DeserializeVK(vkBytes)
	if err != nil {
		t.Fatalf("DeserializeVK: %v", err)
	}

	if vk.LogCircuitSize != 16 {
		t.Errorf("LogCircuitSize = %d, want 16", vk.LogCircuitSize)
	}
	if vk.CircuitSize != 65536 {
		t.Errorf("CircuitSize = %d, want 65536", vk.CircuitSize)
	}
}

func TestDeserializeProof_Membership(t *testing.T) {
	proofBytes := loadFixture(t, "membership_proof.bin")

	proof, err := DeserializeProof(proofBytes, 14)
	if err != nil {
		t.Fatalf("DeserializeProof: %v", err)
	}

	// Check basic structure
	if len(proof.SumcheckUnivariates) != 14 {
		t.Errorf("SumcheckUnivariates length = %d, want 14", len(proof.SumcheckUnivariates))
	}
	for i, u := range proof.SumcheckUnivariates {
		if len(u) != ZKBatchedRelationPartialLen {
			t.Errorf("SumcheckUnivariates[%d] length = %d, want %d", i, len(u), ZKBatchedRelationPartialLen)
		}
	}

	if len(proof.GeminiFoldComms) != 13 {
		t.Errorf("GeminiFoldComms length = %d, want 13", len(proof.GeminiFoldComms))
	}
	if len(proof.GeminiAEvaluations) != 14 {
		t.Errorf("GeminiAEvaluations length = %d, want 14", len(proof.GeminiAEvaluations))
	}

	// Verify W1 is a valid non-zero point
	if proof.W1.X.IsZero() && proof.W1.Y.IsZero() {
		t.Error("W1 is the zero point, expected a non-trivial commitment")
	}
}

func TestDeserializeProof_Age(t *testing.T) {
	proofBytes := loadFixture(t, "age_proof.bin")

	proof, err := DeserializeProof(proofBytes, 16)
	if err != nil {
		t.Fatalf("DeserializeProof: %v", err)
	}

	if len(proof.SumcheckUnivariates) != 16 {
		t.Errorf("SumcheckUnivariates length = %d, want 16", len(proof.SumcheckUnivariates))
	}
	if len(proof.GeminiFoldComms) != 15 {
		t.Errorf("GeminiFoldComms length = %d, want 15", len(proof.GeminiFoldComms))
	}
	if len(proof.GeminiAEvaluations) != 16 {
		t.Errorf("GeminiAEvaluations length = %d, want 16", len(proof.GeminiAEvaluations))
	}
}

// ---------------------------------------------------------------------------
// Full verification tests
// ---------------------------------------------------------------------------

func TestVerify_Membership(t *testing.T) {
	proofBytes := loadFixture(t, "membership_proof.bin")
	vkBytes := loadFixture(t, "membership_vk.bin")
	pubInputBytes := loadFixture(t, "membership_public_inputs.bin")
	pubInputs := parsePublicInputs(pubInputBytes)

	t.Logf("Proof size: %d bytes", len(proofBytes))
	t.Logf("VK size: %d bytes", len(vkBytes))
	t.Logf("Public inputs: %d elements", len(pubInputs))

	valid, err := Verify(proofBytes, vkBytes, pubInputs)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !valid {
		t.Fatal("Verify returned false for valid membership proof")
	}
}

func TestVerify_Age(t *testing.T) {
	proofBytes := loadFixture(t, "age_proof.bin")
	vkBytes := loadFixture(t, "age_vk.bin")
	pubInputBytes := loadFixture(t, "age_public_inputs.bin")
	pubInputs := parsePublicInputs(pubInputBytes)

	t.Logf("Proof size: %d bytes", len(proofBytes))
	t.Logf("VK size: %d bytes", len(vkBytes))
	t.Logf("Public inputs: %d elements", len(pubInputs))

	valid, err := Verify(proofBytes, vkBytes, pubInputs)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !valid {
		t.Fatal("Verify returned false for valid age proof")
	}
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestDeserializeVK_InvalidSize(t *testing.T) {
	_, err := DeserializeVK(make([]byte, 100))
	if err == nil {
		t.Error("expected error for invalid VK size")
	}
}

func TestDeserializeProof_TooShort(t *testing.T) {
	_, err := DeserializeProof(make([]byte, 100), 14)
	if err == nil {
		t.Error("expected error for too-short proof")
	}
}

func TestVerify_WrongPublicInputs(t *testing.T) {
	proofBytes := loadFixture(t, "membership_proof.bin")
	vkBytes := loadFixture(t, "membership_vk.bin")

	// Wrong number of public inputs
	_, err := Verify(proofBytes, vkBytes, nil)
	if err == nil {
		t.Error("expected error for nil public inputs")
	}
}
