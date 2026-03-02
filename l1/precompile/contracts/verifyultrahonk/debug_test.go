package verifyultrahonk

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

func TestDebugVKHash(t *testing.T) {
	vkBytes, err := os.ReadFile(filepath.Join(fixturesDir(), "membership_vk.bin"))
	if err != nil {
		t.Fatal(err)
	}

	expected := "2659af28b6355329868d579300d44a884fef3e3e52e3b90acb82fc2c9e2e2043"

	// Approach 1: keccak256 of raw binary VK
	h := sha3.NewLegacyKeccak256()
	h.Write(vkBytes)
	rawHash := h.Sum(nil)
	hash := hex.EncodeToString(rawHash)
	t.Logf("keccak256(raw vk binary):          0x%s  match=%v", hash, hash == expected)

	// Approach 1b: same but reduced modulo BN254 scalar field (fr.Element)
	var frHash fr.Element
	frHash.SetBytes(rawHash)
	frHashHex := hex.EncodeToString(frHash.Marshal())
	t.Logf("keccak256(raw vk) mod r:           0x%s  match=%v", frHashHex, frHashHex == expected)

	// Approach 2: keccak256 of Solidity-struct-format VK (circuitSize first, struct G1 order)
	// Solidity struct: circuitSize, logCircuitSize, publicInputsSize, then 28 G1 in struct order
	// Struct order: qm, qc, ql, qr, qo, q4, qLookup, qArith, qDeltaRange, qMemory, qNnf, qElliptic, ...
	// Binary order: qm, qc, ql, qr, qo, q4, qLookup, qArith, qDeltaRange, qElliptic, qMemory, qNnf, ...
	{
		solVK := make([]byte, 1888)

		// Metadata: circuitSize, logCircuitSize, publicInputsSize
		logN := binary.BigEndian.Uint64(vkBytes[24:32])
		pubInputsSize := binary.BigEndian.Uint64(vkBytes[56:64])

		// circuitSize = 1 << logN
		circuitSize := uint64(1) << logN
		binary.BigEndian.PutUint64(solVK[24:32], circuitSize)
		binary.BigEndian.PutUint64(solVK[56:64], logN)
		binary.BigEndian.PutUint64(solVK[88:96], pubInputsSize)

		// Copy G1 points, swapping positions 9,10,11
		// Binary: [0-8 same] [9=qElliptic] [10=qMemory] [11=qNnf] [12+ same]
		// Struct: [0-8 same] [9=qMemory] [10=qNnf] [11=qElliptic] [12+ same]
		g1Start := 96
		// Copy first 9 points as-is (0-8: qm through qDeltaRange)
		copy(solVK[g1Start:g1Start+9*64], vkBytes[g1Start:g1Start+9*64])

		// Swap: struct[9]=qMemory=binary[10], struct[10]=qNnf=binary[11], struct[11]=qElliptic=binary[9]
		copy(solVK[g1Start+9*64:g1Start+10*64], vkBytes[g1Start+10*64:g1Start+11*64])  // qMemory
		copy(solVK[g1Start+10*64:g1Start+11*64], vkBytes[g1Start+11*64:g1Start+12*64]) // qNnf
		copy(solVK[g1Start+11*64:g1Start+12*64], vkBytes[g1Start+9*64:g1Start+10*64])  // qElliptic

		// Copy remaining points as-is (12+: qPoseidon2Ext through lagrangeLast)
		copy(solVK[g1Start+12*64:], vkBytes[g1Start+12*64:])

		h2 := sha3.NewLegacyKeccak256()
		h2.Write(solVK)
		hash2 := hex.EncodeToString(h2.Sum(nil))
		t.Logf("keccak256(struct-format VK):        0x%s  match=%v", hash2, hash2 == expected)
	}

	// Approach 3: keccak256 of only the G1 points (without metadata)
	{
		h3 := sha3.NewLegacyKeccak256()
		h3.Write(vkBytes[96:]) // skip 3*32 metadata
		hash3 := hex.EncodeToString(h3.Sum(nil))
		t.Logf("keccak256(G1 points only):         0x%s  match=%v", hash3, hash3 == expected)
	}

	// Approach 4: keccak256 of VK with circuitSize prepended (keep binary G1 order)
	{
		logN := binary.BigEndian.Uint64(vkBytes[24:32])
		pubInputsSize := binary.BigEndian.Uint64(vkBytes[56:64])
		circuitSize := uint64(1) << logN

		buf := make([]byte, 1888)
		binary.BigEndian.PutUint64(buf[24:32], circuitSize)
		binary.BigEndian.PutUint64(buf[56:64], logN)
		binary.BigEndian.PutUint64(buf[88:96], pubInputsSize)
		copy(buf[96:], vkBytes[96:]) // G1 points in binary (WIRE) order

		h4 := sha3.NewLegacyKeccak256()
		h4.Write(buf)
		hash4 := hex.EncodeToString(h4.Sum(nil))
		t.Logf("keccak256(circuitSize+binary G1):  0x%s  match=%v", hash4, hash4 == expected)
	}

	// Approach 5: Maybe the bb tool computes VK_HASH from the native VK format, not the EVM format
	// Or perhaps VK_HASH is keccak256 of abi.encodePacked of specific elements
	// Let's also try keccak256 of the VK with full Solidity struct (abi.encode with G1 as (uint256,uint256))
	// which is the same as packed since all elements are 32 bytes

	// Approach 5: 4 metadata fields: circuitSize, logCircuitSize, publicInputsSize, pub_inputs_offset
	{
		logN := binary.BigEndian.Uint64(vkBytes[24:32])
		pubInputsSize := binary.BigEndian.Uint64(vkBytes[56:64])
		circuitSize := uint64(1) << logN

		buf := make([]byte, 4*32+28*64) // 4 metadata + 28 G1 points
		binary.BigEndian.PutUint64(buf[24:32], circuitSize)
		binary.BigEndian.PutUint64(buf[56:64], logN)
		binary.BigEndian.PutUint64(buf[88:96], pubInputsSize)
		binary.BigEndian.PutUint64(buf[120:128], 1) // pub_inputs_offset = 1
		copy(buf[128:], vkBytes[96:]) // G1 points in binary order

		h5 := sha3.NewLegacyKeccak256()
		h5.Write(buf)
		hash5 := hex.EncodeToString(h5.Sum(nil))
		t.Logf("keccak256(4meta + binary G1):       0x%s  match=%v", hash5, hash5 == expected)
	}

	// Approach 6: VK hash from the Solidity struct format with 4 metadata fields
	{
		logN := binary.BigEndian.Uint64(vkBytes[24:32])
		pubInputsSize := binary.BigEndian.Uint64(vkBytes[56:64])
		circuitSize := uint64(1) << logN

		buf := make([]byte, 4*32+28*64)
		binary.BigEndian.PutUint64(buf[24:32], circuitSize)
		binary.BigEndian.PutUint64(buf[56:64], logN)
		binary.BigEndian.PutUint64(buf[88:96], pubInputsSize)
		binary.BigEndian.PutUint64(buf[120:128], 1)
		// G1 points in struct declaration order (swap 9,10,11)
		copy(buf[128:128+9*64], vkBytes[96:96+9*64])
		copy(buf[128+9*64:128+10*64], vkBytes[96+10*64:96+11*64])  // qMemory
		copy(buf[128+10*64:128+11*64], vkBytes[96+11*64:96+12*64]) // qNnf
		copy(buf[128+11*64:128+12*64], vkBytes[96+9*64:96+10*64])  // qElliptic
		copy(buf[128+12*64:], vkBytes[96+12*64:])

		h6 := sha3.NewLegacyKeccak256()
		h6.Write(buf)
		hash6 := hex.EncodeToString(h6.Sum(nil))
		t.Logf("keccak256(4meta + struct G1):       0x%s  match=%v", hash6, hash6 == expected)
	}

	// Approach 7: Hash only G1 points in struct order (no metadata)
	{
		buf := make([]byte, 28*64)
		copy(buf[:9*64], vkBytes[96:96+9*64])
		copy(buf[9*64:10*64], vkBytes[96+10*64:96+11*64])  // qMemory
		copy(buf[10*64:11*64], vkBytes[96+11*64:96+12*64]) // qNnf
		copy(buf[11*64:12*64], vkBytes[96+9*64:96+10*64])  // qElliptic
		copy(buf[12*64:], vkBytes[96+12*64:])

		h7 := sha3.NewLegacyKeccak256()
		h7.Write(buf)
		hash7 := hex.EncodeToString(h7.Sum(nil))
		t.Logf("keccak256(struct G1 only):          0x%s  match=%v", hash7, hash7 == expected)
	}

	t.Logf("Expected:                          0x%s", expected)
}

func TestDebugShpleminiStepByStep(t *testing.T) {
	proofBytes := loadFixture(t, "membership_proof.bin")
	vkBytes := loadFixture(t, "membership_vk.bin")
	pubInputBytes := loadFixture(t, "membership_public_inputs.bin")
	pubInputs := parsePublicInputs(pubInputBytes)

	vk, err := DeserializeVK(vkBytes)
	if err != nil {
		t.Fatal(err)
	}
	logN := vk.LogCircuitSize

	proof, err := DeserializeProof(proofBytes, logN)
	if err != nil {
		t.Fatal(err)
	}

	// Compute VK hash
	kh := sha3.NewLegacyKeccak256()
	kh.Write(vkBytes)
	rawHash := kh.Sum(nil)
	var vkHashFr fr.Element
	vkHashFr.SetBytes(rawHash)
	var vkHash [32]byte
	copy(vkHash[:], vkHashFr.Marshal())

	tp := GenerateTranscript(proof, pubInputs, vkHash, vk.PublicInputsSize, logN)
	tp.RelationParams.PublicInputsDelta = computePublicInputDelta(
		pubInputs, proof.PairingPointObject[:], tp.RelationParams.Beta, tp.RelationParams.Gamma, 1,
	)

	// Step 1: Verify sumcheck passes
	if !verifySumcheck(proof, tp, logN) {
		t.Fatal("Sumcheck failed")
	}
	t.Log("Sumcheck PASSED")

	// Step 2: Test the MSM without recursion aggregation
	// Build the full MSM as in verifyShplemini, then check the raw pairing
	powersOfR := computeSquares(tp.GeminiR, logN)

	var posInvDenom, negInvDenom fr.Element
	{
		var tmp fr.Element
		tmp.Sub(&tp.ShplonkZ, &powersOfR[0])
		posInvDenom.Inverse(&tmp)
		tmp.Add(&tp.ShplonkZ, &powersOfR[0])
		negInvDenom.Inverse(&tmp)
	}

	var unshiftedScalar, shiftedScalar fr.Element
	{
		var tmp fr.Element
		tmp.Mul(&tp.ShplonkNu, &negInvDenom)
		unshiftedScalar.Add(&posInvDenom, &tmp)
	}
	{
		var rInv, tmp, diff fr.Element
		rInv.Inverse(&tp.GeminiR)
		tmp.Mul(&tp.ShplonkNu, &negInvDenom)
		diff.Sub(&posInvDenom, &tmp)
		shiftedScalar.Mul(&rInv, &diff)
	}

	t.Logf("unshiftedScalar: 0x%s", hex.EncodeToString(unshiftedScalar.Marshal()))
	t.Logf("shiftedScalar: 0x%s", hex.EncodeToString(shiftedScalar.Marshal()))

	// Build batched evaluation
	var batchingChallenge fr.Element
	batchingChallenge.SetOne()
	var batchedEvaluation fr.Element

	var unshiftedScalarNeg, shiftedScalarNeg fr.Element
	unshiftedScalarNeg.Neg(&unshiftedScalar)
	shiftedScalarNeg.Neg(&shiftedScalar)

	for i := 1; i <= int(NumberUnshiftedZK); i++ {
		var evalTerm fr.Element
		evalTerm.Mul(&proof.SumcheckEvaluations[i-NumMaskingPolynomials], &batchingChallenge)
		batchedEvaluation.Add(&batchedEvaluation, &evalTerm)
		batchingChallenge.Mul(&batchingChallenge, &tp.Rho)
	}

	for i := 0; i < NumberToBeShifted; i++ {
		evaluationOff := i + int(NumberUnshiftedZK)
		var evalTerm fr.Element
		evalTerm.Mul(&proof.SumcheckEvaluations[evaluationOff], &batchingChallenge)
		batchedEvaluation.Add(&batchedEvaluation, &evalTerm)
		batchingChallenge.Mul(&batchingChallenge, &tp.Rho)
	}

	t.Logf("batchedEvaluation: 0x%s", hex.EncodeToString(batchedEvaluation.Marshal()))

	// Compute fold position evaluations
	foldPosEvals := computeFoldPosEvaluations(
		tp.SumcheckU[:logN], batchedEvaluation,
		proof.GeminiAEvaluations, powersOfR, logN,
	)

	t.Logf("foldPosEvals[0]: 0x%s", hex.EncodeToString(foldPosEvals[0].Marshal()))
	if logN > 1 {
		t.Logf("foldPosEvals[1]: 0x%s", hex.EncodeToString(foldPosEvals[1].Marshal()))
	}

	// Compute constant term accumulator
	var constantTermAccumulator fr.Element
	{
		var t1, t2 fr.Element
		t1.Mul(&foldPosEvals[0], &posInvDenom)
		t2.Mul(&proof.GeminiAEvaluations[0], &tp.ShplonkNu)
		t2.Mul(&t2, &negInvDenom)
		constantTermAccumulator.Add(&t1, &t2)
	}

	t.Logf("constantTermAccumulator (initial): 0x%s", hex.EncodeToString(constantTermAccumulator.Marshal()))

	// Check if the pairing point object itself forms a valid pairing
	p0Other, p1Other := convertPairingPointsToG1(proof.PairingPointObject)
	pairingOK, _ := bn254.PairingCheck(
		[]bn254.G1Affine{p0Other, p1Other},
		[]bn254.G2Affine{srsG2, srsG2VK},
	)
	t.Logf("Pairing point object valid: %v", pairingOK)

	// Verify G2 generator matches Solidity
	_, _, _, g2Gen := bn254.Generators()
	t.Logf("G2 gen X.A0: 0x%s", hex.EncodeToString(g2Gen.X.A0.Marshal()))
	t.Logf("G2 gen X.A1: 0x%s", hex.EncodeToString(g2Gen.X.A1.Marshal()))
	t.Logf("G2 gen Y.A0: 0x%s", hex.EncodeToString(g2Gen.Y.A0.Marshal()))
	t.Logf("G2 gen Y.A1: 0x%s", hex.EncodeToString(g2Gen.Y.A1.Marshal()))

	// Verify SRS G2 VK point
	t.Logf("SRS G2 VK X.A0: 0x%s", hex.EncodeToString(srsG2VK.X.A0.Marshal()))
	t.Logf("SRS G2 VK X.A1: 0x%s", hex.EncodeToString(srsG2VK.X.A1.Marshal()))
	t.Logf("SRS G2 VK Y.A0: 0x%s", hex.EncodeToString(srsG2VK.Y.A0.Marshal()))
	t.Logf("SRS G2 VK Y.A1: 0x%s", hex.EncodeToString(srsG2VK.Y.A1.Marshal()))
	t.Logf("SRS G2 VK on curve: %v", srsG2VK.IsOnCurve())

	t.Log("Shplemini step-by-step debug complete")
}

func TestDebugShplemini(t *testing.T) {
	proofBytes := loadFixture(t, "membership_proof.bin")
	vkBytes := loadFixture(t, "membership_vk.bin")
	pubInputBytes := loadFixture(t, "membership_public_inputs.bin")
	pubInputs := parsePublicInputs(pubInputBytes)

	vk, err := DeserializeVK(vkBytes)
	if err != nil {
		t.Fatal(err)
	}
	logN := vk.LogCircuitSize

	proof, err := DeserializeProof(proofBytes, logN)
	if err != nil {
		t.Fatal(err)
	}

	// Compute VK hash
	h := sha3.NewLegacyKeccak256()
	h.Write(vkBytes)
	rawHash := h.Sum(nil)
	var vkHashFr fr.Element
	vkHashFr.SetBytes(rawHash)
	var vkHash [32]byte
	copy(vkHash[:], vkHashFr.Marshal())

	// Generate transcript
	tp := GenerateTranscript(proof, pubInputs, vkHash, vk.PublicInputsSize, logN)
	tp.RelationParams.PublicInputsDelta = computePublicInputDelta(
		pubInputs, proof.PairingPointObject[:], tp.RelationParams.Beta, tp.RelationParams.Gamma, 1,
	)

	t.Logf("shplonkZ: 0x%s", hex.EncodeToString(tp.ShplonkZ.Marshal()))
	t.Logf("shplonkNu: 0x%s", hex.EncodeToString(tp.ShplonkNu.Marshal()))
	t.Logf("geminiR: 0x%s", hex.EncodeToString(tp.GeminiR.Marshal()))
	t.Logf("rho: 0x%s", hex.EncodeToString(tp.Rho.Marshal()))

	// Check pairing point object reconstruction
	p0Other, p1Other := convertPairingPointsToG1(proof.PairingPointObject)
	t.Logf("P0_other.X: 0x%s", hex.EncodeToString(p0Other.X.Marshal()))
	t.Logf("P0_other.Y: 0x%s", hex.EncodeToString(p0Other.Y.Marshal()))
	t.Logf("P1_other.X: 0x%s", hex.EncodeToString(p1Other.X.Marshal()))
	t.Logf("P1_other.Y: 0x%s", hex.EncodeToString(p1Other.Y.Marshal()))

	// Check if P0_other and P1_other are on the curve
	t.Logf("P0_other on curve: %v", p0Other.IsOnCurve())
	t.Logf("P1_other on curve: %v", p1Other.IsOnCurve())

	// Print first few sumcheck evaluations
	t.Logf("SumcheckEval[0] (masking): 0x%s", hex.EncodeToString(proof.SumcheckEvaluations[0].Marshal()))
	t.Logf("SumcheckEval[1] (qm):      0x%s", hex.EncodeToString(proof.SumcheckEvaluations[1].Marshal()))

	// Print gemini A evaluations
	t.Logf("GeminiAEval[0]: 0x%s", hex.EncodeToString(proof.GeminiAEvaluations[0].Marshal()))

	// Print libra poly evals
	for i := 0; i < 4; i++ {
		t.Logf("LibraPolyEval[%d]: 0x%s", i, hex.EncodeToString(proof.LibraPolyEvals[i].Marshal()))
	}
}

func TestDebugTranscript(t *testing.T) {
	proofBytes := loadFixture(t, "membership_proof.bin")
	vkBytes := loadFixture(t, "membership_vk.bin")
	pubInputBytes := loadFixture(t, "membership_public_inputs.bin")
	pubInputs := parsePublicInputs(pubInputBytes)

	vk, err := DeserializeVK(vkBytes)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := DeserializeProof(proofBytes, vk.LogCircuitSize)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("LogN: %d, PublicInputsSize: %d, UserInputs: %d", vk.LogCircuitSize, vk.PublicInputsSize, len(pubInputs))

	// Compute VK hash using keccak256 of raw binary
	h := sha3.NewLegacyKeccak256()
	h.Write(vkBytes)
	var vkHash [32]byte
	h.Sum(vkHash[:0])
	t.Logf("vkHash: 0x%s", hex.EncodeToString(vkHash[:]))

	// Also try with the Solidity VK_HASH constant directly
	solVKHash, _ := hex.DecodeString("2659af28b6355329868d579300d44a884fef3e3e52e3b90acb82fc2c9e2e2043")
	var solVKHash32 [32]byte
	copy(solVKHash32[:], solVKHash)

	// Generate transcript with Solidity VK_HASH
	tp := GenerateTranscript(proof, pubInputs, solVKHash32, vk.PublicInputsSize, vk.LogCircuitSize)

	t.Logf("Using Solidity VK_HASH constant:")
	t.Logf("  eta:    0x%s", hex.EncodeToString(tp.RelationParams.Eta.Marshal()))
	t.Logf("  etaTwo: 0x%s", hex.EncodeToString(tp.RelationParams.EtaTwo.Marshal()))
	t.Logf("  beta:   0x%s", hex.EncodeToString(tp.RelationParams.Beta.Marshal()))
	t.Logf("  gamma:  0x%s", hex.EncodeToString(tp.RelationParams.Gamma.Marshal()))
	t.Logf("  libraChallenge: 0x%s", hex.EncodeToString(tp.LibraChallenge.Marshal()))

	// Check round 0: u[0] + u[1] should equal libraChallenge * libraSum
	var roundTargetSum0 = tp.LibraChallenge
	roundTargetSum0.Mul(&roundTargetSum0, &proof.LibraSum)
	t.Logf("  roundTargetSum0 (libra*libraSum): 0x%s", hex.EncodeToString(roundTargetSum0.Marshal()))

	var sumU0U1 = proof.SumcheckUnivariates[0][0]
	sumU0U1.Add(&sumU0U1, &proof.SumcheckUnivariates[0][1])
	t.Logf("  sumcheck_uni[0]+[1]:              0x%s", hex.EncodeToString(sumU0U1.Marshal()))
	t.Logf("  Match: %v", sumU0U1.Equal(&roundTargetSum0))

	// Even if the transcript is correct, we need the VK hash to be correct
	_ = fmt.Sprintf("")
}
