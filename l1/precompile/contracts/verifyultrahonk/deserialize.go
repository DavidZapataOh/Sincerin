package verifyultrahonk

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// DeserializeVK parses a verification key from EVM-format bytes (1888 bytes).
// Layout: 3 × 32-byte metadata + 28 × 64-byte G1 affine points.
func DeserializeVK(data []byte) (*VerificationKey, error) {
	const vkSize = 3*FieldElementSize + 28*GroupElementSize // 96 + 1792 = 1888
	if len(data) != vkSize {
		return nil, fmt.Errorf("invalid VK size: got %d, want %d", len(data), vkSize)
	}

	vk := &VerificationKey{}
	off := 0

	// Metadata: 3 uint256 fields (big-endian, values fit in uint64)
	// Binary order: logCircuitSize, publicInputsSize, pub_inputs_offset
	vk.LogCircuitSize = readUint256AsUint64(data[off : off+32])
	off += 32
	vk.PublicInputsSize = readUint256AsUint64(data[off : off+32])
	off += 32
	vk.PubInputsOffset = readUint256AsUint64(data[off : off+32])
	off += 32

	// Derive circuitSize from logCircuitSize
	vk.CircuitSize = 1 << vk.LogCircuitSize

	// 28 G1 affine points (standard format: 32 bytes x + 32 bytes y, big-endian)
	// Order matches the WIRE enum / C++ serialization order (verified against binary hex dump):
	// Qm, Qc, Ql, Qr, Qo, Q4, QLookup, QArith, QDeltaRange, QElliptic,
	// QMemory, QNnf, QPoseidon2External, QPoseidon2Internal,
	// S1-S4, ID1-ID4, T1-T4, LagrangeFirst, LagrangeLast
	points := []*bn254.G1Affine{
		&vk.Qm, &vk.Qc, &vk.Ql, &vk.Qr, &vk.Qo, &vk.Q4,
		&vk.QLookup, &vk.QArith, &vk.QDeltaRange, &vk.QElliptic,
		&vk.QMemory, &vk.QNnf, &vk.QPoseidon2External, &vk.QPoseidon2Internal,
		&vk.S1, &vk.S2, &vk.S3, &vk.S4,
		&vk.ID1, &vk.ID2, &vk.ID3, &vk.ID4,
		&vk.T1, &vk.T2, &vk.T3, &vk.T4,
		&vk.LagrangeFirst, &vk.LagrangeLast,
	}

	for i, p := range points {
		if err := readG1Affine(data[off:off+GroupElementSize], p); err != nil {
			return nil, fmt.Errorf("VK G1 point %d: %w", i, err)
		}
		off += GroupElementSize
	}

	return vk, nil
}

// DeserializeProof parses a ZK proof from EVM-format bytes.
// The proof size is variable depending on logN from the VK.
func DeserializeProof(data []byte, logN uint64) (*ZKProof, error) {
	p := &ZKProof{}
	off := 0

	// Helper to check bounds
	need := func(n int) error {
		if off+n > len(data) {
			return fmt.Errorf("proof too short: need %d more bytes at offset %d, have %d", n, off, len(data))
		}
		return nil
	}

	// 1. Pairing point object: 16 Fr elements
	for i := 0; i < PairingPointsSize; i++ {
		if err := need(FieldElementSize); err != nil {
			return nil, err
		}
		readFr(data[off:off+FieldElementSize], &p.PairingPointObject[i])
		off += FieldElementSize
	}

	// 2. Gemini masking polynomial commitment (ZK)
	if err := need(GroupElementSize); err != nil {
		return nil, err
	}
	if err := readG1Affine(data[off:off+GroupElementSize], &p.GeminiMaskingPoly); err != nil {
		return nil, fmt.Errorf("geminiMaskingPoly: %w", err)
	}
	off += GroupElementSize

	// 3. Wire commitments: w1, w2, w3
	wireComms := []*bn254.G1Affine{&p.W1, &p.W2, &p.W3}
	for i, w := range wireComms {
		if err := need(GroupElementSize); err != nil {
			return nil, err
		}
		if err := readG1Affine(data[off:off+GroupElementSize], w); err != nil {
			return nil, fmt.Errorf("w%d: %w", i+1, err)
		}
		off += GroupElementSize
	}

	// 4. Lookup/permutation helpers (in Solidity loadProof order)
	// lookupReadCounts, lookupReadTags, w4, lookupInverses, zPerm
	orderedComms := []*bn254.G1Affine{
		&p.LookupReadCounts, &p.LookupReadTags,
		&p.W4,
		&p.LookupInverses, &p.ZPerm,
	}
	names := []string{"lookupReadCounts", "lookupReadTags", "w4", "lookupInverses", "zPerm"}
	for i, c := range orderedComms {
		if err := need(GroupElementSize); err != nil {
			return nil, err
		}
		if err := readG1Affine(data[off:off+GroupElementSize], c); err != nil {
			return nil, fmt.Errorf("%s: %w", names[i], err)
		}
		off += GroupElementSize
	}

	// 5. Libra commitment 0
	if err := need(GroupElementSize); err != nil {
		return nil, err
	}
	if err := readG1Affine(data[off:off+GroupElementSize], &p.LibraCommitments[0]); err != nil {
		return nil, fmt.Errorf("libraCommitments[0]: %w", err)
	}
	off += GroupElementSize

	// 6. Libra sum
	if err := need(FieldElementSize); err != nil {
		return nil, err
	}
	readFr(data[off:off+FieldElementSize], &p.LibraSum)
	off += FieldElementSize

	// 7. Sumcheck univariates: logN rounds × ZK_BATCHED_RELATION_PARTIAL_LENGTH
	p.SumcheckUnivariates = make([][]fr.Element, logN)
	for i := uint64(0); i < logN; i++ {
		p.SumcheckUnivariates[i] = make([]fr.Element, ZKBatchedRelationPartialLen)
		for j := 0; j < ZKBatchedRelationPartialLen; j++ {
			if err := need(FieldElementSize); err != nil {
				return nil, err
			}
			readFr(data[off:off+FieldElementSize], &p.SumcheckUnivariates[i][j])
			off += FieldElementSize
		}
	}

	// 8. Sumcheck evaluations: NUMBER_OF_ENTITIES_ZK (42 for EVM format)
	for i := 0; i < NumberOfEntitiesZK; i++ {
		if err := need(FieldElementSize); err != nil {
			return nil, err
		}
		readFr(data[off:off+FieldElementSize], &p.SumcheckEvaluations[i])
		off += FieldElementSize
	}

	// 9. Libra evaluation
	if err := need(FieldElementSize); err != nil {
		return nil, err
	}
	readFr(data[off:off+FieldElementSize], &p.LibraEvaluation)
	off += FieldElementSize

	// 10. Libra commitments 1 and 2
	for i := 1; i <= 2; i++ {
		if err := need(GroupElementSize); err != nil {
			return nil, err
		}
		if err := readG1Affine(data[off:off+GroupElementSize], &p.LibraCommitments[i]); err != nil {
			return nil, fmt.Errorf("libraCommitments[%d]: %w", i, err)
		}
		off += GroupElementSize
	}

	// 11. Gemini fold commitments: logN - 1 G1 points
	p.GeminiFoldComms = make([]bn254.G1Affine, logN-1)
	for i := uint64(0); i < logN-1; i++ {
		if err := need(GroupElementSize); err != nil {
			return nil, err
		}
		if err := readG1Affine(data[off:off+GroupElementSize], &p.GeminiFoldComms[i]); err != nil {
			return nil, fmt.Errorf("geminiFoldComms[%d]: %w", i, err)
		}
		off += GroupElementSize
	}

	// 12. Gemini A evaluations: logN scalars
	p.GeminiAEvaluations = make([]fr.Element, logN)
	for i := uint64(0); i < logN; i++ {
		if err := need(FieldElementSize); err != nil {
			return nil, err
		}
		readFr(data[off:off+FieldElementSize], &p.GeminiAEvaluations[i])
		off += FieldElementSize
	}

	// 13. Libra polynomial evaluations: 4 scalars
	for i := 0; i < 4; i++ {
		if err := need(FieldElementSize); err != nil {
			return nil, err
		}
		readFr(data[off:off+FieldElementSize], &p.LibraPolyEvals[i])
		off += FieldElementSize
	}

	// 14. Shplonk Q
	if err := need(GroupElementSize); err != nil {
		return nil, err
	}
	if err := readG1Affine(data[off:off+GroupElementSize], &p.ShplonkQ); err != nil {
		return nil, fmt.Errorf("shplonkQ: %w", err)
	}
	off += GroupElementSize

	// 15. KZG quotient
	if err := need(GroupElementSize); err != nil {
		return nil, err
	}
	if err := readG1Affine(data[off:off+GroupElementSize], &p.KzgQuotient); err != nil {
		return nil, fmt.Errorf("kzgQuotient: %w", err)
	}

	return p, nil
}

// readUint256AsUint64 reads a 32-byte big-endian uint256 and returns the low 64 bits.
func readUint256AsUint64(data []byte) uint64 {
	// The value is in the last 8 bytes for small values
	return binary.BigEndian.Uint64(data[24:32])
}

// readFr reads a 32-byte big-endian field element.
func readFr(data []byte, out *fr.Element) {
	out.SetBytes(data[:FieldElementSize])
}

// readG1Affine reads a 64-byte big-endian uncompressed G1 point (x, y).
// Accepts (0, 0) as the point at infinity.
func readG1Affine(data []byte, out *bn254.G1Affine) error {
	// Check for point at infinity (all zeros)
	allZero := true
	for _, b := range data[:GroupElementSize] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		out.X.SetZero()
		out.Y.SetZero()
		return nil
	}

	// gnark-crypto SetBytes expects big-endian uncompressed: x (32 bytes) || y (32 bytes)
	_, err := out.SetBytes(data[:GroupElementSize])
	if err != nil {
		return fmt.Errorf("invalid G1 point: %w", err)
	}
	return nil
}
