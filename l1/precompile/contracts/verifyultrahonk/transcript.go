package verifyultrahonk

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

// mask127 is 2^127 - 1, used to extract the lower 127 bits.
var mask127 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))

// GenerateTranscript generates all Fiat-Shamir challenges from the proof and public inputs.
// This exactly mirrors the Solidity ZKTranscriptLib.generateTranscript.
func GenerateTranscript(
	proof *ZKProof,
	publicInputs []fr.Element,
	vkHash [32]byte,
	publicInputsSize uint64,
	logN uint64,
) *Transcript {
	t := &Transcript{}
	var prevChallenge fr.Element

	// 1. Relation parameters (eta, etaTwo, etaThree, beta, gamma)
	t.RelationParams, prevChallenge = generateRelationParametersChallenges(
		proof, publicInputs, vkHash, publicInputsSize,
	)

	// 2. Alpha challenges
	t.Alphas, prevChallenge = generateAlphaChallenges(prevChallenge, proof)

	// 3. Gate challenges
	t.GateChallenges, prevChallenge = generateGateChallenges(prevChallenge, logN)

	// 4. Libra challenge (ZK)
	t.LibraChallenge, prevChallenge = generateLibraChallenge(prevChallenge, proof)

	// 5. Sumcheck u-challenges
	t.SumcheckU, prevChallenge = generateSumcheckChallenges(proof, prevChallenge, logN)

	// 6. Rho challenge
	t.Rho, prevChallenge = generateRhoChallenge(proof, prevChallenge)

	// 7. Gemini R challenge
	t.GeminiR, prevChallenge = generateGeminiRChallenge(proof, prevChallenge, logN)

	// 8. Shplonk Nu challenge
	t.ShplonkNu, prevChallenge = generateShplonkNuChallenge(proof, prevChallenge, logN)

	// 9. Shplonk Z challenge
	t.ShplonkZ, _ = generateShplonkZChallenge(proof, prevChallenge)

	return t
}

// splitChallenge splits a 256-bit Fr element into two 127-bit values.
// Matches Solidity: lo = challenge & 0x7FFF...F (127 bits), hi = challenge >> 127
func splitChallenge(challenge fr.Element) (first, second fr.Element) {
	buf := challenge.Marshal()
	val := new(big.Int).SetBytes(buf)

	lo := new(big.Int).And(val, mask127)
	hi := new(big.Int).Rsh(val, 127)

	first.SetBigInt(lo)
	second.SetBigInt(hi)
	return
}

// keccakHash computes keccak256 of the concatenated 32-byte big-endian representations.
func keccakHash(elements ...[]byte) fr.Element {
	h := sha3.NewLegacyKeccak256()
	for _, e := range elements {
		h.Write(e)
	}
	hash := h.Sum(nil)

	var result fr.Element
	result.SetBytes(hash)
	return result
}

// frToBytes32 converts an Fr element to a 32-byte big-endian representation.
func frToBytes32(f fr.Element) []byte {
	return f.Marshal()
}

// g1ToBytes returns the 64-byte big-endian representation of a G1 affine point (x || y).
func g1ToBytes(x, y *big.Int) []byte {
	var buf [64]byte
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(buf[32-len(xBytes):32], xBytes)
	copy(buf[64-len(yBytes):64], yBytes)
	return buf[:]
}

// generateRelationParametersChallenges generates eta, etaTwo, etaThree, beta, gamma.
func generateRelationParametersChallenges(
	proof *ZKProof,
	publicInputs []fr.Element,
	vkHash [32]byte,
	publicInputsSize uint64,
) (RelationParameters, fr.Element) {
	var rp RelationParameters
	var prevChallenge fr.Element

	rp.Eta, rp.EtaTwo, rp.EtaThree, prevChallenge = generateEtaChallenge(
		proof, publicInputs, vkHash, publicInputsSize,
	)
	rp.Beta, rp.Gamma, prevChallenge = generateBetaAndGammaChallenges(prevChallenge, proof)
	return rp, prevChallenge
}

// generateEtaChallenge produces eta, etaTwo, etaThree from the initial round.
// round0 = vkHash || publicInputs[0..n-16] || pairingPointObject[0..15] || geminiMaskingPoly.x/y || w1.x/y || w2.x/y || w3.x/y
func generateEtaChallenge(
	proof *ZKProof,
	publicInputs []fr.Element,
	vkHash [32]byte,
	publicInputsSize uint64,
) (eta, etaTwo, etaThree, prevChallenge fr.Element) {
	// Build round0: 1 (vkHash) + publicInputsSize + 8 (geminiMask(2) + 3 wires(6)) elements
	var parts [][]byte

	// vkHash
	parts = append(parts, vkHash[:])

	// Public inputs (excluding pairing point object which is from the proof)
	numUserInputs := int(publicInputsSize) - PairingPointsSize
	for i := 0; i < numUserInputs; i++ {
		if i < len(publicInputs) {
			parts = append(parts, frToBytes32(publicInputs[i]))
		} else {
			parts = append(parts, make([]byte, 32))
		}
	}

	// Pairing point object (16 elements from proof)
	for i := 0; i < PairingPointsSize; i++ {
		parts = append(parts, frToBytes32(proof.PairingPointObject[i]))
	}

	// Gemini masking poly commitment (ZK)
	parts = append(parts, pointXBytes(&proof.GeminiMaskingPoly))
	parts = append(parts, pointYBytes(&proof.GeminiMaskingPoly))

	// w1, w2, w3 commitments
	parts = append(parts, pointXBytes(&proof.W1))
	parts = append(parts, pointYBytes(&proof.W1))
	parts = append(parts, pointXBytes(&proof.W2))
	parts = append(parts, pointYBytes(&proof.W2))
	parts = append(parts, pointXBytes(&proof.W3))
	parts = append(parts, pointYBytes(&proof.W3))

	prevChallenge = keccakHash(parts...)
	eta, etaTwo = splitChallenge(prevChallenge)

	// etaThree = splitChallenge(keccak256(prevChallenge))
	prevChallenge = keccakHash(frToBytes32(prevChallenge))
	etaThree, _ = splitChallenge(prevChallenge)
	return
}

// generateBetaAndGammaChallenges produces beta and gamma.
// round1 = prevChallenge || lookupReadCounts.x/y || lookupReadTags.x/y || w4.x/y
func generateBetaAndGammaChallenges(prevChallenge fr.Element, proof *ZKProof) (beta, gamma, nextPrev fr.Element) {
	parts := [][]byte{
		frToBytes32(prevChallenge),
		pointXBytes(&proof.LookupReadCounts),
		pointYBytes(&proof.LookupReadCounts),
		pointXBytes(&proof.LookupReadTags),
		pointYBytes(&proof.LookupReadTags),
		pointXBytes(&proof.W4),
		pointYBytes(&proof.W4),
	}
	nextPrev = keccakHash(parts...)
	beta, gamma = splitChallenge(nextPrev)
	return
}

// generateAlphaChallenges produces alpha powers for batching subrelations.
// round = prevChallenge || lookupInverses.x/y || zPerm.x/y
func generateAlphaChallenges(prevChallenge fr.Element, proof *ZKProof) ([NumberOfAlphas]fr.Element, fr.Element) {
	parts := [][]byte{
		frToBytes32(prevChallenge),
		pointXBytes(&proof.LookupInverses),
		pointYBytes(&proof.LookupInverses),
		pointXBytes(&proof.ZPerm),
		pointYBytes(&proof.ZPerm),
	}
	nextPrev := keccakHash(parts...)
	alpha, _ := splitChallenge(nextPrev)

	var alphas [NumberOfAlphas]fr.Element
	alphas[0] = alpha
	for i := 1; i < NumberOfAlphas; i++ {
		alphas[i].Mul(&alphas[i-1], &alpha)
	}
	return alphas, nextPrev
}

// generateGateChallenges produces gate challenges (first is from hash, rest are squares).
func generateGateChallenges(prevChallenge fr.Element, logN uint64) ([ConstProofSizeLogN]fr.Element, fr.Element) {
	var gateChallenges [ConstProofSizeLogN]fr.Element
	prevChallenge = keccakHash(frToBytes32(prevChallenge))
	gateChallenges[0], _ = splitChallenge(prevChallenge)
	for i := uint64(1); i < logN; i++ {
		gateChallenges[i].Mul(&gateChallenges[i-1], &gateChallenges[i-1])
	}
	return gateChallenges, prevChallenge
}

// generateLibraChallenge produces the libra challenge (ZK).
// round = prevChallenge || libraCommitments[0].x/y || libraSum
func generateLibraChallenge(prevChallenge fr.Element, proof *ZKProof) (libraChallenge, nextPrev fr.Element) {
	parts := [][]byte{
		frToBytes32(prevChallenge),
		pointXBytes(&proof.LibraCommitments[0]),
		pointYBytes(&proof.LibraCommitments[0]),
		frToBytes32(proof.LibraSum),
	}
	nextPrev = keccakHash(parts...)
	libraChallenge, _ = splitChallenge(nextPrev)
	return
}

// generateSumcheckChallenges produces one challenge per sumcheck round.
func generateSumcheckChallenges(proof *ZKProof, prevChallenge fr.Element, logN uint64) ([ConstProofSizeLogN]fr.Element, fr.Element) {
	var challenges [ConstProofSizeLogN]fr.Element
	for i := uint64(0); i < logN; i++ {
		parts := [][]byte{frToBytes32(prevChallenge)}
		for j := 0; j < ZKBatchedRelationPartialLen; j++ {
			parts = append(parts, frToBytes32(proof.SumcheckUnivariates[i][j]))
		}
		prevChallenge = keccakHash(parts...)
		challenges[i], _ = splitChallenge(prevChallenge)
	}
	return challenges, prevChallenge
}

// generateRhoChallenge produces rho from sumcheck evaluations + libra data.
func generateRhoChallenge(proof *ZKProof, prevChallenge fr.Element) (rho, nextPrev fr.Element) {
	// 1 (prevChallenge) + NUMBER_OF_ENTITIES_ZK (evaluations) + 1 (libraEval) + 4 (2 libra comm coords)
	parts := [][]byte{frToBytes32(prevChallenge)}

	for i := 0; i < NumberOfEntitiesZK; i++ {
		parts = append(parts, frToBytes32(proof.SumcheckEvaluations[i]))
	}
	parts = append(parts, frToBytes32(proof.LibraEvaluation))
	parts = append(parts, pointXBytes(&proof.LibraCommitments[1]))
	parts = append(parts, pointYBytes(&proof.LibraCommitments[1]))
	parts = append(parts, pointXBytes(&proof.LibraCommitments[2]))
	parts = append(parts, pointYBytes(&proof.LibraCommitments[2]))

	nextPrev = keccakHash(parts...)
	rho, _ = splitChallenge(nextPrev)
	return
}

// generateGeminiRChallenge produces geminiR from fold commitments.
func generateGeminiRChallenge(proof *ZKProof, prevChallenge fr.Element, logN uint64) (geminiR, nextPrev fr.Element) {
	parts := [][]byte{frToBytes32(prevChallenge)}
	for i := uint64(0); i < logN-1; i++ {
		parts = append(parts, pointXBytes(&proof.GeminiFoldComms[i]))
		parts = append(parts, pointYBytes(&proof.GeminiFoldComms[i]))
	}
	nextPrev = keccakHash(parts...)
	geminiR, _ = splitChallenge(nextPrev)
	return
}

// generateShplonkNuChallenge produces shplonkNu from gemini evaluations + libra poly evals.
func generateShplonkNuChallenge(proof *ZKProof, prevChallenge fr.Element, logN uint64) (shplonkNu, nextPrev fr.Element) {
	parts := [][]byte{frToBytes32(prevChallenge)}
	for i := uint64(0); i < logN; i++ {
		parts = append(parts, frToBytes32(proof.GeminiAEvaluations[i]))
	}
	for i := 0; i < 4; i++ {
		parts = append(parts, frToBytes32(proof.LibraPolyEvals[i]))
	}
	nextPrev = keccakHash(parts...)
	shplonkNu, _ = splitChallenge(nextPrev)
	return
}

// generateShplonkZChallenge produces shplonkZ from the shplonk Q commitment.
func generateShplonkZChallenge(proof *ZKProof, prevChallenge fr.Element) (shplonkZ, nextPrev fr.Element) {
	parts := [][]byte{
		frToBytes32(prevChallenge),
		pointXBytes(&proof.ShplonkQ),
		pointYBytes(&proof.ShplonkQ),
	}
	nextPrev = keccakHash(parts...)
	shplonkZ, _ = splitChallenge(nextPrev)
	return
}

// pointXBytes returns the 32-byte big-endian x-coordinate of a G1 affine point.
func pointXBytes(p *bn254.G1Affine) []byte {
	b := p.X.Bytes()
	return b[:]
}

// pointYBytes returns the 32-byte big-endian y-coordinate of a G1 affine point.
func pointYBytes(p *bn254.G1Affine) []byte {
	b := p.Y.Bytes()
	return b[:]
}
