package verifyultrahonk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

// Verify verifies an UltraHonk ZK proof against a verification key and public inputs.
// proofBytes: EVM-format proof bytes (variable length based on circuit)
// vkBytes: EVM-format VK bytes (1888 bytes)
// publicInputs: public inputs as Fr elements (user-visible only, without pairing points)
func Verify(proofBytes, vkBytes []byte, publicInputs []fr.Element) (bool, error) {
	// 1. Deserialize VK
	vk, err := DeserializeVK(vkBytes)
	if err != nil {
		return false, fmt.Errorf("deserialize VK: %w", err)
	}

	logN := vk.LogCircuitSize

	// 2. Deserialize proof
	proof, err := DeserializeProof(proofBytes, logN)
	if err != nil {
		return false, fmt.Errorf("deserialize proof: %w", err)
	}

	// 3. Validate public inputs count
	// VK.publicInputsSize includes PairingPointsSize (16 elements from the proof)
	expectedUserInputs := int(vk.PublicInputsSize) - PairingPointsSize
	if len(publicInputs) != expectedUserInputs {
		return false, fmt.Errorf("expected %d public inputs, got %d", expectedUserInputs, len(publicInputs))
	}

	// 4. Compute VK hash: keccak256(vkBytes) reduced modulo BN254 scalar field order
	h := sha3.NewLegacyKeccak256()
	h.Write(vkBytes)
	rawHash := h.Sum(nil)
	var vkHashFr fr.Element
	vkHashFr.SetBytes(rawHash) // SetBytes reduces modulo the field order
	var vkHash [32]byte
	copy(vkHash[:], vkHashFr.Marshal())

	// 5. Generate Fiat-Shamir transcript
	tp := GenerateTranscript(proof, publicInputs, vkHash, vk.PublicInputsSize, logN)

	// 6. Compute public inputs delta
	tp.RelationParams.PublicInputsDelta = computePublicInputDelta(
		publicInputs,
		proof.PairingPointObject[:],
		tp.RelationParams.Beta,
		tp.RelationParams.Gamma,
		1, // pub_inputs_offset = 1
	)

	// 7. Verify sumcheck
	if !verifySumcheck(proof, tp, logN) {
		return false, fmt.Errorf("sumcheck verification failed")
	}

	// 8. Verify Shplemini opening
	if !verifyShplemini(proof, vk, tp, logN) {
		return false, fmt.Errorf("shplemini verification failed")
	}

	return true, nil
}

// computePublicInputDelta computes the public input contribution to the permutation argument.
// This matches Solidity computePublicInputDelta exactly.
func computePublicInputDelta(
	publicInputs []fr.Element,
	pairingPointObject []fr.Element,
	beta, gamma fr.Element,
	offset uint64,
) fr.Element {
	var one fr.Element
	one.SetOne()

	var numerator, denominator fr.Element
	numerator.SetOne()
	denominator.SetOne()

	// PERMUTATION_ARGUMENT_VALUE_SEPARATOR = 1 << 28
	var separator fr.Element
	separator.SetUint64(1 << 28)

	// numeratorAcc = gamma + beta * (SEPARATOR + offset)
	var numeratorAcc fr.Element
	{
		var tmp fr.Element
		tmp.SetUint64(offset)
		tmp.Add(&tmp, &separator)
		tmp.Mul(&tmp, &beta)
		numeratorAcc.Add(&gamma, &tmp)
	}

	// denominatorAcc = gamma - beta * (offset + 1)
	var denominatorAcc fr.Element
	{
		var tmp fr.Element
		tmp.SetUint64(offset + 1)
		tmp.Mul(&tmp, &beta)
		denominatorAcc.Sub(&gamma, &tmp)
	}

	// Process user-visible public inputs
	for i := range publicInputs {
		var numTerm, denTerm fr.Element
		numTerm.Add(&numeratorAcc, &publicInputs[i])
		numerator.Mul(&numerator, &numTerm)

		denTerm.Add(&denominatorAcc, &publicInputs[i])
		denominator.Mul(&denominator, &denTerm)

		numeratorAcc.Add(&numeratorAcc, &beta)
		denominatorAcc.Sub(&denominatorAcc, &beta)
	}

	// Process pairing point object elements
	for i := range pairingPointObject {
		var numTerm, denTerm fr.Element
		numTerm.Add(&numeratorAcc, &pairingPointObject[i])
		numerator.Mul(&numerator, &numTerm)

		denTerm.Add(&denominatorAcc, &pairingPointObject[i])
		denominator.Mul(&denominator, &denTerm)

		numeratorAcc.Add(&numeratorAcc, &beta)
		denominatorAcc.Sub(&denominatorAcc, &beta)
	}

	// delta = numerator / denominator
	denominator.Inverse(&denominator)
	var delta fr.Element
	delta.Mul(&numerator, &denominator)
	return delta
}

// verifySumcheck verifies the sumcheck protocol.
func verifySumcheck(proof *ZKProof, tp *Transcript, logN uint64) bool {
	// roundTargetSum = libraChallenge * libraSum
	var roundTargetSum fr.Element
	roundTargetSum.Mul(&tp.LibraChallenge, &proof.LibraSum)

	var powPartialEvaluation fr.Element
	powPartialEvaluation.SetOne()

	var one fr.Element
	one.SetOne()

	// Sumcheck reduction over logN rounds
	for round := uint64(0); round < logN; round++ {
		univariate := proof.SumcheckUnivariates[round]

		// Check: u[0] + u[1] == roundTargetSum
		var totalSum fr.Element
		totalSum.Add(&univariate[0], &univariate[1])
		if !totalSum.Equal(&roundTargetSum) {
			return false
		}

		roundChallenge := tp.SumcheckU[round]

		// Compute next target via barycentric evaluation
		roundTargetSum = computeNextTargetSum(univariate, roundChallenge)

		// Update pow partial evaluation
		// powPartialEval *= (1 + roundChallenge * (gateChallenge - 1))
		var gateMinus1, tmp fr.Element
		gateMinus1.Sub(&tp.GateChallenges[round], &one)
		tmp.Mul(&roundChallenge, &gateMinus1)
		tmp.Add(&tmp, &one)
		powPartialEvaluation.Mul(&powPartialEvaluation, &tmp)
	}

	// Final round: evaluate all relations
	// Extract regular entity evaluations (skip gemini_masking_poly at index 0)
	var relationsEvals [NumberOfEntities]fr.Element
	for i := 0; i < NumberOfEntities; i++ {
		relationsEvals[i] = proof.SumcheckEvaluations[i+NumMaskingPolynomials]
	}

	grandHonkRelationSum := accumulateRelationEvaluations(
		relationsEvals, tp.RelationParams, tp.Alphas, powPartialEvaluation,
	)

	// ZK correction: multiply by (1 - product of u[2..logN-1]) and add libra term
	var evaluation fr.Element
	evaluation.SetOne()
	for i := uint64(2); i < logN; i++ {
		evaluation.Mul(&evaluation, &tp.SumcheckU[i])
	}
	var oneMinusEval fr.Element
	oneMinusEval.Sub(&one, &evaluation)
	grandHonkRelationSum.Mul(&grandHonkRelationSum, &oneMinusEval)

	var libraTerm fr.Element
	libraTerm.Mul(&proof.LibraEvaluation, &tp.LibraChallenge)
	grandHonkRelationSum.Add(&grandHonkRelationSum, &libraTerm)

	return grandHonkRelationSum.Equal(&roundTargetSum)
}

// Barycentric Lagrange denominators for ZK_BATCHED_RELATION_PARTIAL_LENGTH = 9
// These are precomputed constants from the Solidity verifier.
var barycentricDenominators [ZKBatchedRelationPartialLen]fr.Element

func init() {
	barycentricDenominators[0].SetString("0x0000000000000000000000000000000000000000000000000000000000009d80")
	barycentricDenominators[1].SetString("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51")
	barycentricDenominators[2].SetString("0x00000000000000000000000000000000000000000000000000000000000005a0")
	barycentricDenominators[3].SetString("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31")
	barycentricDenominators[4].SetString("0x0000000000000000000000000000000000000000000000000000000000000240")
	barycentricDenominators[5].SetString("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31")
	barycentricDenominators[6].SetString("0x00000000000000000000000000000000000000000000000000000000000005a0")
	barycentricDenominators[7].SetString("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51")
	barycentricDenominators[8].SetString("0x0000000000000000000000000000000000000000000000000000000000009d80")
}

// computeNextTargetSum evaluates the univariate polynomial at the challenge point
// using barycentric Lagrange interpolation.
func computeNextTargetSum(univariate []fr.Element, challenge fr.Element) fr.Element {
	// Compute B(x) = product(challenge - i) for i = 0..8
	var numeratorValue fr.Element
	numeratorValue.SetOne()
	for i := 0; i < ZKBatchedRelationPartialLen; i++ {
		var iVal, diff fr.Element
		iVal.SetUint64(uint64(i))
		diff.Sub(&challenge, &iVal)
		numeratorValue.Mul(&numeratorValue, &diff)
	}

	// Compute sum of u[i] / (denom[i] * (challenge - i))
	var targetSum fr.Element
	for i := 0; i < ZKBatchedRelationPartialLen; i++ {
		var iVal, diff, denomTimeDiff, inv, term fr.Element
		iVal.SetUint64(uint64(i))
		diff.Sub(&challenge, &iVal)
		denomTimeDiff.Mul(&barycentricDenominators[i], &diff)
		inv.Inverse(&denomTimeDiff)
		term.Mul(&univariate[i], &inv)
		targetSum.Add(&targetSum, &term)
	}

	// Scale by B(x)
	targetSum.Mul(&targetSum, &numeratorValue)
	return targetSum
}

// verifyShplemini verifies the Shplemini opening protocol and final KZG pairing.
// This exactly mirrors the Solidity verifyShplemini function.
func verifyShplemini(proof *ZKProof, vk *VerificationKey, tp *Transcript, logN uint64) bool {
	// MSM size = NUMBER_UNSHIFTED_ZK + logN + LIBRA_COMMITMENTS + 2
	msmSize := int(NumberUnshiftedZK) + int(logN) + LibraCommitments + 2
	scalars := make([]fr.Element, msmSize)
	commitments := make([]bn254.G1Affine, msmSize)

	// Compute squares of geminiR: [r, r^2, r^4, ..., r^(2^(logN-1))]
	powersOfR := computeSquares(tp.GeminiR, logN)

	// Initial inverse denominators
	var posInvDenom, negInvDenom fr.Element
	{
		var tmp fr.Element
		tmp.Sub(&tp.ShplonkZ, &powersOfR[0])
		posInvDenom.Inverse(&tmp)
		tmp.Add(&tp.ShplonkZ, &powersOfR[0])
		negInvDenom.Inverse(&tmp)
	}

	// unshiftedScalar = 1/(z-r) + nu * 1/(z+r)
	var unshiftedScalar fr.Element
	{
		var tmp fr.Element
		tmp.Mul(&tp.ShplonkNu, &negInvDenom)
		unshiftedScalar.Add(&posInvDenom, &tmp)
	}

	// shiftedScalar = (1/r) * (1/(z-r) - nu * 1/(z+r))
	var shiftedScalar fr.Element
	{
		var rInv, tmp, diff fr.Element
		rInv.Inverse(&tp.GeminiR)
		tmp.Mul(&tp.ShplonkNu, &negInvDenom)
		diff.Sub(&posInvDenom, &tmp)
		shiftedScalar.Mul(&rInv, &diff)
	}

	// Index 0: shplonkQ with scalar 1
	scalars[0].SetOne()
	commitments[0] = proof.ShplonkQ

	var unshiftedScalarNeg, shiftedScalarNeg fr.Element
	unshiftedScalarNeg.Neg(&unshiftedScalar)
	shiftedScalarNeg.Neg(&shiftedScalar)

	// Build commitment array in Solidity order:
	// [1] = geminiMaskingPoly
	// [2..29] = 28 VK commitments
	// [30..37] = w1, w2, w3, w4, zPerm, lookupInverses, lookupReadCounts, lookupReadTags
	commitments[1] = proof.GeminiMaskingPoly
	vkComms := vk.VKCommitments()
	for i := 0; i < 28; i++ {
		commitments[2+i] = vkComms[i]
	}
	commitments[30] = proof.W1
	commitments[31] = proof.W2
	commitments[32] = proof.W3
	commitments[33] = proof.W4
	commitments[34] = proof.ZPerm
	commitments[35] = proof.LookupInverses
	commitments[36] = proof.LookupReadCounts
	commitments[37] = proof.LookupReadTags

	// Batch unshifted evaluations (NUMBER_UNSHIFTED_ZK = 37)
	var batchingChallenge fr.Element
	batchingChallenge.SetOne()
	var batchedEvaluation fr.Element

	for i := 1; i <= int(NumberUnshiftedZK); i++ {
		scalars[i].Mul(&unshiftedScalarNeg, &batchingChallenge)

		var evalTerm fr.Element
		evalTerm.Mul(&proof.SumcheckEvaluations[i-NumMaskingPolynomials], &batchingChallenge)
		batchedEvaluation.Add(&batchedEvaluation, &evalTerm)

		batchingChallenge.Mul(&batchingChallenge, &tp.Rho)
	}

	// Batch shifted commitments (w1, w2, w3, w4, zPerm) - add to existing scalars
	for i := 0; i < NumberToBeShifted; i++ {
		scalarOff := i + ShiftedCommitmentsStart
		evaluationOff := i + int(NumberUnshiftedZK)

		var shiftContrib fr.Element
		shiftContrib.Mul(&shiftedScalarNeg, &batchingChallenge)
		scalars[scalarOff].Add(&scalars[scalarOff], &shiftContrib)

		var evalTerm fr.Element
		evalTerm.Mul(&proof.SumcheckEvaluations[evaluationOff], &batchingChallenge)
		batchedEvaluation.Add(&batchedEvaluation, &evalTerm)

		batchingChallenge.Mul(&batchingChallenge, &tp.Rho)
	}

	// Compute fold position evaluations
	foldPosEvals := computeFoldPosEvaluations(
		tp.SumcheckU[:logN], batchedEvaluation,
		proof.GeminiAEvaluations, powersOfR, logN,
	)

	// Initialize constant term accumulator with A_0(r) and A_0(-r)
	var constantTermAccumulator fr.Element
	{
		var term1, term2 fr.Element
		term1.Mul(&foldPosEvals[0], &posInvDenom)
		term2.Mul(&proof.GeminiAEvaluations[0], &tp.ShplonkNu)
		term2.Mul(&term2, &negInvDenom)
		constantTermAccumulator.Add(&term1, &term2)
	}

	// Gemini fold commitments: batch with nu powers and inverse denominators
	boundary := int(NumberUnshiftedZK) + 1
	batchingChallenge.Mul(&tp.ShplonkNu, &tp.ShplonkNu) // nu^2

	for i := uint64(0); i < logN-1; i++ {
		// Update inverse denominators for this fold level
		var posInvDenomI, negInvDenomI fr.Element
		{
			var tmp fr.Element
			tmp.Sub(&tp.ShplonkZ, &powersOfR[i+1])
			posInvDenomI.Inverse(&tmp)
			tmp.Add(&tp.ShplonkZ, &powersOfR[i+1])
			negInvDenomI.Inverse(&tmp)
		}

		// scalingFactorPos = batchingChallenge * posInvDenom
		// scalingFactorNeg = batchingChallenge * shplonkNu * negInvDenom
		var scalingFactorPos, scalingFactorNeg fr.Element
		scalingFactorPos.Mul(&batchingChallenge, &posInvDenomI)
		scalingFactorNeg.Mul(&batchingChallenge, &tp.ShplonkNu)
		scalingFactorNeg.Mul(&scalingFactorNeg, &negInvDenomI)

		// scalar = -(scalingFactorPos + scalingFactorNeg)
		var combined fr.Element
		combined.Add(&scalingFactorPos, &scalingFactorNeg)
		scalars[boundary+int(i)].Neg(&combined)

		// Accumulate constant term: scalingFactorPos * foldPosEvals[i+1] + scalingFactorNeg * geminiAEvals[i+1]
		var accumContrib, t1, t2 fr.Element
		t1.Mul(&scalingFactorPos, &foldPosEvals[i+1])
		t2.Mul(&scalingFactorNeg, &proof.GeminiAEvaluations[i+1])
		accumContrib.Add(&t1, &t2)
		constantTermAccumulator.Add(&constantTermAccumulator, &accumContrib)

		// Update batchingChallenge: *= nu^2
		batchingChallenge.Mul(&batchingChallenge, &tp.ShplonkNu)
		batchingChallenge.Mul(&batchingChallenge, &tp.ShplonkNu)

		commitments[boundary+int(i)] = proof.GeminiFoldComms[i]
	}

	boundary += int(logN) - 1

	// Libra commitments and polynomial evaluations
	// denominators: [1/(z-r), 1/(z - subgroupGen*r), 1/(z-r), 1/(z-r)]
	var libraDenoms [4]fr.Element
	{
		var tmp fr.Element
		tmp.Sub(&tp.ShplonkZ, &tp.GeminiR)
		libraDenoms[0].Inverse(&tmp)

		var sgr fr.Element
		sgr.Mul(&SubgroupGenerator, &tp.GeminiR)
		tmp.Sub(&tp.ShplonkZ, &sgr)
		libraDenoms[1].Inverse(&tmp)

		libraDenoms[2] = libraDenoms[0]
		libraDenoms[3] = libraDenoms[0]
	}

	// Update batchingChallenge: *= nu^2
	batchingChallenge.Mul(&batchingChallenge, &tp.ShplonkNu)
	batchingChallenge.Mul(&batchingChallenge, &tp.ShplonkNu)

	var batchingScalars [4]fr.Element
	for i := 0; i < LibraEvaluations; i++ {
		var scalingFactor fr.Element
		scalingFactor.Mul(&libraDenoms[i], &batchingChallenge)
		batchingScalars[i].Neg(&scalingFactor)
		batchingChallenge.Mul(&batchingChallenge, &tp.ShplonkNu)

		// Accumulate constant term
		var term fr.Element
		term.Mul(&scalingFactor, &proof.LibraPolyEvals[i])
		constantTermAccumulator.Add(&constantTermAccumulator, &term)
	}

	// Assign libra commitment scalars (batchingScalars[1] + batchingScalars[2] combined)
	scalars[boundary] = batchingScalars[0]
	scalars[boundary+1].Add(&batchingScalars[1], &batchingScalars[2])
	scalars[boundary+2] = batchingScalars[3]

	for i := 0; i < LibraCommitments; i++ {
		commitments[boundary+i] = proof.LibraCommitments[i]
	}
	boundary += LibraCommitments

	// G1 generator for constant term
	_, _, g1Gen, _ := bn254.Generators()
	commitments[boundary] = g1Gen
	scalars[boundary] = constantTermAccumulator
	boundary++

	// KZG quotient with shplonkZ scalar
	commitments[boundary] = proof.KzgQuotient
	scalars[boundary] = tp.ShplonkZ

	// Perform MSM to get P_0
	var p0 bn254.G1Affine
	_, err := p0.MultiExp(commitments, scalars, ecc.MultiExpConfig{})
	if err != nil {
		return false
	}

	// P_1 = -kzgQuotient
	var p1 bn254.G1Affine
	p1.Neg(&proof.KzgQuotient)

	// Aggregate with recursive proof pairing points
	recursionSeparator := generateRecursionSeparator(proof.PairingPointObject, p0, p1)
	p0Other, p1Other := convertPairingPointsToG1(proof.PairingPointObject)

	// P_0_final = recursionSeparator * P_0 + P_0_other
	var p0Final bn254.G1Affine
	p0Final.ScalarMultiplication(&p0, recursionSeparator.BigInt(new(big.Int)))
	p0Final.Add(&p0Final, &p0Other)

	// P_1_final = recursionSeparator * P_1 + P_1_other
	var p1Final bn254.G1Affine
	p1Final.ScalarMultiplication(&p1, recursionSeparator.BigInt(new(big.Int)))
	p1Final.Add(&p1Final, &p1Other)

	// Final pairing check: e(P_0_final, G2) * e(P_1_final, srsG2VK) == 1
	return kzgPairingCheck(p0Final, p1Final)
}

// computeSquares computes [r, r^2, r^4, ..., r^(2^(n-1))].
func computeSquares(r fr.Element, n uint64) []fr.Element {
	powers := make([]fr.Element, n)
	powers[0] = r
	for i := uint64(1); i < n; i++ {
		powers[i].Mul(&powers[i-1], &powers[i-1])
	}
	return powers
}

// convertPairingPointsToG1 converts the 16-element pairing point object from the proof
// into two G1 affine points (lhs, rhs) by reconstructing uint256 from 68-bit limbs.
func convertPairingPointsToG1(pp [PairingPointsSize]fr.Element) (lhs, rhs bn254.G1Affine) {
	// Each coordinate is reconstructed from 4 x 68-bit limbs
	reconstruct := func(elems [4]fr.Element) *big.Int {
		val := new(big.Int)
		for i := 3; i >= 0; i-- {
			limb := elems[i].BigInt(new(big.Int))
			val.Lsh(val, 68)
			val.Or(val, limb)
		}
		return val
	}

	lhsX := reconstruct([4]fr.Element{pp[0], pp[1], pp[2], pp[3]})
	lhsY := reconstruct([4]fr.Element{pp[4], pp[5], pp[6], pp[7]})
	rhsX := reconstruct([4]fr.Element{pp[8], pp[9], pp[10], pp[11]})
	rhsY := reconstruct([4]fr.Element{pp[12], pp[13], pp[14], pp[15]})

	lhs.X.SetBigInt(lhsX)
	lhs.Y.SetBigInt(lhsY)
	rhs.X.SetBigInt(rhsX)
	rhs.Y.SetBigInt(rhsY)
	return
}

// generateRecursionSeparator computes keccak256 of the 8 coordinates
// (proofLhs, proofRhs from pairing points, plus accLhs=P_0, accRhs=P_1).
func generateRecursionSeparator(pp [PairingPointsSize]fr.Element, p0, p1 bn254.G1Affine) fr.Element {
	proofLhs, proofRhs := convertPairingPointsToG1(pp)

	h := sha3.NewLegacyKeccak256()
	// 8 x 32-byte big-endian coordinates
	coords := [8]*big.Int{
		proofLhs.X.BigInt(new(big.Int)),
		proofLhs.Y.BigInt(new(big.Int)),
		proofRhs.X.BigInt(new(big.Int)),
		proofRhs.Y.BigInt(new(big.Int)),
		p0.X.BigInt(new(big.Int)),
		p0.Y.BigInt(new(big.Int)),
		p1.X.BigInt(new(big.Int)),
		p1.Y.BigInt(new(big.Int)),
	}
	for _, c := range coords {
		var buf [32]byte
		b := c.Bytes()
		copy(buf[32-len(b):], b)
		h.Write(buf[:])
	}

	var result fr.Element
	result.SetBytes(h.Sum(nil))
	return result
}

// computeFoldPosEvaluations reconstructs A_l(r^{2^l}) from Gemini evaluations.
// Matches Solidity CommitmentSchemeLib.computeFoldPosEvaluations exactly.
func computeFoldPosEvaluations(
	uChallenges []fr.Element,
	batchedEvalAccumulator fr.Element,
	geminiEvals []fr.Element,
	powersOfR []fr.Element,
	logN uint64,
) []fr.Element {
	evals := make([]fr.Element, logN)

	var one, two fr.Element
	one.SetOne()
	two.SetUint64(2)

	accumulator := batchedEvalAccumulator

	// Iterate from logN down to 1 (matching Solidity: for i = logSize; i > 0; --i)
	for i := logN; i > 0; i-- {
		challengePower := powersOfR[i-1] // r^{2^{i-1}}
		u := uChallenges[i-1]

		// numerator = challengePower * accumulator * 2 - geminiEvals[i-1] * (challengePower * (1 - u) - u)
		var oneMinusU fr.Element
		oneMinusU.Sub(&one, &u)

		var innerTerm fr.Element // challengePower * (1 - u) - u
		innerTerm.Mul(&challengePower, &oneMinusU)
		innerTerm.Sub(&innerTerm, &u)

		var numerator fr.Element
		numerator.Mul(&challengePower, &accumulator)
		numerator.Mul(&numerator, &two)
		var subtractTerm fr.Element
		subtractTerm.Mul(&geminiEvals[i-1], &innerTerm)
		numerator.Sub(&numerator, &subtractTerm)

		// denominator = challengePower * (1 - u) + u
		var denominator fr.Element
		denominator.Mul(&challengePower, &oneMinusU)
		denominator.Add(&denominator, &u)

		// result = numerator / denominator
		var denomInv fr.Element
		denomInv.Inverse(&denominator)
		var result fr.Element
		result.Mul(&numerator, &denomInv)

		accumulator = result
		evals[i-1] = result
	}

	return evals
}

// SRS G2 points from the Aztec Ignition ceremony (BN254).
var (
	srsG2    bn254.G2Affine // G2 generator
	srsG2VK  bn254.G2Affine // [x]G2 from trusted setup
)

func init() {
	// Standard BN254 G2 generator
	_, _, _, g2Gen := bn254.Generators()
	srsG2 = g2Gen

	// [x]G2 from the Aztec Ignition ceremony SRS
	// These are the same values used in the Solidity verifier
	// EVM ecPairing format: x_im(A1), x_re(A0), y_im(A1), y_re(A0)
	srsG2VK.X.A0.SetString("0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0")
	srsG2VK.X.A1.SetString("0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1")
	srsG2VK.Y.A0.SetString("0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55")
	srsG2VK.Y.A1.SetString("0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4")
}

// kzgPairingCheck performs the final KZG pairing verification.
// Checks: e(P_0, G2) * e(P_1, srsG2VK) == 1
// Matches Solidity: pairing(P_0, P_1) with fixed G2 and SRS G2 points.
func kzgPairingCheck(p0, p1 bn254.G1Affine) bool {
	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{p0, p1},
		[]bn254.G2Affine{srsG2, srsG2VK},
	)
	if err != nil {
		return false
	}
	return ok
}
