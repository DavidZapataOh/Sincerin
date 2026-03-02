package verifyultrahonk

// Port of the 28 UltraHonk subrelations from Aztec's Solidity Relations.sol.
// All arithmetic is modular over BN254's scalar field using gnark-crypto fr.Element.

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

var (
	// NEG_HALF_MODULO_P = (p-1)/2 = 0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000
	negHalfModP fr.Element

	// GRUMPKIN_CURVE_B_PARAMETER_NEGATED = 17 (i.e. -(-17) mod p)
	grumpkinCurveBNeg fr.Element

	// LIMB_SIZE = 2^68
	limbSize fr.Element

	// SUBLIMB_SHIFT = 2^14
	sublimbShift fr.Element

	// Poseidon2 internal matrix diagonal constants
	internalMatrixDiag [4]fr.Element

	// Frequently used small constants
	frOne   fr.Element
	frTwo   fr.Element
	frThree fr.Element
	frNine  fr.Element
)

func init() {
	negHalfModP.SetString("0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000")
	grumpkinCurveBNeg.SetUint64(17)

	// LIMB_SIZE = 2^68
	limbSize.SetBigInt(new(big.Int).Lsh(big.NewInt(1), 68))

	// SUBLIMB_SHIFT = 2^14
	sublimbShift.SetBigInt(new(big.Int).Lsh(big.NewInt(1), 14))

	internalMatrixDiag[0].SetString("0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7")
	internalMatrixDiag[1].SetString("0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b")
	internalMatrixDiag[2].SetString("0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15")
	internalMatrixDiag[3].SetString("0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b")

	frOne.SetOne()
	frTwo.SetUint64(2)
	frThree.SetUint64(3)
	frNine.SetUint64(9)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// wire returns the evaluation at the given wire index.
func wire(p [NumberOfEntities]fr.Element, w int) fr.Element {
	return p[w]
}

// ---------------------------------------------------------------------------
// Top-level accumulation
// ---------------------------------------------------------------------------

// accumulateRelationEvaluations computes all 28 UltraHonk subrelation
// evaluations, then scales and batches them with the alpha challenges.
func accumulateRelationEvaluations(
	p [NumberOfEntities]fr.Element,
	rp RelationParameters,
	alphas [NumberOfAlphas]fr.Element,
	powPartialEval fr.Element,
) fr.Element {
	var evals [NumberOfSubrelations]fr.Element

	accumulateArithmeticRelation(&p, &evals, &powPartialEval)
	accumulatePermutationRelation(&p, &rp, &evals, &powPartialEval)
	accumulateLogDerivativeLookupRelation(&p, &rp, &evals, &powPartialEval)
	accumulateDeltaRangeRelation(&p, &evals, &powPartialEval)
	accumulateEllipticRelation(&p, &evals, &powPartialEval)
	accumulateMemoryRelation(&p, &rp, &evals, &powPartialEval)
	accumulateNnfRelation(&p, &evals, &powPartialEval)
	accumulatePoseidon2ExternalRelation(&p, &evals, &powPartialEval)
	accumulatePoseidon2InternalRelation(&p, &evals, &powPartialEval)

	return scaleAndBatchSubrelations(&evals, &alphas)
}

// ---------------------------------------------------------------------------
// Scale and batch
// ---------------------------------------------------------------------------

// scaleAndBatchSubrelations computes:
//
//	accumulator = evals[0] + sum_{i=1..27}( evals[i] * alphas[i-1] )
func scaleAndBatchSubrelations(
	evals *[NumberOfSubrelations]fr.Element,
	alphas *[NumberOfAlphas]fr.Element,
) fr.Element {
	var accumulator fr.Element
	accumulator.Set(&evals[0])

	var tmp fr.Element
	for i := 1; i < NumberOfSubrelations; i++ {
		tmp.Mul(&evals[i], &alphas[i-1])
		accumulator.Add(&accumulator, &tmp)
	}
	return accumulator
}

// ---------------------------------------------------------------------------
// Arithmetic Relation (subrelations 0, 1)
// ---------------------------------------------------------------------------

func accumulateArithmeticRelation(
	p *[NumberOfEntities]fr.Element,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	qArith := wire(*p, WireQArith)

	// Relation 0
	{
		// neg_half = (p-1)/2
		negHalf := negHalfModP

		wQM := wire(*p, WireQM)
		wWR := wire(*p, WireWR)
		wWL := wire(*p, WireWL)
		wQL := wire(*p, WireQL)
		wQR := wire(*p, WireQR)
		wQO := wire(*p, WireQO)
		wWO := wire(*p, WireWO)
		wQ4 := wire(*p, WireQ4)
		wW4 := wire(*p, WireW4)
		wQC := wire(*p, WireQC)
		wW4Shift := wire(*p, WireW4Shift)

		// accum = (q_arith - 3) * (q_m * w_r * w_l) * neg_half
		var accum, tmp, tmp2 fr.Element
		tmp.Sub(&qArith, &frThree)       // q_arith - 3
		tmp2.Mul(&wQM, &wWR)             // q_m * w_r
		tmp2.Mul(&tmp2, &wWL)            // q_m * w_r * w_l
		accum.Mul(&tmp, &tmp2)           // (q_arith - 3) * (q_m * w_r * w_l)
		accum.Mul(&accum, &negHalf)      // * neg_half

		// accum += q_l * w_l
		tmp.Mul(&wQL, &wWL)
		accum.Add(&accum, &tmp)

		// accum += q_r * w_r
		tmp.Mul(&wQR, &wWR)
		accum.Add(&accum, &tmp)

		// accum += q_o * w_o
		tmp.Mul(&wQO, &wWO)
		accum.Add(&accum, &tmp)

		// accum += q_4 * w_4
		tmp.Mul(&wQ4, &wW4)
		accum.Add(&accum, &tmp)

		// accum += q_c
		accum.Add(&accum, &wQC)

		// accum += (q_arith - 1) * w_4_shift
		tmp.Sub(&qArith, &frOne)
		tmp.Mul(&tmp, &wW4Shift)
		accum.Add(&accum, &tmp)

		// accum *= q_arith
		accum.Mul(&accum, &qArith)

		// accum *= domainSep
		accum.Mul(&accum, domainSep)

		evals[0] = accum
	}

	// Relation 1
	{
		wWL := wire(*p, WireWL)
		wW4 := wire(*p, WireW4)
		wWLShift := wire(*p, WireWLShift)
		wQM := wire(*p, WireQM)

		// accum = w_l + w_4 - w_l_shift + q_m
		var accum, tmp fr.Element
		accum.Add(&wWL, &wW4)
		accum.Sub(&accum, &wWLShift)
		accum.Add(&accum, &wQM)

		// accum *= (q_arith - 2)
		tmp.Sub(&qArith, &frTwo)
		accum.Mul(&accum, &tmp)

		// accum *= (q_arith - 1)
		tmp.Sub(&qArith, &frOne)
		accum.Mul(&accum, &tmp)

		// accum *= q_arith
		accum.Mul(&accum, &qArith)

		// accum *= domainSep
		accum.Mul(&accum, domainSep)

		evals[1] = accum
	}
}

// ---------------------------------------------------------------------------
// Permutation Relation (subrelations 2, 3)
// ---------------------------------------------------------------------------

func accumulatePermutationRelation(
	p *[NumberOfEntities]fr.Element,
	rp *RelationParameters,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	var grandProductNumerator, grandProductDenominator fr.Element

	// Numerator: prod_{i=1..4}( w_i + id_i * beta + gamma )
	{
		wWL := wire(*p, WireWL)
		wWR := wire(*p, WireWR)
		wWO := wire(*p, WireWO)
		wW4 := wire(*p, WireW4)
		id1 := wire(*p, WireID1)
		id2 := wire(*p, WireID2)
		id3 := wire(*p, WireID3)
		id4 := wire(*p, WireID4)

		var num, tmp fr.Element
		// w_l + id_1 * beta + gamma
		tmp.Mul(&id1, &rp.Beta)
		num.Add(&wWL, &tmp)
		num.Add(&num, &rp.Gamma)

		// * (w_r + id_2 * beta + gamma)
		tmp.Mul(&id2, &rp.Beta)
		tmp.Add(&tmp, &wWR)
		tmp.Add(&tmp, &rp.Gamma)
		num.Mul(&num, &tmp)

		// * (w_o + id_3 * beta + gamma)
		tmp.Mul(&id3, &rp.Beta)
		tmp.Add(&tmp, &wWO)
		tmp.Add(&tmp, &rp.Gamma)
		num.Mul(&num, &tmp)

		// * (w_4 + id_4 * beta + gamma)
		tmp.Mul(&id4, &rp.Beta)
		tmp.Add(&tmp, &wW4)
		tmp.Add(&tmp, &rp.Gamma)
		num.Mul(&num, &tmp)

		grandProductNumerator = num
	}

	// Denominator: prod_{i=1..4}( w_i + sigma_i * beta + gamma )
	{
		wWL := wire(*p, WireWL)
		wWR := wire(*p, WireWR)
		wWO := wire(*p, WireWO)
		wW4 := wire(*p, WireW4)
		s1 := wire(*p, WireSigma1)
		s2 := wire(*p, WireSigma2)
		s3 := wire(*p, WireSigma3)
		s4 := wire(*p, WireSigma4)

		var den, tmp fr.Element
		tmp.Mul(&s1, &rp.Beta)
		den.Add(&wWL, &tmp)
		den.Add(&den, &rp.Gamma)

		tmp.Mul(&s2, &rp.Beta)
		tmp.Add(&tmp, &wWR)
		tmp.Add(&tmp, &rp.Gamma)
		den.Mul(&den, &tmp)

		tmp.Mul(&s3, &rp.Beta)
		tmp.Add(&tmp, &wWO)
		tmp.Add(&tmp, &rp.Gamma)
		den.Mul(&den, &tmp)

		tmp.Mul(&s4, &rp.Beta)
		tmp.Add(&tmp, &wW4)
		tmp.Add(&tmp, &rp.Gamma)
		den.Mul(&den, &tmp)

		grandProductDenominator = den
	}

	// Contribution 2
	{
		zPerm := wire(*p, WireZPerm)
		zPermShift := wire(*p, WireZPermShift)
		lagFirst := wire(*p, WireLagrangeFirst)
		lagLast := wire(*p, WireLagrangeLast)

		// acc = (z_perm + lagrange_first) * grand_product_numerator
		var acc, tmp, tmp2 fr.Element
		tmp.Add(&zPerm, &lagFirst)
		acc.Mul(&tmp, &grandProductNumerator)

		// acc -= (z_perm_shift + lagrange_last * public_inputs_delta) * grand_product_denominator
		tmp.Mul(&lagLast, &rp.PublicInputsDelta)
		tmp.Add(&zPermShift, &tmp)
		tmp2.Mul(&tmp, &grandProductDenominator)
		acc.Sub(&acc, &tmp2)

		// acc *= domainSep
		acc.Mul(&acc, domainSep)
		evals[2] = acc
	}

	// Contribution 3
	{
		lagLast := wire(*p, WireLagrangeLast)
		zPermShift := wire(*p, WireZPermShift)

		var acc fr.Element
		acc.Mul(&lagLast, &zPermShift)
		acc.Mul(&acc, domainSep)
		evals[3] = acc
	}
}

// ---------------------------------------------------------------------------
// Log-Derivative Lookup Relation (subrelations 4, 5, 6)
// ---------------------------------------------------------------------------

func accumulateLogDerivativeLookupRelation(
	p *[NumberOfEntities]fr.Element,
	rp *RelationParameters,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	var writeTerm, readTerm fr.Element

	// write_term (table accumulation) = table_1 + gamma + table_2*eta + table_3*etaTwo + table_4*etaThree
	{
		t1 := wire(*p, WireTable1)
		t2 := wire(*p, WireTable2)
		t3 := wire(*p, WireTable3)
		t4 := wire(*p, WireTable4)

		var tmp fr.Element

		writeTerm.Set(&t1)
		writeTerm.Add(&writeTerm, &rp.Gamma)

		tmp.Mul(&t2, &rp.Eta)
		writeTerm.Add(&writeTerm, &tmp)

		tmp.Mul(&t3, &rp.EtaTwo)
		writeTerm.Add(&writeTerm, &tmp)

		tmp.Mul(&t4, &rp.EtaThree)
		writeTerm.Add(&writeTerm, &tmp)
	}

	// read_term = derived_entry_1 + derived_entry_2*eta + derived_entry_3*etaTwo + q_o*etaThree
	// where:
	//   derived_entry_1 = w_l + gamma + q_r * w_l_shift
	//   derived_entry_2 = w_r + q_m * w_r_shift
	//   derived_entry_3 = w_o + q_c * w_o_shift
	{
		wWL := wire(*p, WireWL)
		wWR := wire(*p, WireWR)
		wWO := wire(*p, WireWO)
		wQR := wire(*p, WireQR)
		wQM := wire(*p, WireQM)
		wQC := wire(*p, WireQC)
		wQO := wire(*p, WireQO)
		wWLShift := wire(*p, WireWLShift)
		wWRShift := wire(*p, WireWRShift)
		wWOShift := wire(*p, WireWOShift)

		var tmp, de1, de2, de3 fr.Element

		// derived_entry_1 = w_l + gamma + q_r * w_l_shift
		tmp.Mul(&wQR, &wWLShift)
		de1.Add(&wWL, &rp.Gamma)
		de1.Add(&de1, &tmp)

		// derived_entry_2 = w_r + q_m * w_r_shift
		tmp.Mul(&wQM, &wWRShift)
		de2.Add(&wWR, &tmp)

		// derived_entry_3 = w_o + q_c * w_o_shift
		tmp.Mul(&wQC, &wWOShift)
		de3.Add(&wWO, &tmp)

		// read_term = de1 + de2*eta + de3*etaTwo + q_o*etaThree
		readTerm.Set(&de1)

		tmp.Mul(&de2, &rp.Eta)
		readTerm.Add(&readTerm, &tmp)

		tmp.Mul(&de3, &rp.EtaTwo)
		readTerm.Add(&readTerm, &tmp)

		tmp.Mul(&wQO, &rp.EtaThree)
		readTerm.Add(&readTerm, &tmp)
	}

	lookupInv := wire(*p, WireLookupInverses)
	readCounts := wire(*p, WireLookupReadCounts)
	readTags := wire(*p, WireLookupReadTags)
	qLookup := wire(*p, WireQLookup)

	// read_inverse = LOOKUP_INVERSES * write_term
	var readInverse fr.Element
	readInverse.Mul(&lookupInv, &writeTerm)

	// write_inverse = LOOKUP_INVERSES * read_term
	var writeInverse fr.Element
	writeInverse.Mul(&lookupInv, &readTerm)

	// inverse_exists_xor = read_tags + q_lookup - read_tags * q_lookup
	var inverseExistsXor, tmp fr.Element
	inverseExistsXor.Add(&readTags, &qLookup)
	tmp.Mul(&readTags, &qLookup)
	inverseExistsXor.Sub(&inverseExistsXor, &tmp)

	// Subrelation 4: read_term * write_term * LOOKUP_INVERSES - inverse_exists_xor
	{
		var acc fr.Element
		acc.Mul(&readTerm, &writeTerm)
		acc.Mul(&acc, &lookupInv)
		acc.Sub(&acc, &inverseExistsXor)
		acc.Mul(&acc, domainSep)
		evals[4] = acc
	}

	// Subrelation 5: q_lookup * read_inverse - read_counts * write_inverse
	{
		var acc, tmp2 fr.Element
		acc.Mul(&qLookup, &readInverse)
		tmp2.Mul(&readCounts, &writeInverse)
		acc.Sub(&acc, &tmp2)
		evals[5] = acc
	}

	// Subrelation 6: read_tag * read_tag - read_tag (boolean check)
	{
		var acc fr.Element
		acc.Mul(&readTags, &readTags)
		acc.Sub(&acc, &readTags)
		acc.Mul(&acc, domainSep)
		evals[6] = acc
	}
}

// ---------------------------------------------------------------------------
// Delta-Range Relation (subrelations 7, 8, 9, 10)
// ---------------------------------------------------------------------------

func accumulateDeltaRangeRelation(
	p *[NumberOfEntities]fr.Element,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	// minus constants
	var minusOne, minusTwo, minusThree fr.Element
	minusOne.Neg(&frOne)
	minusTwo.Neg(&frTwo)
	minusThree.Neg(&frThree)

	wWL := wire(*p, WireWL)
	wWR := wire(*p, WireWR)
	wWO := wire(*p, WireWO)
	wW4 := wire(*p, WireW4)
	wWLShift := wire(*p, WireWLShift)
	qRange := wire(*p, WireQRange)

	// delta_1 = w_r - w_l
	var delta1, delta2, delta3, delta4 fr.Element
	delta1.Sub(&wWR, &wWL)
	delta2.Sub(&wWO, &wWR)
	delta3.Sub(&wW4, &wWO)
	delta4.Sub(&wWLShift, &wW4)

	// Helper: compute delta*(delta-1)*(delta-2)*(delta-3) * q_range * domainSep
	computeDeltaContrib := func(delta *fr.Element) fr.Element {
		var acc, tmp fr.Element
		acc.Set(delta)

		tmp.Add(delta, &minusOne) // delta - 1
		acc.Mul(&acc, &tmp)

		tmp.Add(delta, &minusTwo) // delta - 2
		acc.Mul(&acc, &tmp)

		tmp.Add(delta, &minusThree) // delta - 3
		acc.Mul(&acc, &tmp)

		acc.Mul(&acc, &qRange)
		acc.Mul(&acc, domainSep)
		return acc
	}

	evals[7] = computeDeltaContrib(&delta1)
	evals[8] = computeDeltaContrib(&delta2)
	evals[9] = computeDeltaContrib(&delta3)
	evals[10] = computeDeltaContrib(&delta4)
}

// ---------------------------------------------------------------------------
// Elliptic Relation (subrelations 11, 12)
// ---------------------------------------------------------------------------

func accumulateEllipticRelation(
	p *[NumberOfEntities]fr.Element,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	x1 := wire(*p, WireWR)
	y1 := wire(*p, WireWO)
	x2 := wire(*p, WireWLShift)
	y2 := wire(*p, WireW4Shift)
	y3 := wire(*p, WireWOShift)
	x3 := wire(*p, WireWRShift)

	qSign := wire(*p, WireQL)
	qIsDouble := wire(*p, WireQM)
	qElliptic := wire(*p, WireQElliptic)

	// x_diff = x2 - x1
	var xDiff fr.Element
	xDiff.Sub(&x2, &x1)

	// y1_sqr = y1^2
	var y1Sqr fr.Element
	y1Sqr.Mul(&y1, &y1)

	// one_minus_is_double = 1 - q_is_double
	var oneMinusIsDouble fr.Element
	oneMinusIsDouble.Sub(&frOne, &qIsDouble)

	// Contribution 11 (point addition, x-coordinate check):
	// q_elliptic * (1 - q_is_double) * ((x3+x2+x1)*(x2-x1)^2 - y2^2 - y1^2 + 2*y1*y2*q_sign)
	{
		var y2Sqr, y1y2, xAddIdentity, xDiffSqr, tmp fr.Element

		y2Sqr.Mul(&y2, &y2)

		y1y2.Mul(&y1, &y2)
		y1y2.Mul(&y1y2, &qSign) // y1*y2*q_sign

		// x_add_identity = (x3 + x2 + x1) * x_diff^2
		xAddIdentity.Add(&x3, &x2)
		xAddIdentity.Add(&xAddIdentity, &x1)
		xDiffSqr.Mul(&xDiff, &xDiff)
		xAddIdentity.Mul(&xAddIdentity, &xDiffSqr)

		// x_add_identity = x_add_identity - y2^2 - y1^2 + 2*y1y2
		xAddIdentity.Sub(&xAddIdentity, &y2Sqr)
		xAddIdentity.Sub(&xAddIdentity, &y1Sqr)
		tmp.Add(&y1y2, &y1y2) // 2 * y1*y2*q_sign
		xAddIdentity.Add(&xAddIdentity, &tmp)

		// evals[11] = x_add_identity * domainSep * q_elliptic * (1 - q_is_double)
		xAddIdentity.Mul(&xAddIdentity, domainSep)
		xAddIdentity.Mul(&xAddIdentity, &qElliptic)
		xAddIdentity.Mul(&xAddIdentity, &oneMinusIsDouble)
		evals[11] = xAddIdentity
	}

	// Contribution 12 (point addition, y-coordinate check):
	// q_elliptic * (1 - q_is_double) * ((y1+y3)*(x2-x1) + (x3-x1)*(y2*q_sign - y1))
	{
		var y1PlusY3, yDiff, yAddIdentity, tmp fr.Element

		y1PlusY3.Add(&y1, &y3)

		// y_diff = y2*q_sign - y1
		yDiff.Mul(&y2, &qSign)
		yDiff.Sub(&yDiff, &y1)

		// y_add_identity = y1_plus_y3 * x_diff + (x3 - x1) * y_diff
		yAddIdentity.Mul(&y1PlusY3, &xDiff)
		tmp.Sub(&x3, &x1)
		tmp.Mul(&tmp, &yDiff)
		yAddIdentity.Add(&yAddIdentity, &tmp)

		yAddIdentity.Mul(&yAddIdentity, domainSep)
		yAddIdentity.Mul(&yAddIdentity, &qElliptic)
		yAddIdentity.Mul(&yAddIdentity, &oneMinusIsDouble)
		evals[12] = yAddIdentity
	}

	// Contribution 11 doubling (x-coordinate):
	// (x3 + x1 + x1) * 4*y1^2 - 9 * (y1^2 + b_neg) * x1  [where b_neg = 17]
	// then *= domainSep * q_elliptic * q_is_double, add to evals[11]
	{
		// x_pow_4 = (y1^2 + grumpkin_b_neg) * x1
		var xPow4, y1SqrMul4, x1Pow4Mul9, xDoubleIdentity, tmp fr.Element

		xPow4.Add(&y1Sqr, &grumpkinCurveBNeg)
		xPow4.Mul(&xPow4, &x1)

		// y1_sqr_mul_4 = 4 * y1^2
		y1SqrMul4.Add(&y1Sqr, &y1Sqr)
		y1SqrMul4.Add(&y1SqrMul4, &y1SqrMul4)

		// x1_pow_4_mul_9 = 9 * x_pow_4
		x1Pow4Mul9.Mul(&xPow4, &frNine)

		// x_double_identity = (x3 + x1 + x1) * y1_sqr_mul_4 - x1_pow_4_mul_9
		tmp.Add(&x3, &x1)
		tmp.Add(&tmp, &x1)
		xDoubleIdentity.Mul(&tmp, &y1SqrMul4)
		xDoubleIdentity.Sub(&xDoubleIdentity, &x1Pow4Mul9)

		xDoubleIdentity.Mul(&xDoubleIdentity, domainSep)
		xDoubleIdentity.Mul(&xDoubleIdentity, &qElliptic)
		xDoubleIdentity.Mul(&xDoubleIdentity, &qIsDouble)
		evals[11].Add(&evals[11], &xDoubleIdentity)
	}

	// Contribution 12 doubling (y-coordinate):
	// 3*x1^2 * (x1 - x3) - 2*y1*(y1 + y3)
	// then *= domainSep * q_elliptic * q_is_double, add to evals[12]
	{
		// x1_sqr_mul_3 = 3*x1^2
		var x1SqrMul3, yDoubleIdentity, tmp, tmp2 fr.Element

		tmp.Add(&x1, &x1)
		tmp.Add(&tmp, &x1) // 3*x1
		x1SqrMul3.Mul(&tmp, &x1)

		// y_double_identity = x1_sqr_mul_3 * (x1 - x3) - (y1 + y1) * (y1 + y3)
		tmp.Sub(&x1, &x3)
		yDoubleIdentity.Mul(&x1SqrMul3, &tmp)

		tmp.Add(&y1, &y1)   // 2*y1
		tmp2.Add(&y1, &y3)  // y1 + y3
		tmp.Mul(&tmp, &tmp2) // 2*y1 * (y1 + y3)
		yDoubleIdentity.Sub(&yDoubleIdentity, &tmp)

		yDoubleIdentity.Mul(&yDoubleIdentity, domainSep)
		yDoubleIdentity.Mul(&yDoubleIdentity, &qElliptic)
		yDoubleIdentity.Mul(&yDoubleIdentity, &qIsDouble)
		evals[12].Add(&evals[12], &yDoubleIdentity)
	}
}

// ---------------------------------------------------------------------------
// Memory (Auxiliary) Relation (subrelations 13, 14, 15, 16, 17, 18)
// ---------------------------------------------------------------------------

func accumulateMemoryRelation(
	p *[NumberOfEntities]fr.Element,
	rp *RelationParameters,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	// Use rp.EtaTwo, rp.EtaThree from the RelationParameters (already computed)
	eta := rp.Eta
	etaTwo := rp.EtaTwo
	etaThree := rp.EtaThree

	wWL := wire(*p, WireWL)
	wWR := wire(*p, WireWR)
	wWO := wire(*p, WireWO)
	wW4 := wire(*p, WireW4)
	wQC := wire(*p, WireQC)
	wQL := wire(*p, WireQL)
	wQR := wire(*p, WireQR)
	wQO := wire(*p, WireQO)
	wQM := wire(*p, WireQM)
	wQ4 := wire(*p, WireQ4)
	wQMemory := wire(*p, WireQMemory)

	wWLShift := wire(*p, WireWLShift)
	wWRShift := wire(*p, WireWRShift)
	wWOShift := wire(*p, WireWOShift)
	wW4Shift := wire(*p, WireW4Shift)

	// Memory record check:
	// memory_record_check = w_o * eta_three + w_r * eta_two + w_l * eta + q_c
	var memoryRecordCheck, partialRecordCheck, tmp fr.Element
	tmp.Mul(&wWO, &etaThree)
	memoryRecordCheck.Set(&tmp)

	tmp.Mul(&wWR, &etaTwo)
	memoryRecordCheck.Add(&memoryRecordCheck, &tmp)

	tmp.Mul(&wWL, &eta)
	memoryRecordCheck.Add(&memoryRecordCheck, &tmp)

	memoryRecordCheck.Add(&memoryRecordCheck, &wQC)

	partialRecordCheck.Set(&memoryRecordCheck) // save before subtracting w_4

	memoryRecordCheck.Sub(&memoryRecordCheck, &wW4)

	// index_delta = w_l_shift - w_l
	var indexDelta fr.Element
	indexDelta.Sub(&wWLShift, &wWL)

	// record_delta = w_4_shift - w_4
	var recordDelta fr.Element
	recordDelta.Sub(&wW4Shift, &wW4)

	// index_is_monotonically_increasing = index_delta * (index_delta - 1)
	var indexIsMonotonicallyIncreasing fr.Element
	{
		var tmp2 fr.Element
		tmp2.Sub(&indexDelta, &frOne)
		indexIsMonotonicallyIncreasing.Mul(&indexDelta, &tmp2)
	}

	// adjacent_values_match_if_adjacent_indices_match = (-index_delta + 1) * record_delta
	var adjValuesMatch fr.Element
	{
		var negIdxDeltaPlusOne fr.Element
		negIdxDeltaPlusOne.Neg(&indexDelta)
		negIdxDeltaPlusOne.Add(&negIdxDeltaPlusOne, &frOne) // 1 - index_delta
		adjValuesMatch.Mul(&negIdxDeltaPlusOne, &recordDelta)
	}

	// ql_qr = q_l * q_r
	var qlQr fr.Element
	qlQr.Mul(&wQL, &wQR)

	// q_mem_dom = q_memory * domainSep
	var qMemDom fr.Element
	qMemDom.Mul(&wQMemory, domainSep)

	// Subrelation 14: adjacent_values_match * (q_l * q_r) * (q_memory * domainSep)
	{
		var acc fr.Element
		acc.Mul(&adjValuesMatch, &qlQr)
		acc.Mul(&acc, &qMemDom)
		evals[14] = acc
	}

	// Subrelation 15: index_is_monotonically_increasing * (q_l * q_r) * (q_memory * domainSep)
	{
		var acc fr.Element
		acc.Mul(&indexIsMonotonicallyIncreasing, &qlQr)
		acc.Mul(&acc, &qMemDom)
		evals[15] = acc
	}

	// ROM_consistency_check_identity = memory_record_check * (q_l * q_r)
	var romConsistencyCheck fr.Element
	romConsistencyCheck.Mul(&memoryRecordCheck, &qlQr)

	// --- RAM section ---

	// access_type = w_4 - partial_record_check
	var accessType fr.Element
	accessType.Sub(&wW4, &partialRecordCheck)

	// access_check = access_type * (access_type - 1)
	var accessCheck fr.Element
	{
		var tmp2 fr.Element
		tmp2.Sub(&accessType, &frOne)
		accessCheck.Mul(&accessType, &tmp2)
	}

	// next_gate_access_type = w_4_shift - (w_o_shift*eta_three + w_r_shift*eta_two + w_l_shift*eta)
	var nextGateAccessType fr.Element
	{
		tmp.Mul(&wWOShift, &etaThree)
		nextGateAccessType.Set(&tmp)

		tmp.Mul(&wWRShift, &etaTwo)
		nextGateAccessType.Add(&nextGateAccessType, &tmp)

		tmp.Mul(&wWLShift, &eta)
		nextGateAccessType.Add(&nextGateAccessType, &tmp)

		nextGateAccessType.Sub(&wW4Shift, &nextGateAccessType)
	}

	// value_delta = w_o_shift - w_o
	var valueDelta fr.Element
	valueDelta.Sub(&wWOShift, &wWO)

	// adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
	// = (1 - index_delta) * value_delta * (1 - next_gate_access_type)
	var adjValuesMatchRead fr.Element
	{
		var oneMinusIdx, oneMinusAccess fr.Element
		oneMinusIdx.Sub(&frOne, &indexDelta)
		oneMinusAccess.Sub(&frOne, &nextGateAccessType)

		adjValuesMatchRead.Mul(&oneMinusIdx, &valueDelta)
		adjValuesMatchRead.Mul(&adjValuesMatchRead, &oneMinusAccess)
	}

	// next_gate_access_type_is_boolean = next_gate_access_type^2 - next_gate_access_type
	var nextGateAccessTypeIsBool fr.Element
	{
		nextGateAccessTypeIsBool.Mul(&nextGateAccessType, &nextGateAccessType)
		nextGateAccessTypeIsBool.Sub(&nextGateAccessTypeIsBool, &nextGateAccessType)
	}

	// q_o_q_mem_dom = q_o * q_memory * domainSep
	var qoQMemDom fr.Element
	qoQMemDom.Mul(&wQO, &qMemDom)

	// Subrelation 16: adjValuesMatchRead * q_o * (q_memory * domainSep)
	{
		var acc fr.Element
		acc.Mul(&adjValuesMatchRead, &qoQMemDom)
		evals[16] = acc
	}

	// Subrelation 17: indexIsMonotonicallyIncreasing * q_o * (q_memory * domainSep)
	{
		var acc fr.Element
		acc.Mul(&indexIsMonotonicallyIncreasing, &qoQMemDom)
		evals[17] = acc
	}

	// Subrelation 18: nextGateAccessTypeIsBool * q_o * (q_memory * domainSep)
	{
		var acc fr.Element
		acc.Mul(&nextGateAccessTypeIsBool, &qoQMemDom)
		evals[18] = acc
	}

	// RAM_consistency_check_identity = access_check * q_o
	var ramConsistencyCheck fr.Element
	ramConsistencyCheck.Mul(&accessCheck, &wQO)

	// RAM_timestamp_check_identity = (1 - index_delta) * timestamp_delta - w_o
	// where timestamp_delta = w_r_shift - w_r
	var ramTimestampCheck fr.Element
	{
		var timestampDelta, oneMinusIdx fr.Element
		timestampDelta.Sub(&wWRShift, &wWR)

		oneMinusIdx.Sub(&frOne, &indexDelta)
		ramTimestampCheck.Mul(&oneMinusIdx, &timestampDelta)
		ramTimestampCheck.Sub(&ramTimestampCheck, &wWO)
	}

	// Subrelation 13 (the big memory identity):
	// memory_identity = ROM_consistency_check
	//   + RAM_timestamp_check * (q_4 * q_l)
	//   + memory_record_check * (q_m * q_l)
	//   + RAM_consistency_check
	// Then *= (q_memory * domainSep)
	{
		var memoryIdentity fr.Element
		memoryIdentity.Set(&romConsistencyCheck)

		// + RAM_timestamp_check * q_4 * q_l
		var q4ql fr.Element
		q4ql.Mul(&wQ4, &wQL)
		tmp.Mul(&ramTimestampCheck, &q4ql)
		memoryIdentity.Add(&memoryIdentity, &tmp)

		// + memory_record_check * q_m * q_l
		var qmql fr.Element
		qmql.Mul(&wQM, &wQL)
		tmp.Mul(&memoryRecordCheck, &qmql)
		memoryIdentity.Add(&memoryIdentity, &tmp)

		// + RAM_consistency_check
		memoryIdentity.Add(&memoryIdentity, &ramConsistencyCheck)

		// *= (q_memory * domainSep)
		memoryIdentity.Mul(&memoryIdentity, &qMemDom)
		evals[13] = memoryIdentity
	}
}

// ---------------------------------------------------------------------------
// Non-Native Field (NNF) Relation (subrelation 19)
// ---------------------------------------------------------------------------

func accumulateNnfRelation(
	p *[NumberOfEntities]fr.Element,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	wWL := wire(*p, WireWL)
	wWR := wire(*p, WireWR)
	wWO := wire(*p, WireWO)
	wW4 := wire(*p, WireW4)
	wQR := wire(*p, WireQR)
	wQO := wire(*p, WireQO)
	wQM := wire(*p, WireQM)
	wQ4 := wire(*p, WireQ4)
	wQNnf := wire(*p, WireQNnf)

	wWLShift := wire(*p, WireWLShift)
	wWRShift := wire(*p, WireWRShift)
	wWOShift := wire(*p, WireWOShift)
	wW4Shift := wire(*p, WireW4Shift)

	// limb_subproduct = w_l * w_r_shift + w_l_shift * w_r
	var limbSubproduct, tmp, tmp2 fr.Element
	tmp.Mul(&wWL, &wWRShift)
	tmp2.Mul(&wWLShift, &wWR)
	limbSubproduct.Add(&tmp, &tmp2)

	// non_native_field_gate_2 = (w_l*w_4 + w_r*w_o - w_o_shift) * LIMB_SIZE - w_4_shift + limb_subproduct
	// then *= q_4
	var nnfGate2 fr.Element
	{
		var a fr.Element
		a.Mul(&wWL, &wW4)
		tmp.Mul(&wWR, &wWO)
		a.Add(&a, &tmp)
		a.Sub(&a, &wWOShift)

		a.Mul(&a, &limbSize)
		a.Sub(&a, &wW4Shift)
		a.Add(&a, &limbSubproduct)
		nnfGate2.Mul(&a, &wQ4)
	}

	// Update limb_subproduct: limb_subproduct = limb_subproduct * LIMB_SIZE + w_l_shift * w_r_shift
	limbSubproduct.Mul(&limbSubproduct, &limbSize)
	tmp.Mul(&wWLShift, &wWRShift)
	limbSubproduct.Add(&limbSubproduct, &tmp)

	// non_native_field_gate_1 = (limb_subproduct - (w_o + w_4)) * q_o
	var nnfGate1 fr.Element
	{
		var a fr.Element
		a.Add(&wWO, &wW4)
		nnfGate1.Sub(&limbSubproduct, &a)
		nnfGate1.Mul(&nnfGate1, &wQO)
	}

	// non_native_field_gate_3 = (limb_subproduct + w_4 - (w_o_shift + w_4_shift)) * q_m
	var nnfGate3 fr.Element
	{
		var a fr.Element
		a.Add(&limbSubproduct, &wW4)
		tmp.Add(&wWOShift, &wW4Shift)
		a.Sub(&a, &tmp)
		nnfGate3.Mul(&a, &wQM)
	}

	// non_native_field_identity = (gate_1 + gate_2 + gate_3) * q_r
	var nnfIdentity fr.Element
	nnfIdentity.Add(&nnfGate1, &nnfGate2)
	nnfIdentity.Add(&nnfIdentity, &nnfGate3)
	nnfIdentity.Mul(&nnfIdentity, &wQR)

	// Limb accumulator 1:
	// ((((w_r_shift * 2^14 + w_l_shift) * 2^14 + w_o) * 2^14 + w_r) * 2^14 + w_l - w_4) * q_4
	var limbAccum1 fr.Element
	{
		limbAccum1.Mul(&wWRShift, &sublimbShift)
		limbAccum1.Add(&limbAccum1, &wWLShift)
		limbAccum1.Mul(&limbAccum1, &sublimbShift)
		limbAccum1.Add(&limbAccum1, &wWO)
		limbAccum1.Mul(&limbAccum1, &sublimbShift)
		limbAccum1.Add(&limbAccum1, &wWR)
		limbAccum1.Mul(&limbAccum1, &sublimbShift)
		limbAccum1.Add(&limbAccum1, &wWL)
		limbAccum1.Sub(&limbAccum1, &wW4)
		limbAccum1.Mul(&limbAccum1, &wQ4)
	}

	// Limb accumulator 2:
	// ((((w_o_shift * 2^14 + w_r_shift) * 2^14 + w_l_shift) * 2^14 + w_4) * 2^14 + w_o - w_4_shift) * q_m
	var limbAccum2 fr.Element
	{
		limbAccum2.Mul(&wWOShift, &sublimbShift)
		limbAccum2.Add(&limbAccum2, &wWRShift)
		limbAccum2.Mul(&limbAccum2, &sublimbShift)
		limbAccum2.Add(&limbAccum2, &wWLShift)
		limbAccum2.Mul(&limbAccum2, &sublimbShift)
		limbAccum2.Add(&limbAccum2, &wW4)
		limbAccum2.Mul(&limbAccum2, &sublimbShift)
		limbAccum2.Add(&limbAccum2, &wWO)
		limbAccum2.Sub(&limbAccum2, &wW4Shift)
		limbAccum2.Mul(&limbAccum2, &wQM)
	}

	// limb_accumulator_identity = (limbAccum1 + limbAccum2) * q_o
	var limbAccumIdentity fr.Element
	limbAccumIdentity.Add(&limbAccum1, &limbAccum2)
	limbAccumIdentity.Mul(&limbAccumIdentity, &wQO)

	// nnf_identity = (nnfIdentity + limbAccumIdentity) * (q_nnf * domainSep)
	var result fr.Element
	result.Add(&nnfIdentity, &limbAccumIdentity)
	tmp.Mul(&wQNnf, domainSep)
	result.Mul(&result, &tmp)

	evals[19] = result
}

// ---------------------------------------------------------------------------
// Poseidon2 External Relation (subrelations 20, 21, 22, 23)
// ---------------------------------------------------------------------------

func accumulatePoseidon2ExternalRelation(
	p *[NumberOfEntities]fr.Element,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	wWL := wire(*p, WireWL)
	wWR := wire(*p, WireWR)
	wWO := wire(*p, WireWO)
	wW4 := wire(*p, WireW4)
	wQL := wire(*p, WireQL)
	wQR := wire(*p, WireQR)
	wQO := wire(*p, WireQO)
	wQ4 := wire(*p, WireQ4)
	qPosExt := wire(*p, WireQPoseidon2External)

	wWLShift := wire(*p, WireWLShift)
	wWRShift := wire(*p, WireWRShift)
	wWOShift := wire(*p, WireWOShift)
	wW4Shift := wire(*p, WireW4Shift)

	// s_i = w_i + q_i (add round constants)
	var s1, s2, s3, s4 fr.Element
	s1.Add(&wWL, &wQL)
	s2.Add(&wWR, &wQR)
	s3.Add(&wWO, &wQO)
	s4.Add(&wW4, &wQ4)

	// u_i = s_i^5
	pow5 := func(s *fr.Element) fr.Element {
		var s2v, s4v, s5v fr.Element
		s2v.Mul(s, s)
		s4v.Mul(&s2v, &s2v)
		s5v.Mul(&s4v, s)
		return s5v
	}

	u1 := pow5(&s1)
	u2 := pow5(&s2)
	u3 := pow5(&s3)
	u4 := pow5(&s4)

	// Matrix multiplication: v = M_E * u (MDS matrix with 14 additions)
	var t0, t1, t2, t3, v1, v2, v3, v4 fr.Element

	// t0 = u1 + u2
	t0.Add(&u1, &u2)

	// t1 = u3 + u4
	t1.Add(&u3, &u4)

	// t2 = 2*u2 + t1
	t2.Add(&u2, &u2)
	t2.Add(&t2, &t1)

	// t3 = 2*u4 + t0
	t3.Add(&u4, &u4)
	t3.Add(&t3, &t0)

	// v4 = 4*t1 + t3 = 4*(u3+u4) + (2*u4+u1+u2)
	v4.Add(&t1, &t1)
	v4.Add(&v4, &v4) // 4*t1
	v4.Add(&v4, &t3)

	// v2 = 4*t0 + t2 = 4*(u1+u2) + (2*u2+u3+u4)
	v2.Add(&t0, &t0)
	v2.Add(&v2, &v2) // 4*t0
	v2.Add(&v2, &t2)

	// v1 = t3 + v2
	v1.Add(&t3, &v2)

	// v3 = t2 + v4
	v3.Add(&t2, &v4)

	// q_pos_by_scaling = q_poseidon2_external * domainSep
	var qPosByScaling fr.Element
	qPosByScaling.Mul(&qPosExt, domainSep)

	// evals[20] += q_pos_by_scaling * (v1 - w_l_shift)
	{
		var diff, contrib fr.Element
		diff.Sub(&v1, &wWLShift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[20].Add(&evals[20], &contrib)
	}

	// evals[21] += q_pos_by_scaling * (v2 - w_r_shift)
	{
		var diff, contrib fr.Element
		diff.Sub(&v2, &wWRShift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[21].Add(&evals[21], &contrib)
	}

	// evals[22] += q_pos_by_scaling * (v3 - w_o_shift)
	{
		var diff, contrib fr.Element
		diff.Sub(&v3, &wWOShift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[22].Add(&evals[22], &contrib)
	}

	// evals[23] += q_pos_by_scaling * (v4 - w_4_shift)
	{
		var diff, contrib fr.Element
		diff.Sub(&v4, &wW4Shift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[23].Add(&evals[23], &contrib)
	}
}

// ---------------------------------------------------------------------------
// Poseidon2 Internal Relation (subrelations 24, 25, 26, 27)
// ---------------------------------------------------------------------------

func accumulatePoseidon2InternalRelation(
	p *[NumberOfEntities]fr.Element,
	evals *[NumberOfSubrelations]fr.Element,
	domainSep *fr.Element,
) {
	wWL := wire(*p, WireWL)
	wWR := wire(*p, WireWR)
	wWO := wire(*p, WireWO)
	wW4 := wire(*p, WireW4)
	wQL := wire(*p, WireQL)
	qPosInt := wire(*p, WireQPoseidon2Internal)

	wWLShift := wire(*p, WireWLShift)
	wWRShift := wire(*p, WireWRShift)
	wWOShift := wire(*p, WireWOShift)
	wW4Shift := wire(*p, WireW4Shift)

	// s1 = w_l + q_l (add round constant to first element only)
	var s1 fr.Element
	s1.Add(&wWL, &wQL)

	// u1 = s1^5
	var u1 fr.Element
	{
		var s2v, s4v fr.Element
		s2v.Mul(&s1, &s1)
		s4v.Mul(&s2v, &s2v)
		u1.Mul(&s4v, &s1)
	}

	// u2..u4 are just the wire values (no S-box for internal rounds)
	u2 := wWR
	u3 := wWO
	u4 := wW4

	// u_sum = u1 + u2 + u3 + u4
	var uSum fr.Element
	uSum.Add(&u1, &u2)
	uSum.Add(&uSum, &u3)
	uSum.Add(&uSum, &u4)

	// q_pos_by_scaling = q_poseidon2_internal * domainSep
	var qPosByScaling fr.Element
	qPosByScaling.Mul(&qPosInt, domainSep)

	// v_i = u_i * diag[i] + u_sum
	// evals[24+i] += q_pos_by_scaling * (v_i - w_i_shift)

	// v1 = u1 * diag[0] + u_sum
	{
		var v1, diff, contrib fr.Element
		v1.Mul(&u1, &internalMatrixDiag[0])
		v1.Add(&v1, &uSum)
		diff.Sub(&v1, &wWLShift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[24].Add(&evals[24], &contrib)
	}

	// v2 = u2 * diag[1] + u_sum
	{
		var v2, diff, contrib fr.Element
		v2.Mul(&u2, &internalMatrixDiag[1])
		v2.Add(&v2, &uSum)
		diff.Sub(&v2, &wWRShift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[25].Add(&evals[25], &contrib)
	}

	// v3 = u3 * diag[2] + u_sum
	{
		var v3, diff, contrib fr.Element
		v3.Mul(&u3, &internalMatrixDiag[2])
		v3.Add(&v3, &uSum)
		diff.Sub(&v3, &wWOShift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[26].Add(&evals[26], &contrib)
	}

	// v4 = u4 * diag[3] + u_sum
	{
		var v4, diff, contrib fr.Element
		v4.Mul(&u4, &internalMatrixDiag[3])
		v4.Add(&v4, &uSum)
		diff.Sub(&v4, &wW4Shift)
		contrib.Mul(&qPosByScaling, &diff)
		evals[27].Add(&evals[27], &contrib)
	}
}
