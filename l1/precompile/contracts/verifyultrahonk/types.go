package verifyultrahonk

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// UltraHonk ZK verification constants matching Barretenberg 4.0 / bb EVM target.
const (
	ConstProofSizeLogN            = 28
	NumberOfSubrelations          = 28
	BatchedRelationPartialLength  = 8
	ZKBatchedRelationPartialLen   = 9
	NumberOfEntities              = 41
	NumMaskingPolynomials         = 1
	NumberOfEntitiesZK            = NumberOfEntities + NumMaskingPolynomials // 42
	NumberUnshifted               = 36
	NumberUnshiftedZK             = NumberUnshifted + NumMaskingPolynomials // 37
	NumberToBeShifted             = 5
	PairingPointsSize             = 16
	NumberOfAlphas                = NumberOfSubrelations - 1 // 27
	SubgroupSize                  = 256
	LibraEvaluations              = 4
	LibraCommitments              = 3
	LibraUnivariatesLength        = 9
	ShiftedCommitmentsStart       = 30 // index of w1 in the MSM commitment array
	FieldElementSize              = 32
	GroupElementSize              = 64
)

// Wire indices into sumcheckEvaluations (after skipping masking poly at index 0).
const (
	WireQM = iota
	WireQC
	WireQL
	WireQR
	WireQO
	WireQ4
	WireQLookup
	WireQArith
	WireQRange
	WireQElliptic
	WireQMemory
	WireQNnf
	WireQPoseidon2External
	WireQPoseidon2Internal
	WireSigma1
	WireSigma2
	WireSigma3
	WireSigma4
	WireID1
	WireID2
	WireID3
	WireID4
	WireTable1
	WireTable2
	WireTable3
	WireTable4
	WireLagrangeFirst
	WireLagrangeLast
	WireWL
	WireWR
	WireWO
	WireW4
	WireZPerm
	WireLookupInverses
	WireLookupReadCounts
	WireLookupReadTags
	WireWLShift
	WireWRShift
	WireWOShift
	WireW4Shift
	WireZPermShift
)

// VerificationKey represents a deserialized UltraHonk verification key.
type VerificationKey struct {
	CircuitSize      uint64
	LogCircuitSize   uint64
	PublicInputsSize uint64
	PubInputsOffset  uint64

	// 28 G1 commitment points (order matches Solidity HonkVerificationKey)
	Qm                 bn254.G1Affine
	Qc                 bn254.G1Affine
	Ql                 bn254.G1Affine
	Qr                 bn254.G1Affine
	Qo                 bn254.G1Affine
	Q4                 bn254.G1Affine
	QLookup            bn254.G1Affine
	QArith             bn254.G1Affine
	QDeltaRange        bn254.G1Affine
	QElliptic          bn254.G1Affine
	QMemory            bn254.G1Affine
	QNnf               bn254.G1Affine
	QPoseidon2External bn254.G1Affine
	QPoseidon2Internal bn254.G1Affine
	S1                 bn254.G1Affine
	S2                 bn254.G1Affine
	S3                 bn254.G1Affine
	S4                 bn254.G1Affine
	ID1                bn254.G1Affine
	ID2                bn254.G1Affine
	ID3                bn254.G1Affine
	ID4                bn254.G1Affine
	T1                 bn254.G1Affine
	T2                 bn254.G1Affine
	T3                 bn254.G1Affine
	T4                 bn254.G1Affine
	LagrangeFirst      bn254.G1Affine
	LagrangeLast       bn254.G1Affine
}

// VKCommitments returns all 28 commitments as a slice in entity order.
func (vk *VerificationKey) VKCommitments() [28]bn254.G1Affine {
	return [28]bn254.G1Affine{
		vk.Qm, vk.Qc, vk.Ql, vk.Qr, vk.Qo, vk.Q4,
		vk.QLookup, vk.QArith, vk.QDeltaRange, vk.QElliptic,
		vk.QMemory, vk.QNnf, vk.QPoseidon2External, vk.QPoseidon2Internal,
		vk.S1, vk.S2, vk.S3, vk.S4,
		vk.ID1, vk.ID2, vk.ID3, vk.ID4,
		vk.T1, vk.T2, vk.T3, vk.T4,
		vk.LagrangeFirst, vk.LagrangeLast,
	}
}

// ZKProof represents a deserialized UltraHonk ZK proof (EVM format).
type ZKProof struct {
	PairingPointObject [PairingPointsSize]fr.Element

	// ZK: Gemini masking polynomial commitment
	GeminiMaskingPoly bn254.G1Affine

	// Wire commitments
	W1 bn254.G1Affine
	W2 bn254.G1Affine
	W3 bn254.G1Affine
	W4 bn254.G1Affine

	// Lookup/permutation commitments
	LookupReadCounts bn254.G1Affine
	LookupReadTags   bn254.G1Affine
	LookupInverses   bn254.G1Affine
	ZPerm            bn254.G1Affine

	// Libra commitments (ZK)
	LibraCommitments [3]bn254.G1Affine
	LibraSum         fr.Element

	// Sumcheck: logN rounds of ZK_BATCHED_RELATION_PARTIAL_LENGTH univariate values
	SumcheckUnivariates [][]fr.Element // [logN][ZKBatchedRelationPartialLen]

	// Libra evaluation (after sumcheck evals)
	LibraEvaluation fr.Element

	// Sumcheck evaluations: NUMBER_OF_ENTITIES_ZK elements
	// Index 0 = gemini_masking_poly eval, indices 1..41 = normal entities
	SumcheckEvaluations [NumberOfEntitiesZK]fr.Element

	// Gemini fold commitments: logN-1 G1 points
	GeminiFoldComms []bn254.G1Affine

	// Gemini A evaluations: logN scalars
	GeminiAEvaluations []fr.Element

	// Libra polynomial evaluations (ZK): 4 scalars
	LibraPolyEvals [4]fr.Element

	// Shplonk quotient and KZG quotient
	ShplonkQ    bn254.G1Affine
	KzgQuotient bn254.G1Affine
}

// ProofWitnessCommitments returns the 8 witness G1 commitments (+ geminiMaskingPoly).
func (p *ZKProof) ProofWitnessCommitments() [9]bn254.G1Affine {
	return [9]bn254.G1Affine{
		p.GeminiMaskingPoly,
		p.W1, p.W2, p.W3, p.W4,
		p.LookupReadCounts, p.LookupReadTags,
		p.LookupInverses, p.ZPerm,
	}
}

// RelationParameters holds the transcript challenges needed for relation evaluation.
type RelationParameters struct {
	Eta              fr.Element
	EtaTwo           fr.Element
	EtaThree         fr.Element
	Beta             fr.Element
	Gamma            fr.Element
	PublicInputsDelta fr.Element
}

// Transcript holds all Fiat-Shamir challenges.
type Transcript struct {
	RelationParams RelationParameters
	Alphas         [NumberOfAlphas]fr.Element
	GateChallenges [ConstProofSizeLogN]fr.Element
	LibraChallenge fr.Element
	SumcheckU      [ConstProofSizeLogN]fr.Element
	Rho            fr.Element
	GeminiR        fr.Element
	ShplonkNu      fr.Element
	ShplonkZ       fr.Element
}

// BN254 scalar field modulus.
var (
	ScalarFieldModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// Subgroup generator for UltraHonk (256th root of unity).
	SubgroupGenerator    fr.Element
	SubgroupGeneratorInv fr.Element
)

func init() {
	SubgroupGenerator.SetString("0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76")
	SubgroupGeneratorInv.SetString("0x204bd3277422fad364751ad938e2b5e6a54cf8c68712848a692c553d0329f5d6")
}
