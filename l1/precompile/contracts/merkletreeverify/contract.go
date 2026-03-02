package merkletreeverify

import (
	_ "embed"
	"fmt"
	"math/big"

	"github.com/ava-labs/libevm/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
	"github.com/sincerin/l1/crypto/smt"
	"github.com/sincerin/l1/precompile/contract"
)

//go:embed contract.abi
var MerkleTreeVerifyRawABI string

var MerkleTreeVerifyABI = contract.ParseABI(MerkleTreeVerifyRawABI)

// MerkleTreeVerifyPrecompile is the stateful precompile contract singleton.
var MerkleTreeVerifyPrecompile contract.StatefulPrecompiledContract = createMerkleTreeVerifyPrecompile()

func merkleTreeVerify(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	remainingGas, err = contract.DeductGas(suppliedGas, GasMerkleTreeVerify)
	if err != nil {
		return nil, 0, err
	}

	// Unpack ABI input: verify(bytes32, bytes32, uint256, bytes32[32], bytes32)
	res, err := MerkleTreeVerifyABI.UnpackInput("verify", input, false)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to unpack input: %w", err)
	}
	if len(res) != 5 {
		return nil, remainingGas, fmt.Errorf("expected 5 arguments, got %d", len(res))
	}

	proofHashRaw, ok := res[0].([32]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid proofHash argument type")
	}
	metadataRaw, ok := res[1].([32]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid metadata argument type")
	}
	leafIndexBig, ok := res[2].(*big.Int)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid leafIndex argument type")
	}
	merkleProofRaw, ok := res[3].([32][32]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid merkleProof argument type")
	}
	rootRaw, ok := res[4].([32]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid root argument type")
	}

	// Convert to field elements
	var proofHash, metadata fr.Element
	proofHash.SetBytes(proofHashRaw[:])
	metadata.SetBytes(metadataRaw[:])

	// Compute leaf = Poseidon2Hash(proofHash, metadata)
	leaf := poseidon2.Hash2(proofHash, metadata)

	leafIndex := leafIndexBig.Uint64()

	// Convert merkle proof to [32]fr.Element
	var merkleProof [smt.TreeDepth]fr.Element
	for i := 0; i < smt.TreeDepth; i++ {
		merkleProof[i].SetBytes(merkleProofRaw[i][:])
	}

	// Convert root
	var root fr.Element
	root.SetBytes(rootRaw[:])

	// Verify
	valid := smt.VerifyProof(leaf, leafIndex, merkleProof, root)

	// Pack output: returns (bool valid)
	packed, err := MerkleTreeVerifyABI.PackOutput("verify", valid)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}

	return packed, remainingGas, nil
}

func createMerkleTreeVerifyPrecompile() contract.StatefulPrecompiledContract {
	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"verify": merkleTreeVerify,
	}

	functions := make([]*contract.StatefulPrecompileFunction, 0, len(abiFunctionMap))
	for name, function := range abiFunctionMap {
		method, ok := MerkleTreeVerifyABI.Methods[name]
		if !ok {
			panic(fmt.Errorf("method (%s) not found in ABI", name))
		}
		functions = append(functions, contract.NewStatefulPrecompileFunction(method.ID, function))
	}

	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}
