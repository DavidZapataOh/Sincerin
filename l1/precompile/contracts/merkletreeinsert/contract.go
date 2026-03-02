package merkletreeinsert

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
var MerkleTreeInsertRawABI string

var MerkleTreeInsertABI = contract.ParseABI(MerkleTreeInsertRawABI)

// GlobalSMT is the singleton Sparse Merkle Tree instance.
// For MVP, this is in-memory. Post-MVP, it would be backed by EVM storage.
var GlobalSMT = smt.New()

// MerkleTreeInsertPrecompile is the stateful precompile contract singleton.
var MerkleTreeInsertPrecompile contract.StatefulPrecompiledContract = createMerkleTreeInsertPrecompile()

func merkleTreeInsert(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("merkleTreeInsert is not allowed in read-only mode")
	}

	remainingGas, err = contract.DeductGas(suppliedGas, GasMerkleTreeInsert)
	if err != nil {
		return nil, 0, err
	}

	// Unpack ABI input: insert(bytes32 proofHash, bytes32 metadata)
	res, err := MerkleTreeInsertABI.UnpackInput("insert", input, false)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to unpack input: %w", err)
	}
	if len(res) != 2 {
		return nil, remainingGas, fmt.Errorf("expected 2 arguments, got %d", len(res))
	}

	proofHashRaw, ok := res[0].([32]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid proofHash argument type")
	}
	metadataRaw, ok := res[1].([32]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid metadata argument type")
	}

	// Convert to field elements
	var proofHash, metadata fr.Element
	proofHash.SetBytes(proofHashRaw[:])
	metadata.SetBytes(metadataRaw[:])

	// Compute leaf = Poseidon2Hash(proofHash, metadata)
	leaf := poseidon2.Hash2(proofHash, metadata)

	// Insert into the global SMT
	newRoot, leafIndex, err := GlobalSMT.Insert(leaf)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("insert failed: %w", err)
	}

	// Convert root to [32]byte
	rootBytes := newRoot.Bytes()
	var rootArr [32]byte
	copy(rootArr[:], rootBytes[:])

	// Convert leaf index to *big.Int for ABI encoding
	leafIndexBig := new(big.Int).SetUint64(leafIndex)

	// Pack output: returns (bytes32 newRoot, uint256 leafIndex)
	packed, err := MerkleTreeInsertABI.PackOutput("insert", rootArr, leafIndexBig)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}

	return packed, remainingGas, nil
}

func createMerkleTreeInsertPrecompile() contract.StatefulPrecompiledContract {
	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"insert": merkleTreeInsert,
	}

	functions := make([]*contract.StatefulPrecompileFunction, 0, len(abiFunctionMap))
	for name, function := range abiFunctionMap {
		method, ok := MerkleTreeInsertABI.Methods[name]
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
