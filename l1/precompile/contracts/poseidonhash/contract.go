package poseidonhash

import (
	_ "embed"
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/crypto/poseidon2"
	"github.com/sincerin/l1/precompile/contract"
)

//go:embed contract.abi
var PoseidonHashRawABI string

var PoseidonHashABI = contract.ParseABI(PoseidonHashRawABI)

// PoseidonHashPrecompile is the stateful precompile contract singleton.
var PoseidonHashPrecompile contract.StatefulPrecompiledContract = createPoseidonHashPrecompile()

// MaxInputs is the maximum number of field elements that can be hashed.
const MaxInputs = 16

func poseidonHash(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	// Unpack ABI input: hash(bytes32[])
	res, err := PoseidonHashABI.UnpackInput("hash", input, false)
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("failed to unpack input: %w", err)
	}
	if len(res) != 1 {
		return nil, suppliedGas, fmt.Errorf("expected 1 argument, got %d", len(res))
	}

	inputsRaw, ok := res[0].([][32]byte)
	if !ok {
		return nil, suppliedGas, fmt.Errorf("invalid inputs argument type")
	}

	numInputs := len(inputsRaw)
	if numInputs < 1 || numInputs > MaxInputs {
		return nil, suppliedGas, fmt.Errorf("num_inputs must be 1-%d, got %d", MaxInputs, numInputs)
	}

	// Calculate and deduct dynamic gas: base + perExtra * (n-1)
	gasCost := GasPoseidonHashBase
	if numInputs > 1 {
		gasCost += GasPoseidonHashPerExtra * uint64(numInputs-1)
	}
	remainingGas, err = contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	// Convert to field elements
	elements := make([]fr.Element, numInputs)
	for i := 0; i < numInputs; i++ {
		elements[i].SetBytes(inputsRaw[i][:])
	}

	// Hash using optimized paths for 2 and 3 inputs
	var result fr.Element
	switch numInputs {
	case 1:
		result = poseidon2.HashN(elements)
	case 2:
		result = poseidon2.Hash2(elements[0], elements[1])
	case 3:
		result = poseidon2.Hash3(elements[0], elements[1], elements[2])
	default:
		result = poseidon2.HashN(elements)
	}

	// Convert result to bytes32
	resultBytes := result.Bytes()
	var resultArr [32]byte
	copy(resultArr[:], resultBytes[:])

	// Pack output
	packed, err := PoseidonHashABI.PackOutput("hash", resultArr)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}

	return packed, remainingGas, nil
}

func createPoseidonHashPrecompile() contract.StatefulPrecompiledContract {
	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"hash": poseidonHash,
	}

	functions := make([]*contract.StatefulPrecompileFunction, 0, len(abiFunctionMap))
	for name, function := range abiFunctionMap {
		method, ok := PoseidonHashABI.Methods[name]
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
