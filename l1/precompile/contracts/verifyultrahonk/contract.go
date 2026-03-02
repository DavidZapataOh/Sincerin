package verifyultrahonk

import (
	_ "embed"
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/sincerin/l1/precompile/contract"
)

//go:embed contract.abi
var VerifyUltraHonkRawABI string

var VerifyUltraHonkABI = contract.ParseABI(VerifyUltraHonkRawABI)

// VerifyUltraHonkPrecompile is the stateful precompile contract singleton.
var VerifyUltraHonkPrecompile contract.StatefulPrecompiledContract = createVerifyUltraHonkPrecompile()

func verifyUltraHonk(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	// Deduct gas
	remainingGas, err = contract.DeductGas(suppliedGas, GasVerifyUltraHonk)
	if err != nil {
		return nil, 0, err
	}

	// Unpack ABI input: verify(bytes proof, bytes vk, bytes32[] publicInputs)
	res, err := VerifyUltraHonkABI.UnpackInput("verify", input, false)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to unpack input: %w", err)
	}
	if len(res) != 3 {
		return nil, remainingGas, fmt.Errorf("expected 3 arguments, got %d", len(res))
	}

	proofBytes, ok := res[0].([]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid proof argument type")
	}
	vkBytes, ok := res[1].([]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid vk argument type")
	}
	pubInputsRaw, ok := res[2].([][32]byte)
	if !ok {
		return nil, remainingGas, fmt.Errorf("invalid publicInputs argument type")
	}

	// Convert public inputs from [32]byte to fr.Element
	pubInputs := make([]fr.Element, len(pubInputsRaw))
	for i, raw := range pubInputsRaw {
		pubInputs[i].SetBytes(raw[:])
	}

	// Run verification
	valid, err := Verify(proofBytes, vkBytes, pubInputs)
	if err != nil {
		// Verification errors are not EVM errors - they just mean the proof is invalid
		valid = false
	}

	// Pack output: returns (bool valid)
	packed, err := VerifyUltraHonkABI.PackOutput("verify", valid)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}

	return packed, remainingGas, nil
}

func createVerifyUltraHonkPrecompile() contract.StatefulPrecompiledContract {
	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"verify": verifyUltraHonk,
	}

	functions := make([]*contract.StatefulPrecompileFunction, 0, len(abiFunctionMap))
	for name, function := range abiFunctionMap {
		method, ok := VerifyUltraHonkABI.Methods[name]
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
