// Package benchmark provides comparative benchmarks between Sincerin's native
// precompiles and equivalent operations executed in the EVM interpreter.
package benchmark

import (
	_ "embed"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/state"
	"github.com/ava-labs/libevm/core/types"
	"github.com/sincerin/l1/core/vm/runtime"
	"github.com/sincerin/l1/params"
)

//go:embed poseidon2_yul.hex
var poseidon2YulHex string

// poseidon2YulBytecode is the deployed runtime bytecode of the Poseidon2 Yul contract
// from github.com/zemse/poseidon2-evm (BN254, t=4, Rf=8, Rp=56).
// Identical parameters to Sincerin's crypto/poseidon2 and Noir/Barretenberg.
var poseidon2YulBytecode []byte

// contractAddr is a fixed address for deploying test contracts in the EVM.
var contractAddr = common.HexToAddress("0x1000000000000000000000000000000000000001")

func init() {
	trimmed := strings.TrimSpace(poseidon2YulHex)
	var err error
	poseidon2YulBytecode, err = hex.DecodeString(trimmed)
	if err != nil {
		panic("failed to decode poseidon2 yul bytecode: " + err.Error())
	}
}

// EVMResult holds the results of an EVM execution.
type EVMResult struct {
	Output    []byte
	GasUsed   uint64
	WallClock time.Duration
	Err       error
}

// NewEVMState creates a fresh in-memory statedb with the Poseidon2 Yul contract deployed.
func NewEVMState() *state.StateDB {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	statedb.CreateAccount(contractAddr)
	statedb.SetCode(contractAddr, poseidon2YulBytecode)
	// Give the contract some balance to ensure it's not considered empty
	statedb.SetBalance(contractAddr, common.U2560)
	return statedb
}

// RunPoseidon2InEVM calls the deployed Poseidon2 Yul contract with the given calldata
// and returns the output, gas used, and wall-clock time.
func RunPoseidon2InEVM(statedb *state.StateDB, calldata []byte, gasLimit uint64) EVMResult {
	random := common.Hash{1} // non-nil Random signals post-merge (required for Shanghai/PUSH0)
	cfg := &runtime.Config{
		ChainConfig: params.TestChainConfig,
		GasLimit:    gasLimit,
		State:       statedb,
		Random:      &random,
	}

	start := time.Now()
	ret, leftOverGas, err := runtime.Call(contractAddr, calldata, cfg)
	elapsed := time.Since(start)

	return EVMResult{
		Output:    ret,
		GasUsed:   gasLimit - leftOverGas,
		WallClock: elapsed,
		Err:       err,
	}
}

// EncodeHash2Calldata encodes a call to the Poseidon2 Yul contract for hash_2.
// Format: 4 dummy bytes (selector, ignored by contract) + uint256(a) + uint256(b)
// The contract determines hash_2 from calldatasize = 68.
func EncodeHash2Calldata(a, b *big.Int) []byte {
	data := make([]byte, 68) // 4 + 32 + 32
	// bytes 0-3: dummy selector (zeros are fine)
	// bytes 4-35: a as big-endian uint256
	aBytes := a.Bytes()
	copy(data[4+32-len(aBytes):36], aBytes)
	// bytes 36-67: b as big-endian uint256
	bBytes := b.Bytes()
	copy(data[36+32-len(bBytes):68], bBytes)
	return data
}
