package poseidonhash

import (
	"github.com/ava-labs/libevm/common"
)

// ContractAddress is the address of the PoseidonHash precompile.
// Inspired by EIP-5988 (stagnant in Ethereum).
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000003")

// GasPoseidonHashBase is the base gas cost for a Poseidon hash.
const GasPoseidonHashBase uint64 = 200

// GasPoseidonHashPerExtra is the additional gas per input beyond the first.
const GasPoseidonHashPerExtra uint64 = 50
