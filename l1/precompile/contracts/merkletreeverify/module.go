package merkletreeverify

import (
	"github.com/ava-labs/libevm/common"
)

// ContractAddress is the address of the MerkleTreeVerify precompile.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000005")

// GasMerkleTreeVerify is the fixed gas cost for verifying Merkle inclusion.
const GasMerkleTreeVerify uint64 = 300
