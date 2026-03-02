package merkletreeinsert

import (
	"github.com/ava-labs/libevm/common"
)

// ContractAddress is the address of the MerkleTreeInsert precompile.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000004")

// GasMerkleTreeInsert is the fixed gas cost for inserting a proof hash into the registry tree.
const GasMerkleTreeInsert uint64 = 500
