package merkletreeinsert

import (
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/sincerin/l1/precompile/contract"
	"github.com/sincerin/l1/precompile/modules"
	"github.com/sincerin/l1/precompile/precompileconfig"
)

// ContractAddress is the address of the MerkleTreeInsert precompile.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000004")

// GasMerkleTreeInsert is the fixed gas cost for inserting a proof hash into the registry tree.
const GasMerkleTreeInsert uint64 = 500

// Module is the subnet-evm module for the MerkleTreeInsert precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     MerkleTreeInsertPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	_, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("expected config type %T, got %T", &Config{}, cfg)
	}
	return nil
}
