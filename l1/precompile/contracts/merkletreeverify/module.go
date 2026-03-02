package merkletreeverify

import (
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/sincerin/l1/precompile/contract"
	"github.com/sincerin/l1/precompile/modules"
	"github.com/sincerin/l1/precompile/precompileconfig"
)

// ContractAddress is the address of the MerkleTreeVerify precompile.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000005")

// GasMerkleTreeVerify is the fixed gas cost for verifying Merkle inclusion.
const GasMerkleTreeVerify uint64 = 300

// Module is the subnet-evm module for the MerkleTreeVerify precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     MerkleTreeVerifyPrecompile,
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
