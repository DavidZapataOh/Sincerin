package poseidonhash

import (
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/sincerin/l1/precompile/contract"
	"github.com/sincerin/l1/precompile/modules"
	"github.com/sincerin/l1/precompile/precompileconfig"
)

// ContractAddress is the address of the PoseidonHash precompile.
// Inspired by EIP-5988 (stagnant in Ethereum).
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000003")

// GasPoseidonHashBase is the base gas cost for a Poseidon hash.
const GasPoseidonHashBase uint64 = 200

// GasPoseidonHashPerExtra is the additional gas per input beyond the first.
const GasPoseidonHashPerExtra uint64 = 50

// Module is the subnet-evm module for the PoseidonHash precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     PoseidonHashPrecompile,
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
