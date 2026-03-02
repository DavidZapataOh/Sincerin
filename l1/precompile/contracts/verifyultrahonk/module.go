package verifyultrahonk

import (
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/sincerin/l1/precompile/contract"
	"github.com/sincerin/l1/precompile/modules"
	"github.com/sincerin/l1/precompile/precompileconfig"
)

// ContractAddress is the address of the VerifyUltraHonk precompile.
// Per subnet-evm convention, custom precompiles for forks start at 0x0300...
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000002")

// GasVerifyUltraHonk is the fixed gas cost for UltraHonk proof verification.
// 91% savings vs Ethereum's ecPairing (~220,000 gas).
const GasVerifyUltraHonk uint64 = 20_000

// Module is the subnet-evm module for the VerifyUltraHonk precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     VerifyUltraHonkPrecompile,
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
