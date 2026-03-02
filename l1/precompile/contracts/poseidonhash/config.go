package poseidonhash

import (
	"github.com/sincerin/l1/precompile/precompileconfig"
)

var _ precompileconfig.Config = (*Config)(nil)

const ConfigKey = "poseidonHashConfig"

type Config struct {
	precompileconfig.Upgrade
}

func NewConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{BlockTimestamp: blockTimestamp},
	}
}

func NewDisableConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{
			BlockTimestamp: blockTimestamp,
			Disable:        true,
		},
	}
}

func (*Config) Key() string { return ConfigKey }

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	return nil
}
