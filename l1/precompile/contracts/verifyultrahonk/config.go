package verifyultrahonk

import (
	"github.com/sincerin/l1/precompile/precompileconfig"
)

var _ precompileconfig.Config = (*Config)(nil)

// ConfigKey is the unique identifier for this precompile in the genesis config.
const ConfigKey = "verifyUltraHonkConfig"

// Config holds the activation timestamp for the VerifyUltraHonk precompile.
type Config struct {
	precompileconfig.Upgrade
}

// NewConfig creates a new config that activates at the given timestamp.
func NewConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{BlockTimestamp: blockTimestamp},
	}
}

// NewDisableConfig creates a config that disables the precompile at the given timestamp.
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
