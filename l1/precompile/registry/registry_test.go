package registry

import (
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/sincerin/l1/precompile/modules"
	"github.com/stretchr/testify/require"
)

// Sincerin custom precompile addresses
var (
	verifyUltraHonkAddr  = common.HexToAddress("0x0300000000000000000000000000000000000002")
	poseidonHashAddr     = common.HexToAddress("0x0300000000000000000000000000000000000003")
	merkleTreeInsertAddr = common.HexToAddress("0x0300000000000000000000000000000000000004")
	merkleTreeVerifyAddr = common.HexToAddress("0x0300000000000000000000000000000000000005")
)

func TestRegistry_AllSincerinPrecompilesRegistered(t *testing.T) {
	addrs := map[common.Address]string{
		verifyUltraHonkAddr:  "verifyUltraHonk",
		poseidonHashAddr:     "poseidonHash",
		merkleTreeInsertAddr: "merkleTreeInsert",
		merkleTreeVerifyAddr: "merkleTreeVerify",
	}

	for addr, name := range addrs {
		mod, found := modules.GetPrecompileModuleByAddress(addr)
		require.True(t, found, "%s not found at address %s", name, addr.Hex())
		require.NotNil(t, mod.Contract, "%s contract is nil", name)
		require.NotNil(t, mod.Configurator, "%s configurator is nil", name)
		require.NotEmpty(t, mod.ConfigKey, "%s config key is empty", name)
	}
}

func TestRegistry_CorrectConfigKeys(t *testing.T) {
	tests := []struct {
		key  string
		addr common.Address
	}{
		{"verifyUltraHonkConfig", verifyUltraHonkAddr},
		{"poseidonHashConfig", poseidonHashAddr},
		{"merkleTreeInsertConfig", merkleTreeInsertAddr},
		{"merkleTreeVerifyConfig", merkleTreeVerifyAddr},
	}

	for _, tt := range tests {
		mod, found := modules.GetPrecompileModule(tt.key)
		require.True(t, found, "config key %s not found", tt.key)
		require.Equal(t, tt.addr, mod.Address, "address mismatch for %s", tt.key)
	}
}

func TestRegistry_NoAddressConflicts(t *testing.T) {
	allModules := modules.RegisteredModules()
	seen := make(map[common.Address]string)
	for _, mod := range allModules {
		if prev, ok := seen[mod.Address]; ok {
			t.Fatalf("address conflict: %s and %s both at %s", prev, mod.ConfigKey, mod.Address.Hex())
		}
		seen[mod.Address] = mod.ConfigKey
	}
}

func TestRegistry_SincerinAddressesInReservedRange(t *testing.T) {
	addrs := []common.Address{
		verifyUltraHonkAddr,
		poseidonHashAddr,
		merkleTreeInsertAddr,
		merkleTreeVerifyAddr,
	}
	for _, addr := range addrs {
		require.True(t, modules.ReservedAddress(addr), "address %s not in reserved range", addr.Hex())
	}
}

func TestRegistry_UpstreamPrecompilesStillRegistered(t *testing.T) {
	// Verify our additions don't break existing subnet-evm precompiles
	upstreamKeys := []string{
		"contractDeployerAllowListConfig",
		"contractNativeMinterConfig",
		"txAllowListConfig",
		"feeManagerConfig",
		"rewardManagerConfig",
		"warpConfig",
	}
	for _, key := range upstreamKeys {
		_, found := modules.GetPrecompileModule(key)
		require.True(t, found, "upstream precompile %s not found", key)
	}
}
