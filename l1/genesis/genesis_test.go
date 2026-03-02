package genesis

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sincerin/l1/core"
	"github.com/sincerin/l1/params"
	"github.com/sincerin/l1/plugin/evm"
	"github.com/sincerin/l1/precompile/modules"

	// Import registry to trigger all precompile init() functions
	_ "github.com/sincerin/l1/precompile/registry"

	"github.com/stretchr/testify/require"
)

func loadTestnetGenesis(t *testing.T) *core.Genesis {
	t.Helper()
	data, err := os.ReadFile("testnet.json")
	require.NoError(t, err, "failed to read testnet.json")

	var genesis core.Genesis
	err = json.Unmarshal(data, &genesis)
	require.NoError(t, err, "failed to unmarshal genesis")

	return &genesis
}

func TestGenesis_LoadsSuccessfully(t *testing.T) {
	genesis := loadTestnetGenesis(t)
	require.NotNil(t, genesis)
	require.NotNil(t, genesis.Config)
}

func TestGenesis_ChainID(t *testing.T) {
	genesis := loadTestnetGenesis(t)
	require.Equal(t, int64(43214321), genesis.Config.ChainID.Int64())
}

func TestGenesis_GasLimit(t *testing.T) {
	genesis := loadTestnetGenesis(t)
	require.Equal(t, uint64(30000000), genesis.GasLimit)
}

func TestGenesis_FeeConfig(t *testing.T) {
	err := evm.WithTempRegisteredLibEVMExtras(func() error {
		genesis := loadTestnetGenesis(t)
		cfg := genesis.Config

		extra := params.GetExtra(cfg)
		require.NotNil(t, extra.FeeConfig, "fee config should be set")

		feeConfig := extra.FeeConfig
		require.Equal(t, uint64(30000000), feeConfig.GasLimit.Uint64())
		require.Equal(t, uint64(1000000000), feeConfig.MinBaseFee.Uint64())
		require.Equal(t, uint64(15000000), feeConfig.TargetGas.Uint64())
		require.Equal(t, uint64(48), feeConfig.BaseFeeChangeDenominator.Uint64())
		require.Equal(t, uint64(0), feeConfig.MinBlockGasCost.Uint64())
		require.Equal(t, uint64(10000000), feeConfig.MaxBlockGasCost.Uint64())
		require.Equal(t, uint64(2), feeConfig.TargetBlockRate)
		require.Equal(t, uint64(500000), feeConfig.BlockGasCostStep.Uint64())
		return nil
	})
	require.NoError(t, err)
}

func TestGenesis_PrefundedAccount(t *testing.T) {
	genesis := loadTestnetGenesis(t)
	require.NotEmpty(t, genesis.Alloc, "alloc should have at least one account")

	hasBalance := false
	for _, account := range genesis.Alloc {
		if account.Balance != nil && account.Balance.Sign() > 0 {
			hasBalance = true
			break
		}
	}
	require.True(t, hasBalance, "should have at least one prefunded account")
}

func TestGenesis_PrecompileConfigsPresent(t *testing.T) {
	keys := []string{
		"verifyUltraHonkConfig",
		"poseidonHashConfig",
		"merkleTreeInsertConfig",
		"merkleTreeVerifyConfig",
	}
	for _, key := range keys {
		_, found := modules.GetPrecompileModule(key)
		require.True(t, found, "precompile module for %s should be registered", key)
	}
}
