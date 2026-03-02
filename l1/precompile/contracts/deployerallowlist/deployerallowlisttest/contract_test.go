// Copyright (C) 2019-2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package deployerallowlisttest

import (
	"testing"

	"github.com/sincerin/l1/precompile/allowlist/allowlisttest"
	"github.com/sincerin/l1/precompile/contracts/deployerallowlist"
)

func TestContractDeployerAllowListRun(t *testing.T) {
	allowlisttest.RunPrecompileWithAllowListTests(t, deployerallowlist.Module, nil)
}
