// Copyright (C) 2019-2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package allowlisttest

import (
	"testing"

	"github.com/sincerin/l1/precompile/allowlist"
	"github.com/sincerin/l1/precompile/modules"
)

var testModule = modules.Module{
	Address:      dummyAddr,
	Contract:     allowlist.CreateAllowListPrecompile(dummyAddr),
	Configurator: &dummyConfigurator{},
	ConfigKey:    "dummy",
}

func TestVerifyAllowlist(t *testing.T) {
	RunPrecompileWithAllowListTests(t, testModule, nil)
}

func TestEqualAllowList(t *testing.T) {
	EqualPrecompileWithAllowListTests(t, testModule, nil)
}
