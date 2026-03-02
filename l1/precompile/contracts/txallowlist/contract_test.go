// Copyright (C) 2019-2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package txallowlist

import (
	"testing"

	"github.com/sincerin/l1/precompile/allowlist/allowlisttest"
)

func TestTxAllowListRun(t *testing.T) {
	allowlisttest.RunPrecompileWithAllowListTests(t, Module, nil)
}
