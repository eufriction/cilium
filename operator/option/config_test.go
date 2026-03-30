// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestEnableGatewayAPIExtensionRefFilters(t *testing.T) {
	tests := []struct {
		name     string
		set      bool // whether to explicitly set the flag
		value    bool // value to set if set==true
		expected bool
	}{
		{
			name:     "default is disabled",
			set:      false,
			expected: false,
		},
		{
			name:     "explicitly enabled",
			set:      true,
			value:    true,
			expected: true,
		},
		{
			name:     "explicitly disabled",
			set:      true,
			value:    false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := viper.New()
			if tt.set {
				vp.Set(EnableGatewayAPIExtensionRefFilters, tt.value)
			}

			config := &OperatorConfig{}
			config.Populate(nil, vp)

			assert.Equal(t, tt.expected, config.EnableGatewayAPIExtensionRefFilters)
		})
	}
}
