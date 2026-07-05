// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	"github.com/cilium/cilium/operator/pkg/model"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_routeConfiguration(t *testing.T) {
	res, err := routeConfiguration("dummy-name", []*envoy_config_route_v3.VirtualHost{
		{
			Name: "dummy-virtual-host",
		},
	})
	require.NoError(t, err)

	routeConfiguration := &envoy_config_route_v3.RouteConfiguration{}
	err = proto.Unmarshal(res.Value, routeConfiguration)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", routeConfiguration.GetName())
	require.Len(t, routeConfiguration.GetVirtualHosts(), 1)
	require.Equal(t, "dummy-virtual-host", routeConfiguration.GetVirtualHosts()[0].GetName())
}

func TestHTTPPlainPortKeys(t *testing.T) {
	tests := []struct {
		name string
		m    model.Model
		want []string
	}{
		{
			name: "empty model",
			m:    model.Model{},
			want: nil,
		},
		{
			name: "single plain HTTP port - no per-port needed",
			m: model.Model{
				HTTP: []model.HTTPListener{
					{Port: 80},
				},
			},
			want: []string{"insecure"},
		},
		{
			name: "multiple plain HTTP ports - per-port needed",
			m: model.Model{
				HTTP: []model.HTTPListener{
					{Port: 80},
					{Port: 8080},
				},
			},
			want: []string{"80", "8080"},
		},
		{
			name: "mixed HTTP and HTTPS - per-port needed for HTTP",
			m: model.Model{
				HTTP: []model.HTTPListener{
					{Port: 80},
					{Port: 8080},
					{Port: 443, TLS: []model.TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: []string{"80", "8080"},
		},
		{
			name: "only HTTPS - no plain HTTP ports",
			m: model.Model{
				HTTP: []model.HTTPListener{
					{Port: 443, TLS: []model.TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpPlainPortKeys(&tt.m)
			require.Equal(t, tt.want, got)
		})
	}
}
