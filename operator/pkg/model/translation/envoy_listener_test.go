// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_http_connection_manager_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_getHostNetworkListenerAddresses(t *testing.T) {
	testCases := []struct {
		desc                       string
		ports                      []uint32
		ipv4Enabled                bool
		ipv6Enabled                bool
		expectedPrimaryAdress      *envoy_config_core_v3.Address
		expectedAdditionalAdresses []*envoy_config_listener.AdditionalAddress
	}{
		{
			desc:                       "No ports - no address",
			ipv4Enabled:                true,
			ipv6Enabled:                true,
			expectedPrimaryAdress:      nil,
			expectedAdditionalAdresses: nil,
		},
		{
			desc:                       "No IP family - no address",
			ports:                      []uint32{55555},
			expectedPrimaryAdress:      nil,
			expectedAdditionalAdresses: nil,
		},
		{
			desc:        "IPv4 only",
			ports:       []uint32{55555},
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 55555,
						},
					},
				},
			},
			expectedAdditionalAdresses: nil,
		},
		{
			desc:        "IPv6 only",
			ports:       []uint32{55555},
			ipv4Enabled: false,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "::",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 55555,
						},
					},
				},
			},
			expectedAdditionalAdresses: nil,
		},
		{
			desc:        "IPv4 & IPv6",
			ports:       []uint32{55555},
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 55555,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
		{
			desc:        "IPv4 only with multiple ports",
			ports:       []uint32{44444, 55555},
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 44444,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "0.0.0.0",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
		{
			desc:        "IPv6 only with multiple ports",
			ports:       []uint32{44444, 55555},
			ipv4Enabled: false,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "::",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 44444,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
		{
			desc:        "IPv4 & IPv6 with multiple ports",
			ports:       []uint32{44444, 55555},
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 44444,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 44444,
								},
							},
						},
					},
				},
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "0.0.0.0",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			primaryAddress, additionalAddresses := getHostNetworkListenerAddresses(tC.ports, tC.ipv4Enabled, tC.ipv6Enabled)

			assert.Equal(t, tC.expectedPrimaryAdress, primaryAddress)
			assert.Equal(t, tC.expectedAdditionalAdresses, additionalAddresses)
		})
	}
}

func Test_withHostNetworkPortSorted(t *testing.T) {
	modifiedEnvoyListener1 := withHostNetworkPort(&model.Model{HTTP: []model.HTTPListener{{Port: 80}, {Port: 443}}}, true, true)(&envoy_config_listener.Listener{})
	modifiedEnvoyListener2 := withHostNetworkPort(&model.Model{HTTP: []model.HTTPListener{{Port: 443}, {Port: 80}}}, true, true)(&envoy_config_listener.Listener{})

	diffOutput := cmp.Diff(modifiedEnvoyListener1, modifiedEnvoyListener2, protocmp.Transform())
	if len(diffOutput) != 0 {
		t.Errorf("Modified Envoy Listeners did not match for different order of http listener ports:\n%s\n", diffOutput)
	}
}

// TestDesiredEnvoyListenerPerPort checks that desiredEnvoyListener emits one
// Listener per distinct HTTPS port.
func TestDesiredEnvoyListenerPerPort(t *testing.T) {
	i := &cecTranslator{
		Config: Config{
			SecretsNamespace: "cilium-secrets",
		},
	}

	res, err := i.desiredEnvoyListener(multiPortHTTPSModel)
	require.NoError(t, err)
	require.Len(t, res, 3, "expected 3 Envoy Listeners: insecure, listener-443, listener-50051")

	decodeListener := func(r ciliumv2.XDSResource) *envoy_config_listener.Listener {
		l := &envoy_config_listener.Listener{}
		require.NoError(t, proto.Unmarshal(r.Value, l))
		return l
	}
	decodeHCM := func(fc *envoy_config_listener.FilterChain) *envoy_http_connection_manager_v3.HttpConnectionManager {
		require.Len(t, fc.Filters, 1)
		hcm := &envoy_http_connection_manager_v3.HttpConnectionManager{}
		require.NoError(t, proto.Unmarshal(fc.Filters[0].GetTypedConfig().GetValue(), hcm))
		return hcm
	}

	// insecure listener
	l0 := decodeListener(res[0])
	require.Equal(t, "listener", l0.Name)
	require.Len(t, l0.FilterChains, 1, "insecure listener: one HTTP filter chain")
	require.Equal(t, rawBufferTransportProtocol, l0.FilterChains[0].FilterChainMatch.TransportProtocol)
	hcm0 := decodeHCM(l0.FilterChains[0])
	require.Equal(t, "listener-insecure", hcm0.StatPrefix)
	require.Equal(t, "listener-insecure", hcm0.GetRds().GetRouteConfigName())

	// port 443
	l1 := decodeListener(res[1])
	require.Equal(t, "listener-443", l1.Name)
	require.Len(t, l1.FilterChains, 1, "HTTPS listener-443: one filter chain")
	require.Equal(t, tlsTransportProtocol, l1.FilterChains[0].FilterChainMatch.TransportProtocol)
	require.Equal(t, []string{"example.com"}, l1.FilterChains[0].FilterChainMatch.ServerNames)
	hcm1 := decodeHCM(l1.FilterChains[0])
	require.Equal(t, "listener-443", hcm1.GetRds().GetRouteConfigName())
	require.Equal(t, tlsTransportSocketType, l1.FilterChains[0].TransportSocket.Name)

	// port 50051
	l2 := decodeListener(res[2])
	require.Equal(t, "listener-50051", l2.Name)
	require.Len(t, l2.FilterChains, 1, "HTTPS listener-50051: one filter chain")
	require.Equal(t, tlsTransportProtocol, l2.FilterChains[0].FilterChainMatch.TransportProtocol)
	require.Equal(t, []string{"example.com"}, l2.FilterChains[0].FilterChainMatch.ServerNames)
	hcm2 := decodeHCM(l2.FilterChains[0])
	require.Equal(t, "listener-50051", hcm2.GetRds().GetRouteConfigName())
	require.Equal(t, tlsTransportSocketType, l2.FilterChains[0].TransportSocket.Name)
}

// TestDesiredEnvoyListenerSingleHTTPS checks that a single-HTTPS-port model
// still produces one combined Listener, preserving the original behaviour.
func TestDesiredEnvoyListenerSingleHTTPS(t *testing.T) {
	i := &cecTranslator{
		Config: Config{
			SecretsNamespace: "cilium-secrets",
		},
	}

	res, err := i.desiredEnvoyListener(hostRulesModel)
	require.NoError(t, err)
	require.Len(t, res, 1, "single HTTPS port: one combined listener")

	l := &envoy_config_listener.Listener{}
	require.NoError(t, proto.Unmarshal(res[0].Value, l))

	require.Equal(t, "listener", l.Name)
	require.Len(t, l.FilterChains, 2)

	decodeHCM := func(fc *envoy_config_listener.FilterChain) *envoy_http_connection_manager_v3.HttpConnectionManager {
		hcm := &envoy_http_connection_manager_v3.HttpConnectionManager{}
		require.NoError(t, proto.Unmarshal(fc.Filters[0].GetTypedConfig().GetValue(), hcm))
		return hcm
	}

	hcm0 := decodeHCM(l.FilterChains[0])
	require.Equal(t, "listener-insecure", hcm0.GetRds().GetRouteConfigName())

	hcm1 := decodeHCM(l.FilterChains[1])
	require.Equal(t, "listener-secure", hcm1.GetRds().GetRouteConfigName())
}
