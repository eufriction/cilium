// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
)

func Test_desiredHTTPConnectionManager(t *testing.T) {
	i := &cecTranslator{}
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", nil)
	require.NoError(t, err)

	httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)

	require.NoError(t, err)

	require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
	require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
		Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
	}, httpConnectionManager.GetRouteSpecifier())

	require.Len(t, httpConnectionManager.GetHttpFilters(), 3)
	require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
	require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[2].Name)

	require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
	require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
}

// parseHCM is a test helper that unmarshals the XDSResource into an HCM proto.
func parseHCM(t *testing.T, i *cecTranslator, customFilters []model.CustomHTTPFilter) *httpConnectionManagerv3.HttpConnectionManager {
	t.Helper()
	res, err := i.desiredHTTPConnectionManager("test", "test-route", customFilters)
	require.NoError(t, err)

	hcm := &httpConnectionManagerv3.HttpConnectionManager{}
	require.NoError(t, proto.Unmarshal(res.Value, hcm))
	return hcm
}

// filterNames extracts the filter name strings from the HCM filter list.
func filterNames(hcm *httpConnectionManagerv3.HttpConnectionManager) []string {
	names := make([]string, 0, len(hcm.GetHttpFilters()))
	for _, f := range hcm.GetHttpFilters() {
		names = append(names, f.Name)
	}
	return names
}

func Test_desiredHTTPConnectionManager_CustomFilters(t *testing.T) {
	testCases := []struct {
		desc          string
		customFilters []model.CustomHTTPFilter
		expectedNames []string
	}{
		{
			desc: "one First filter",
			customFilters: []model.CustomHTTPFilter{
				{Name: "envoy.filters.http.oauth2", Placement: "First"},
			},
			expectedNames: []string{
				"envoy.filters.http.grpc_web",
				"envoy.filters.http.grpc_stats",
				"envoy.filters.http.oauth2",
				"envoy.filters.http.router",
			},
		},
		{
			desc: "one Last filter",
			customFilters: []model.CustomHTTPFilter{
				{Name: "envoy.filters.http.lua", Placement: "Last"},
			},
			expectedNames: []string{
				"envoy.filters.http.grpc_web",
				"envoy.filters.http.grpc_stats",
				"envoy.filters.http.lua",
				"envoy.filters.http.router",
			},
		},
		{
			desc: "multiple First - declaration order preserved",
			customFilters: []model.CustomHTTPFilter{
				{Name: "envoy.filters.http.alpha", Placement: "First"},
				{Name: "envoy.filters.http.beta", Placement: "First"},
			},
			expectedNames: []string{
				"envoy.filters.http.grpc_web",
				"envoy.filters.http.grpc_stats",
				"envoy.filters.http.alpha",
				"envoy.filters.http.beta",
				"envoy.filters.http.router",
			},
		},
		{
			desc: "multiple Last - declaration order preserved",
			customFilters: []model.CustomHTTPFilter{
				{Name: "envoy.filters.http.alpha", Placement: "Last"},
				{Name: "envoy.filters.http.beta", Placement: "Last"},
			},
			expectedNames: []string{
				"envoy.filters.http.grpc_web",
				"envoy.filters.http.grpc_stats",
				"envoy.filters.http.alpha",
				"envoy.filters.http.beta",
				"envoy.filters.http.router",
			},
		},
		{
			desc: "mixed First and Last - First before Last, router terminal",
			customFilters: []model.CustomHTTPFilter{
				{Name: "envoy.filters.http.oauth2", Placement: "First"},
				{Name: "envoy.filters.http.lua", Placement: "Last"},
				{Name: "envoy.filters.http.ext_authz", Placement: "First"},
			},
			expectedNames: []string{
				"envoy.filters.http.grpc_web",
				"envoy.filters.http.grpc_stats",
				"envoy.filters.http.oauth2",
				"envoy.filters.http.ext_authz",
				"envoy.filters.http.lua",
				"envoy.filters.http.router",
			},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			hcm := parseHCM(t, &cecTranslator{}, tC.customFilters)
			require.Equal(t, tC.expectedNames, filterNames(hcm))
		})
	}
}

func Test_desiredHTTPConnectionManager_TypedConfig(t *testing.T) {
	t.Run("TypedConfig passthrough", func(t *testing.T) {
		wantTypeURL := "type.googleapis.com/envoy.extensions.filters.http.oauth2.v3.OAuth2"
		wantConfig := []byte{0x0a, 0x02, 0x08, 0x01}

		hcm := parseHCM(t, &cecTranslator{}, []model.CustomHTTPFilter{
			{
				Name:      "envoy.filters.http.oauth2",
				Placement: "First",
				TypeURL:   wantTypeURL,
				Config:    wantConfig,
			},
		})

		require.Len(t, hcm.GetHttpFilters(), 4) // grpc_web, grpc_stats, oauth2, router
		oauth2Filter := hcm.GetHttpFilters()[2]
		require.Equal(t, "envoy.filters.http.oauth2", oauth2Filter.Name)
		tc := oauth2Filter.GetTypedConfig()
		require.NotNil(t, tc)
		require.Equal(t, wantTypeURL, tc.GetTypeUrl())
		require.Equal(t, wantConfig, tc.GetValue())
	})

	t.Run("no TypedConfig when TypeURL is empty", func(t *testing.T) {
		hcm := parseHCM(t, &cecTranslator{}, []model.CustomHTTPFilter{
			{Name: "envoy.filters.http.cors", Placement: "First"},
		})

		require.Len(t, hcm.GetHttpFilters(), 4) // grpc_web, grpc_stats, cors, router
		corsFilter := hcm.GetHttpFilters()[2]
		require.Equal(t, "envoy.filters.http.cors", corsFilter.Name)
		require.Nil(t, corsFilter.GetTypedConfig())
	})
}

func Test_collectCustomHTTPFilters(t *testing.T) {
	testCases := []struct {
		desc          string
		model         *model.Model
		expectedNames []string
	}{
		{
			desc:          "empty model",
			model:         &model.Model{},
			expectedNames: nil,
		},
		{
			desc: "deduplicates by name within one listener",
			model: &model.Model{
				HTTP: []model.HTTPListener{
					{
						Routes: []model.HTTPRoute{
							{CustomHTTPFilters: []model.CustomHTTPFilter{
								{Name: "envoy.filters.http.oauth2", Placement: "First"},
							}},
							{CustomHTTPFilters: []model.CustomHTTPFilter{
								{Name: "envoy.filters.http.oauth2", Placement: "First"},
								{Name: "envoy.filters.http.lua", Placement: "Last"},
							}},
						},
					},
				},
			},
			expectedNames: []string{"envoy.filters.http.oauth2", "envoy.filters.http.lua"},
		},
		{
			desc: "deduplicates across multiple listeners",
			model: &model.Model{
				HTTP: []model.HTTPListener{
					{
						Routes: []model.HTTPRoute{
							{CustomHTTPFilters: []model.CustomHTTPFilter{
								{Name: "envoy.filters.http.oauth2", Placement: "First"},
							}},
						},
					},
					{
						Routes: []model.HTTPRoute{
							{CustomHTTPFilters: []model.CustomHTTPFilter{
								{Name: "envoy.filters.http.oauth2", Placement: "First"},
								{Name: "envoy.filters.http.ext_authz", Placement: "Last"},
							}},
						},
					},
				},
			},
			expectedNames: []string{"envoy.filters.http.oauth2", "envoy.filters.http.ext_authz"},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			result := collectCustomHTTPFilters(tC.model)
			if tC.expectedNames == nil {
				require.Empty(t, result)
				return
			}
			require.Len(t, result, len(tC.expectedNames))
			for i, name := range tC.expectedNames {
				require.Equal(t, name, result[i].Name)
			}
		})
	}
}
