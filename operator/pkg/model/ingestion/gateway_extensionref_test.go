// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// ---------------------------------------------------------------------------
// Helpers shared across ExtensionRef tests
// ---------------------------------------------------------------------------

func testSvcPort(port int32) *gatewayv1.PortNumber {
	p := gatewayv1.PortNumber(port)
	return &p
}

// minimalHTTPRoute builds a gatewayv1.HTTPRoute with one rule containing the
// supplied rule-level filters and a backend reference to "backend-svc".
func minimalHTTPRoute(namespace, name string, ruleFilters []gatewayv1.HTTPRouteFilter) gatewayv1.HTTPRoute {
	return gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: testSvcPort(80),
							},
						}},
					},
					Filters: ruleFilters,
				},
			},
		},
	}
}

// backendService returns a minimal corev1.Service matching the backend-svc
// used in minimalHTTPRoute.
func backendService(namespace string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-svc", Namespace: namespace},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 80}}},
	}
}

// extensionRefFilter builds an HTTPRouteFilter of type ExtensionRef.
func extensionRefFilter(group, kind, name string) gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterExtensionRef,
		ExtensionRef: &gatewayv1.LocalObjectReference{
			Group: gatewayv1.Group(group),
			Kind:  gatewayv1.Kind(kind),
			Name:  gatewayv1.ObjectName(name),
		},
	}
}

// makeCEHF builds a CiliumEnvoyHTTPFilter with a single no-config filter entry.
func makeCEHF(namespace, name string, placement v2alpha1.CiliumEnvoyHTTPFilterPlacement) v2alpha1.CiliumEnvoyHTTPFilter {
	return v2alpha1.CiliumEnvoyHTTPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v2alpha1.CiliumEnvoyHTTPFilterSpec{
			Placement: placement,
			Filters: []v2alpha1.CiliumEnvoyHTTPFilterEntry{
				{Name: "envoy.filters.http.oauth2", TypedConfig: ciliumv2.XDSResource{}},
			},
		},
	}
}

// callExtractRoutes is a convenience wrapper around extractRoutes that pins the
// constant parameters shared across all ExtensionRef tests.
func callExtractRoutes(
	logger *slog.Logger,
	hr gatewayv1.HTTPRoute,
	services []corev1.Service,
	enabled bool,
	cehfs []v2alpha1.CiliumEnvoyHTTPFilter,
) []model.HTTPRoute {
	return extractRoutes(
		logger,
		80,                      // listenerPort
		[]string{"example.com"}, // hostnames
		hr,
		services,
		nil, // serviceImports
		nil, // grants
		nil, // btlspMap
		enabled,
		false, // isGamma
		cehfs,
	)
}

func newTestLogger(t *testing.T) *slog.Logger {
	return hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestExtractRoutes_NoExtensionRef ensures that routes without any
// ExtensionRef filters are completely unaffected.
func TestExtractRoutes_NoExtensionRef(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", nil)

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, false, nil)

	require.Len(t, routes, 1)
	assert.Nil(t, routes[0].DirectResponse)
	assert.Len(t, routes[0].Backends, 1)
	assert.Empty(t, routes[0].CustomHTTPFilters)
}

// TestExtractRoutes_ExtensionRef_FeatureDisabled verifies that when the
// feature flag is false, any ExtensionRef causes the rule to return 500
// (fail-closed) with no backends.
func TestExtractRoutes_ExtensionRef_FeatureDisabled(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
	})
	cehf := makeCEHF("default", "my-filter", v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst)

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, false, []v2alpha1.CiliumEnvoyHTTPFilter{cehf})

	require.Len(t, routes, 1)
	require.NotNil(t, routes[0].DirectResponse)
	assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
	assert.Empty(t, routes[0].Backends)
	assert.Empty(t, routes[0].CustomHTTPFilters)
}

// TestExtractRoutes_ExtensionRef_ValidRef verifies that a valid ExtensionRef
// pointing at an existing CiliumEnvoyHTTPFilter populates CustomHTTPFilters
// and keeps backends intact.
func TestExtractRoutes_ExtensionRef_ValidRef(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
	})
	cehf := makeCEHF("default", "my-filter", v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst)

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, []v2alpha1.CiliumEnvoyHTTPFilter{cehf})

	require.Len(t, routes, 1)
	assert.Nil(t, routes[0].DirectResponse)
	assert.Len(t, routes[0].Backends, 1)
	require.Len(t, routes[0].CustomHTTPFilters, 1)
	assert.Equal(t, "envoy.filters.http.oauth2", routes[0].CustomHTTPFilters[0].Name)
	assert.Equal(t, string(v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst), routes[0].CustomHTTPFilters[0].Placement)
}

// TestExtractRoutes_ExtensionRef_MissingObject verifies that a reference to a
// non-existent CiliumEnvoyHTTPFilter causes a 500 (fail-closed).
func TestExtractRoutes_ExtensionRef_MissingObject(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "nonexistent"),
	})

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, nil)

	require.Len(t, routes, 1)
	require.NotNil(t, routes[0].DirectResponse)
	assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
	assert.Empty(t, routes[0].Backends)
	assert.Empty(t, routes[0].CustomHTTPFilters)
}

// TestExtractRoutes_ExtensionRef_WrongGroup verifies that a mismatched group
// causes 500 (fail-closed).
func TestExtractRoutes_ExtensionRef_WrongGroup(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("gateway.networking.k8s.io", "CiliumEnvoyHTTPFilter", "my-filter"),
	})
	cehf := makeCEHF("default", "my-filter", v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst)

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, []v2alpha1.CiliumEnvoyHTTPFilter{cehf})

	require.Len(t, routes, 1)
	require.NotNil(t, routes[0].DirectResponse)
	assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
	assert.Empty(t, routes[0].Backends)
}

// TestExtractRoutes_ExtensionRef_WrongKind verifies that a mismatched kind
// causes 500 (fail-closed).
func TestExtractRoutes_ExtensionRef_WrongKind(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "SomeOtherKind", "my-filter"),
	})
	cehf := makeCEHF("default", "my-filter", v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst)

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, []v2alpha1.CiliumEnvoyHTTPFilter{cehf})

	require.Len(t, routes, 1)
	require.NotNil(t, routes[0].DirectResponse)
	assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
	assert.Empty(t, routes[0].Backends)
}

// TestExtractRoutes_ExtensionRef_WrongNamespace verifies that a CEHF in a
// different namespace is NOT resolved (LocalObjectReference is namespace-local).
func TestExtractRoutes_ExtensionRef_WrongNamespace(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
	})
	// CEHF lives in "other-ns", not "default"
	cehf := makeCEHF("other-ns", "my-filter", v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst)

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, []v2alpha1.CiliumEnvoyHTTPFilter{cehf})

	require.Len(t, routes, 1)
	require.NotNil(t, routes[0].DirectResponse)
	assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
}

// TestExtractRoutes_ExtensionRef_MultipleFilters verifies that multiple
// ExtensionRef filters on the same rule are resolved in declaration order.
func TestExtractRoutes_ExtensionRef_MultipleFilters(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "filter-a"),
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "filter-b"),
	})

	cehfA := v2alpha1.CiliumEnvoyHTTPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "filter-a", Namespace: "default"},
		Spec: v2alpha1.CiliumEnvoyHTTPFilterSpec{
			Placement: v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst,
			Filters: []v2alpha1.CiliumEnvoyHTTPFilterEntry{
				{Name: "envoy.filters.http.alpha", TypedConfig: ciliumv2.XDSResource{}},
			},
		},
	}
	cehfB := v2alpha1.CiliumEnvoyHTTPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "filter-b", Namespace: "default"},
		Spec: v2alpha1.CiliumEnvoyHTTPFilterSpec{
			Placement: v2alpha1.CiliumEnvoyHTTPFilterPlacementLast,
			Filters: []v2alpha1.CiliumEnvoyHTTPFilterEntry{
				{Name: "envoy.filters.http.beta", TypedConfig: ciliumv2.XDSResource{}},
			},
		},
	}

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, []v2alpha1.CiliumEnvoyHTTPFilter{cehfA, cehfB})

	require.Len(t, routes, 1)
	assert.Nil(t, routes[0].DirectResponse)
	assert.Len(t, routes[0].Backends, 1)
	require.Len(t, routes[0].CustomHTTPFilters, 2)
	// Declaration order must be preserved
	assert.Equal(t, "envoy.filters.http.alpha", routes[0].CustomHTTPFilters[0].Name)
	assert.Equal(t, string(v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst), routes[0].CustomHTTPFilters[0].Placement)
	assert.Equal(t, "envoy.filters.http.beta", routes[0].CustomHTTPFilters[1].Name)
	assert.Equal(t, string(v2alpha1.CiliumEnvoyHTTPFilterPlacementLast), routes[0].CustomHTTPFilters[1].Placement)
}

// TestExtractRoutes_ExtensionRef_PartialFailure verifies that if even one
// ExtensionRef in a rule fails to resolve, the whole rule returns 500.
func TestExtractRoutes_ExtensionRef_PartialFailure(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "exists"),
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "missing"),
	})
	cehf := makeCEHF("default", "exists", v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst)

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, []v2alpha1.CiliumEnvoyHTTPFilter{cehf})

	require.Len(t, routes, 1)
	// Even one failure -> fail-closed for the entire rule
	require.NotNil(t, routes[0].DirectResponse)
	assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
	assert.Empty(t, routes[0].Backends)
	assert.Empty(t, routes[0].CustomHTTPFilters)
}

// TestExtractRoutes_ExtensionRef_TypedConfigPassthrough verifies that TypeURL
// and Config bytes are carried through the model unchanged.
func TestExtractRoutes_ExtensionRef_TypedConfigPassthrough(t *testing.T) {
	log := newTestLogger(t)
	svc := backendService("default")
	hr := minimalHTTPRoute("default", "test-route", []gatewayv1.HTTPRouteFilter{
		extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
	})

	wantTypeURL := "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
	wantConfig := []byte{0x0a, 0x02}

	cehf := v2alpha1.CiliumEnvoyHTTPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "my-filter", Namespace: "default"},
		Spec: v2alpha1.CiliumEnvoyHTTPFilterSpec{
			Placement: v2alpha1.CiliumEnvoyHTTPFilterPlacementLast,
			Filters: []v2alpha1.CiliumEnvoyHTTPFilterEntry{
				{
					Name: "envoy.filters.http.router",
					TypedConfig: ciliumv2.XDSResource{
						Any: &anypb.Any{
							TypeUrl: wantTypeURL,
							Value:   wantConfig,
						},
					},
				},
			},
		},
	}

	routes := callExtractRoutes(log, hr, []corev1.Service{svc}, true, []v2alpha1.CiliumEnvoyHTTPFilter{cehf})

	require.Len(t, routes, 1)
	assert.Nil(t, routes[0].DirectResponse)
	require.Len(t, routes[0].CustomHTTPFilters, 1)
	f := routes[0].CustomHTTPFilters[0]
	assert.Equal(t, "envoy.filters.http.router", f.Name)
	assert.Equal(t, wantTypeURL, f.TypeURL)
	assert.Equal(t, wantConfig, f.Config)
}

// TestCustomHTTPFilter_ModelFields is a model-layer smoke test verifying that
// CustomHTTPFilter fields survive storage on an HTTPRoute.
func TestCustomHTTPFilter_ModelFields(t *testing.T) {
	route := model.HTTPRoute{
		CustomHTTPFilters: []model.CustomHTTPFilter{
			{
				Name:      "envoy.filters.http.oauth2",
				Placement: "First",
				TypeURL:   "type.googleapis.com/envoy.extensions.filters.http.oauth2.v3.OAuth2",
				Config:    []byte{0x01, 0x02, 0x03},
			},
		},
	}

	require.Len(t, route.CustomHTTPFilters, 1)
	f := route.CustomHTTPFilters[0]
	assert.Equal(t, "envoy.filters.http.oauth2", f.Name)
	assert.Equal(t, "First", f.Placement)
	assert.Equal(t, "type.googleapis.com/envoy.extensions.filters.http.oauth2.v3.OAuth2", f.TypeURL)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, f.Config)
}
