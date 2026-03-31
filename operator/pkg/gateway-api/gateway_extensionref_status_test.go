// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func Test_extensionRefCondition(t *testing.T) {
	cehfs := []v2alpha1.CiliumEnvoyHTTPFilter{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "my-filter", Namespace: "default"},
			Spec: v2alpha1.CiliumEnvoyHTTPFilterSpec{
				Placement: v2alpha1.CiliumEnvoyHTTPFilterPlacementFirst,
				Filters:   []v2alpha1.CiliumEnvoyHTTPFilterEntry{{Name: "envoy.filters.http.oauth2"}},
			},
		},
	}

	extensionRefFilter := func(group, kind, name string) gatewayv1.HTTPRouteFilter {
		return gatewayv1.HTTPRouteFilter{
			Type: gatewayv1.HTTPRouteFilterExtensionRef,
			ExtensionRef: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group(group),
				Kind:  gatewayv1.Kind(kind),
				Name:  gatewayv1.ObjectName(name),
			},
		}
	}

	testCases := []struct {
		name           string
		enabled        bool
		hr             *gatewayv1.HTTPRoute
		cehfs          []v2alpha1.CiliumEnvoyHTTPFilter
		wantOK         bool
		wantReason     string
		wantSubMessage string
	}{
		{
			name:    "no ExtensionRef filters",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{}},
					},
				},
			},
			cehfs:  nil,
			wantOK: true,
		},
		{
			name:    "no rules at all",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec:       gatewayv1.HTTPRouteSpec{},
			},
			cehfs:  nil,
			wantOK: true,
		},
		{
			name:    "feature disabled",
			enabled: false,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
						}},
					},
				},
			},
			cehfs:          cehfs,
			wantOK:         false,
			wantReason:     string(gatewayv1.RouteReasonRefNotPermitted),
			wantSubMessage: "EnableGatewayAPIExtensionRefFilters",
		},
		{
			name:    "wrong group",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("example.com", "CiliumEnvoyHTTPFilter", "my-filter"),
						}},
					},
				},
			},
			cehfs:          cehfs,
			wantOK:         false,
			wantReason:     string(gatewayv1.RouteReasonInvalidKind),
			wantSubMessage: "unsupported group/kind",
		},
		{
			name:    "wrong kind",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("cilium.io", "SomeOtherKind", "my-filter"),
						}},
					},
				},
			},
			cehfs:          cehfs,
			wantOK:         false,
			wantReason:     string(gatewayv1.RouteReasonInvalidKind),
			wantSubMessage: "unsupported group/kind",
		},
		{
			name:    "object not found",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "does-not-exist"),
						}},
					},
				},
			},
			cehfs:          cehfs,
			wantOK:         false,
			wantReason:     string(gatewayv1.RouteReasonBackendNotFound),
			wantSubMessage: "not found",
		},
		{
			name:    "object in wrong namespace",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "other-ns"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
						}},
					},
				},
			},
			cehfs:          cehfs,
			wantOK:         false,
			wantReason:     string(gatewayv1.RouteReasonBackendNotFound),
			wantSubMessage: "not found",
		},
		{
			name:    "valid ref",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
						}},
					},
				},
			},
			cehfs:  cehfs,
			wantOK: true,
		},
		{
			name:    "multiple rules - second has invalid ref",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
						}},
						{Filters: []gatewayv1.HTTPRouteFilter{
							extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "missing"),
						}},
					},
				},
			},
			cehfs:          cehfs,
			wantOK:         false,
			wantReason:     string(gatewayv1.RouteReasonBackendNotFound),
			wantSubMessage: "not found",
		},
		{
			name:    "mixed filters - non-ExtensionRef ignored",
			enabled: true,
			hr: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Filters: []gatewayv1.HTTPRouteFilter{
							{Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier},
							extensionRefFilter("cilium.io", "CiliumEnvoyHTTPFilter", "my-filter"),
						}},
					},
				},
			},
			cehfs:  cehfs,
			wantOK: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			r := &gatewayReconciler{
				operatorConfig: &operatorOption.OperatorConfig{
					EnableGatewayAPIExtensionRefFilters: tt.enabled,
				},
			}

			cond, ok := r.extensionRefCondition(tt.hr, tt.cehfs)
			require.Equal(t, tt.wantOK, ok)

			if !tt.wantOK {
				require.Equal(t, string(gatewayv1.RouteConditionResolvedRefs), cond.Type)
				require.Equal(t, metav1.ConditionFalse, cond.Status)
				require.Equal(t, tt.wantReason, cond.Reason)
				require.Contains(t, cond.Message, tt.wantSubMessage)
			}
		})
	}
}
