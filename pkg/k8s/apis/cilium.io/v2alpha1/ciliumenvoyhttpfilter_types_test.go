// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"

	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
)

func TestCiliumEnvoyHTTPFilterSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, AddToScheme(scheme))

	gvk := schema.GroupVersionKind{
		Group:   CustomResourceDefinitionGroup,
		Version: CustomResourceDefinitionVersion,
		Kind:    "CiliumEnvoyHTTPFilter",
	}

	obj, err := scheme.New(gvk)
	require.NoError(t, err)
	require.IsType(t, &CiliumEnvoyHTTPFilter{}, obj)

	listGVK := schema.GroupVersionKind{
		Group:   CustomResourceDefinitionGroup,
		Version: CustomResourceDefinitionVersion,
		Kind:    "CiliumEnvoyHTTPFilterList",
	}

	listObj, err := scheme.New(listGVK)
	require.NoError(t, err)
	require.IsType(t, &CiliumEnvoyHTTPFilterList{}, listObj)
}

func TestCiliumEnvoyHTTPFilterRuntimeObject(t *testing.T) {
	var obj runtime.Object = &CiliumEnvoyHTTPFilter{}
	require.NotNil(t, obj)

	var listObj runtime.Object = &CiliumEnvoyHTTPFilterList{}
	require.NotNil(t, listObj)
}

func TestCiliumEnvoyHTTPFilterSpecJSON(t *testing.T) {
	specYAML := []byte(`placement: First
filters:
- name: envoy.filters.http.router
  typedConfig:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`)

	jsonBytes, err := yaml.YAMLToJSON(specYAML)
	require.NoError(t, err)

	spec := &CiliumEnvoyHTTPFilterSpec{}
	err = json.Unmarshal(jsonBytes, spec)
	require.NoError(t, err)

	require.Equal(t, CiliumEnvoyHTTPFilterPlacementFirst, spec.Placement)
	require.Len(t, spec.Filters, 1)
	require.Equal(t, "envoy.filters.http.router", spec.Filters[0].Name)
	require.Equal(t, "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router", spec.Filters[0].TypedConfig.TypeUrl)

	// Round-trip: marshal back to JSON and unmarshal again
	roundTripped, err := json.Marshal(spec)
	require.NoError(t, err)

	spec2 := &CiliumEnvoyHTTPFilterSpec{}
	err = json.Unmarshal(roundTripped, spec2)
	require.NoError(t, err)

	require.Equal(t, spec.Placement, spec2.Placement)
	require.Len(t, spec2.Filters, 1)
	require.Equal(t, spec.Filters[0].Name, spec2.Filters[0].Name)
	require.Equal(t, spec.Filters[0].TypedConfig.TypeUrl, spec2.Filters[0].TypedConfig.TypeUrl)
}

func TestCiliumEnvoyHTTPFilterDeepCopy(t *testing.T) {
	specYAML := []byte(`placement: Last
filters:
- name: envoy.filters.http.router
  typedConfig:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`)

	jsonBytes, err := yaml.YAMLToJSON(specYAML)
	require.NoError(t, err)

	original := &CiliumEnvoyHTTPFilter{}
	original.Name = "test-filter"
	original.Namespace = "test-ns"
	err = json.Unmarshal(jsonBytes, &original.Spec)
	require.NoError(t, err)

	copied := original.DeepCopy()
	require.NotNil(t, copied)

	// Verify the copy is equal
	require.Equal(t, original.Name, copied.Name)
	require.Equal(t, original.Namespace, copied.Namespace)
	require.Equal(t, original.Spec.Placement, copied.Spec.Placement)
	require.Len(t, copied.Spec.Filters, 1)
	require.Equal(t, original.Spec.Filters[0].Name, copied.Spec.Filters[0].Name)

	// Verify the copy is independent: mutating the copy must not affect the original
	copied.Name = "mutated"
	copied.Spec.Placement = CiliumEnvoyHTTPFilterPlacementFirst
	copied.Spec.Filters[0].Name = "mutated-filter"

	require.Equal(t, "test-filter", original.Name)
	require.Equal(t, CiliumEnvoyHTTPFilterPlacementLast, original.Spec.Placement)
	require.Equal(t, "envoy.filters.http.router", original.Spec.Filters[0].Name)
}

func TestCiliumEnvoyHTTPFilterPlacementConstants(t *testing.T) {
	require.Equal(t, CiliumEnvoyHTTPFilterPlacement("First"), CiliumEnvoyHTTPFilterPlacementFirst)
	require.Equal(t, CiliumEnvoyHTTPFilterPlacement("Last"), CiliumEnvoyHTTPFilterPlacementLast)
}
