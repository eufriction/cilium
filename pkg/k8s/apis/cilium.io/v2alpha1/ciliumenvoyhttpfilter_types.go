// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumenvoyhttpfilter",path="ciliumenvoyhttpfilters",scope="Namespaced",shortName={cehf}
// +kubebuilder:printcolumn:name="Placement",type=string,JSONPath=".spec.placement"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
// +kubebuilder:storageversion

// CiliumEnvoyHTTPFilter is a Cilium-specific custom resource that can be
// referenced from Gateway API HTTPRoute rules using ExtensionRef. It defines
// Envoy HTTP filters to be injected into the filter chain at a configurable
// position.
type CiliumEnvoyHTTPFilter struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired Envoy HTTP filters and their placement.
	//
	// +kubebuilder:validation:Required
	Spec CiliumEnvoyHTTPFilterSpec `json:"spec"`
}

// CiliumEnvoyHTTPFilterSpec defines the desired state of CiliumEnvoyHTTPFilter.
type CiliumEnvoyHTTPFilterSpec struct {
	// Placement determines where the filter block is inserted relative to
	// the generated route filters in the HTTP filter chain.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=First;Last
	Placement CiliumEnvoyHTTPFilterPlacement `json:"placement"`

	// Filters is the ordered list of Envoy HTTP filters to inject.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Filters []CiliumEnvoyHTTPFilterEntry `json:"filters"`
}

// CiliumEnvoyHTTPFilterPlacement defines where custom HTTP filters are placed
// relative to the generated route filters.
type CiliumEnvoyHTTPFilterPlacement string

const (
	// CiliumEnvoyHTTPFilterPlacementFirst places custom filters before
	// generated route filters (but after mandatory internal pre-filters).
	CiliumEnvoyHTTPFilterPlacementFirst CiliumEnvoyHTTPFilterPlacement = "First"

	// CiliumEnvoyHTTPFilterPlacementLast places custom filters after
	// generated route filters (but before the mandatory terminal router filter).
	CiliumEnvoyHTTPFilterPlacementLast CiliumEnvoyHTTPFilterPlacement = "Last"
)

// CiliumEnvoyHTTPFilterEntry defines a single Envoy HTTP filter to be injected.
type CiliumEnvoyHTTPFilterEntry struct {
	// Name is the Envoy HTTP filter name, e.g. "envoy.filters.http.oauth2".
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// TypedConfig contains the Envoy filter configuration as a protobuf Any.
	// Uses the same format as CiliumEnvoyConfig resources.
	//
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Required
	TypedConfig ciliumv2.XDSResource `json:"typedConfig"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumEnvoyHTTPFilterList is a list of CiliumEnvoyHTTPFilter objects.
type CiliumEnvoyHTTPFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEnvoyHTTPFilter.
	Items []CiliumEnvoyHTTPFilter `json:"items"`
}
