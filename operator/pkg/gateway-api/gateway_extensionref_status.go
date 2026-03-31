// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// checkExtensionRefStatus validates ExtensionRef filters on an HTTPRoute
// and sets ResolvedRefs=False on any matching Gateway parent when a reference
// cannot be resolved.
func (r *gatewayReconciler) checkExtensionRefStatus(
	input routechecks.Input,
	hr *gatewayv1.HTTPRoute,
	cehfs []v2alpha1.CiliumEnvoyHTTPFilter,
) {
	cond, ok := r.extensionRefCondition(hr, cehfs)
	if ok {
		return
	}
	for _, parent := range hr.Spec.ParentRefs {
		if !helpers.IsGateway(parent) || !r.parentIsMatchingGateway(parent, hr.Namespace) {
			continue
		}
		input.SetParentCondition(parent, cond)
	}
}

// extensionRefCondition checks all rules in an HTTPRoute for unresolvable
// ExtensionRef filters. It returns (condition, false) on the first failure.
// If all refs are valid or no ExtensionRef is present, it returns (zero, true).
func (r *gatewayReconciler) extensionRefCondition(
	hr *gatewayv1.HTTPRoute,
	cehfs []v2alpha1.CiliumEnvoyHTTPFilter,
) (metav1.Condition, bool) {
	for _, rule := range hr.Spec.Rules {
		for _, f := range rule.Filters {
			if f.Type != gatewayv1.HTTPRouteFilterExtensionRef || f.ExtensionRef == nil {
				continue
			}
			ref := f.ExtensionRef

			if !r.operatorConfig.EnableGatewayAPIExtensionRefFilters {
				return metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonRefNotPermitted),
					Message: fmt.Sprintf("ExtensionRef %q requires the EnableGatewayAPIExtensionRefFilters feature flag", ref.Name),
				}, false
			}

			if string(ref.Group) != v2alpha1.SchemeGroupVersion.Group || string(ref.Kind) != "CiliumEnvoyHTTPFilter" {
				return metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonInvalidKind),
					Message: fmt.Sprintf("ExtensionRef %q has unsupported group/kind %s/%s; expected cilium.io/CiliumEnvoyHTTPFilter", ref.Name, ref.Group, ref.Kind),
				}, false
			}

			found := false
			for i := range cehfs {
				if cehfs[i].Name == string(ref.Name) && cehfs[i].Namespace == hr.Namespace {
					found = true
					break
				}
			}
			if !found {
				return metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("ExtensionRef CiliumEnvoyHTTPFilter %q not found in namespace %q", ref.Name, hr.Namespace),
				}, false
			}
		}
	}
	return metav1.Condition{}, true
}
