/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ClusterPolicyGroupSpec struct {
	GroupSpec `json:""`

	// Policies is a list of policies that are part of the group that will
	// be available to be called in the evaluation expression field.
	// Each policy in the group should be a Kubewarden policy.
	// +kubebuilder:validation:Required
	Policies PolicyGroupMembersWithContext `json:"policies"`
}

// ClusterAdmissionPolicyGroupSpec defines the desired state of ClusterAdmissionPolicyGroup.
type ClusterAdmissionPolicyGroupSpec struct {
	ClusterPolicyGroupSpec `json:""`

	// NamespaceSelector decides whether to run the webhook on an object based
	// on whether the namespace for that object matches the selector. If the
	// object itself is a namespace, the matching is performed on
	// object.metadata.labels. If the object is another cluster scoped resource,
	// it never skips the webhook.
	//
	// For example, to run the webhook on objects whose namespace does not have
	// a runlevel of 0 or 1, use this selector:
	//
	// ```json
	// {
	//   "namespaceSelector": {
	//     "matchExpressions": [
	//       {
	//         "key": "runlevel",
	//         "operator": "NotIn",
	//         "values": ["0", "1"]
	//       }
	//     ]
	//   }
	// }
	// ```
	//
	// To run the webhook only on objects whose namespace has an environment of
	// prod or staging, use this selector:
	//
	// ```json
	// {
	//   "namespaceSelector": {
	//     "matchExpressions": [
	//       {
	//         "key": "environment",
	//         "operator": "In",
	//         "values": ["prod", "staging"]
	//       }
	//     ]
	//   }
	// }
	// ```
	//
	// See
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
	// for more examples of label selectors.
	//
	// Default to the empty LabelSelector, which matches everything.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// AllowInsideAdmissionControllerNamespace controls whether the policy should also be
	// evaluated for resources in the namespace where Kubewarden is deployed.
	// By default (false), an exclusion rule is added to the webhook so that the
	// Kubewarden namespace is never targeted, protecting against an accidental
	// lockout. Set this to true only if you deliberately want the policy to apply
	// inside the Kubewarden namespace.
	// Warning: setting this to true may cause a deadlock if the policy prevents
	// Kubewarden components from starting.
	// +optional
	AllowInsideAdmissionControllerNamespace bool `json:"allowInsideAdmissionControllerNamespace,omitempty"`
}

// ClusterAdmissionPolicyGroup is the Schema for the clusteradmissionpolicies API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=capg
// +kubebuilder:storageversion
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +kubebuilder:printcolumn:name="Policy Server",type=string,JSONPath=`.spec.policyServer`,description="Bound to Policy Server"
// +kubebuilder:printcolumn:name="Mutating",type=boolean,JSONPath=`.spec.mutating`,description="Whether the policy is mutating"
// +kubebuilder:printcolumn:name="BackgroundAudit",type=boolean,JSONPath=`.spec.backgroundAudit`,description="Whether the policy is used in audit checks"
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`,description="Policy deployment mode"
// +kubebuilder:printcolumn:name="Observed mode",type=string,JSONPath=`.status.mode`,description="Policy deployment mode observed on the assigned Policy Server"
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.policyStatus`,description="Status of the policy"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=".metadata.annotations['io\\.kubewarden\\.policy\\.severity']",priority=1
// +kubebuilder:printcolumn:name="Category",type=string,JSONPath=".metadata.annotations['io\\.kubewarden\\.policy\\.category']",priority=1
type ClusterAdmissionPolicyGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterAdmissionPolicyGroupSpec `json:"spec,omitempty"`
	Status PolicyStatus                    `json:"status,omitempty"`
}

// ClusterAdmissionPolicyGroupList contains a list of ClusterAdmissionPolicyGroup
// +kubebuilder:object:root=true
type ClusterAdmissionPolicyGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterAdmissionPolicyGroup `json:"items"`
}

func (r *ClusterAdmissionPolicyGroup) SetStatus(status PolicyStatusEnum) {
	r.Status.PolicyStatus = status
}

func (r *ClusterAdmissionPolicyGroup) GetPolicyMode() PolicyMode {
	return r.Spec.Mode
}

func (r *ClusterAdmissionPolicyGroup) SetPolicyModeStatus(policyMode PolicyModeStatus) {
	r.Status.PolicyMode = policyMode
}

func (r *ClusterAdmissionPolicyGroup) GetModule() string {
	return ""
}

func (r *ClusterAdmissionPolicyGroup) IsMutating() bool {
	// By design, AdmissionPolicyGroup is always non-mutating.
	// Policy groups can be used only for validating admission requests
	return false
}

func (r *ClusterAdmissionPolicyGroup) IsContextAware() bool {
	for _, policy := range r.Spec.Policies {
		if len(policy.ContextAwareResources) > 0 {
			return true
		}
	}
	return false
}

func (r *ClusterAdmissionPolicyGroup) GetSettings() runtime.RawExtension {
	return runtime.RawExtension{}
}

func (r *ClusterAdmissionPolicyGroup) GetStatus() *PolicyStatus {
	return &r.Status
}

func (r *ClusterAdmissionPolicyGroup) GetPolicyGroupMembersWithContext() PolicyGroupMembersWithContext {
	return r.Spec.Policies
}

func (r *ClusterAdmissionPolicyGroup) GetExpression() string {
	return r.Spec.Expression
}

func (r *ClusterAdmissionPolicyGroup) GetMessage() string {
	return r.Spec.Message
}

func (r *ClusterAdmissionPolicyGroup) CopyInto(policy *Policy) {
	*policy = r.DeepCopy()
}

func (r *ClusterAdmissionPolicyGroup) GetSideEffects() *admissionregistrationv1.SideEffectClass {
	return r.Spec.SideEffects
}

func (r *ClusterAdmissionPolicyGroup) GetFailurePolicy() *admissionregistrationv1.FailurePolicyType {
	return r.Spec.FailurePolicy
}

func (r *ClusterAdmissionPolicyGroup) GetMatchPolicy() *admissionregistrationv1.MatchPolicyType {
	return r.Spec.MatchPolicy
}

func (r *ClusterAdmissionPolicyGroup) GetRules() []admissionregistrationv1.RuleWithOperations {
	return r.Spec.Rules
}

func (r *ClusterAdmissionPolicyGroup) GetMatchConditions() []admissionregistrationv1.MatchCondition {
	return r.Spec.MatchConditions
}

func (r *ClusterAdmissionPolicyGroup) GetNamespaceSelector() *metav1.LabelSelector {
	return r.Spec.NamespaceSelector
}

func (r *ClusterAdmissionPolicyGroup) GetAllowInsideAdmissionControllerNamespace() bool {
	return r.Spec.AllowInsideAdmissionControllerNamespace
}

func (r *ClusterAdmissionPolicyGroup) GetObjectSelector() *metav1.LabelSelector {
	return r.Spec.ObjectSelector
}

func (r *ClusterAdmissionPolicyGroup) GetTimeoutSeconds() *int32 {
	return r.Spec.TimeoutSeconds
}

func (r *ClusterAdmissionPolicyGroup) GetTimeoutEvalSeconds() *int32 {
	// Only policy group members have timeoutEvalSeconds
	return nil
}

func (r *ClusterAdmissionPolicyGroup) GetObjectMeta() *metav1.ObjectMeta {
	return &r.ObjectMeta
}

func (r *ClusterAdmissionPolicyGroup) GetPolicyServer() string {
	return r.Spec.PolicyServer
}

// GetUniqueName returns the cluster-wide unique identity of the policy.
// The `.` delimiter and the dot-free, kind-unique token (`capg`) guarantee
// that two distinct policies can never collide, regardless of their kind.
func (r *ClusterAdmissionPolicyGroup) GetUniqueName() string {
	return "kw.capg." + r.Name
}

func (r *ClusterAdmissionPolicyGroup) GetContextAwareResources() []ContextAwareResource {
	// We return an empty slice here because the policy members have the
	// context aware resources. Therefore, the policy group does not need
	// to have them.
	return []ContextAwareResource{}
}

func (r *ClusterAdmissionPolicyGroup) GetBackgroundAudit() bool {
	return r.Spec.BackgroundAudit
}

func (r *ClusterAdmissionPolicyGroup) GetSeverity() (string, bool) {
	severity, present := r.Annotations[AnnotationSeverity]
	return severity, present
}

func (r *ClusterAdmissionPolicyGroup) GetCategory() (string, bool) {
	category, present := r.Annotations[AnnotationCategory]
	return category, present
}

func (r *ClusterAdmissionPolicyGroup) GetTitle() (string, bool) {
	title, present := r.Annotations[AnnotationTitle]
	return title, present
}

func (r *ClusterAdmissionPolicyGroup) GetDescription() (string, bool) {
	desc, present := r.Annotations[AnnotationDescription]
	return desc, present
}
