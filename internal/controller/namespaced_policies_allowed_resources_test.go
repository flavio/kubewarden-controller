package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// testControllerConfigYAML is the controller configuration used by the unit
// tests and by the envtest suite.
const testControllerConfigYAML = `
namespacedPoliciesAllowedResources:
  - apiGroups: [""]
    resources: ["pods", "configmaps"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
`

func testAllowedResources() namespacedPoliciesAllowedResources {
	return namespacedPoliciesAllowedResources{
		{APIGroups: []string{""}, Resources: []string{"pods", "configmaps"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}},
	}
}

func TestNamespacedPoliciesAllowedResourcesDisallowedTargets(t *testing.T) {
	allowed := testAllowedResources()

	tests := []struct {
		name     string
		rules    []admissionregistrationv1.RuleWithOperations
		expected []string
	}{
		{
			name: "allowed resources",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{""}, []string{"pods", "configmaps"}),
				newRule([]string{"apps"}, []string{"deployments"}),
			},
			expected: []string{},
		},
		{
			name: "subresource of an allowed resource",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{""}, []string{"pods/exec", "pods/*"}),
			},
			expected: []string{},
		},
		{
			name: "resource not in the allow list",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{""}, []string{"pods", "serviceaccounts"}),
			},
			expected: []string{"serviceaccounts"},
		},
		{
			name: "apiGroup not in the allow list",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{"networking.k8s.io"}, []string{"networkpolicies"}),
			},
			expected: []string{"networkpolicies.networking.k8s.io"},
		},
		{
			name: "resource allowed only in another apiGroup",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{"extensions"}, []string{"deployments"}),
			},
			expected: []string{"deployments.extensions"},
		},
		{
			name: "one rule mixes an allowed and a not allowed resource across two apiGroups",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{"", "apps"}, []string{"pods", "daemonsets"}),
			},
			// core/pods is allowed. core/daemonsets, apps/pods and
			// apps/daemonsets are not allowed: the allow list is checked
			// pair by pair, the same way the API server matches a rule.
			expected: []string{"daemonsets", "daemonsets.apps", "pods.apps"},
		},
		{
			name: "the policy has one allowed rule and one not allowed rule",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{""}, []string{"pods"}),
				newRule([]string{"apps"}, []string{"daemonsets"}),
			},
			// The allowed rule (pods) contributes nothing to the result.
			expected: []string{"daemonsets.apps"},
		},
		{
			name: "wildcards are never allowed",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{"*"}, []string{"pods"}),
				newRule([]string{"apps"}, []string{"*"}),
				newRule([]string{"apps"}, []string{"*/*"}),
				newRule([]string{"apps"}, []string{"*/scale"}),
			},
			expected: []string{"*.apps", "*/*.apps", "*/scale.apps", "pods.*"},
		},
		{
			name: "result is sorted and has no duplicates",
			rules: []admissionregistrationv1.RuleWithOperations{
				newRule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings", "roles"}),
				newRule([]string{"rbac.authorization.k8s.io", ""}, []string{"roles", "secrets"}),
			},
			expected: []string{
				"rolebindings.rbac.authorization.k8s.io",
				"roles",
				"roles.rbac.authorization.k8s.io",
				"secrets",
				"secrets.rbac.authorization.k8s.io",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, allowed.disallowedTargets(test.rules))
		})
	}
}

func TestNamespacedPoliciesAllowedResourcesEmptyListDeniesEverything(t *testing.T) {
	allowed := namespacedPoliciesAllowedResources{}
	rules := []admissionregistrationv1.RuleWithOperations{
		newRule([]string{""}, []string{"pods"}),
	}
	assert.Equal(t, []string{"pods"}, allowed.disallowedTargets(rules))
}

func TestIsNamespacedPolicyAllowed(t *testing.T) {
	allowed := testAllowedResources()
	disallowedRules := []admissionregistrationv1.RuleWithOperations{
		newRule([]string{"networking.k8s.io"}, []string{"networkpolicies"}),
	}
	mixedRules := []admissionregistrationv1.RuleWithOperations{
		newRule([]string{""}, []string{"pods"}),
		newRule([]string{"apps"}, []string{"daemonsets"}),
	}

	tests := []struct {
		name               string
		policy             policiesv1.Policy
		expectedAllowed    bool
		expectedDisallowed []string
	}{
		{
			name:            "ClusterAdmissionPolicy is always allowed",
			policy:          policiesv1.NewClusterAdmissionPolicyFactory().WithRules(disallowedRules).Build(),
			expectedAllowed: true,
		},
		{
			name:            "ClusterAdmissionPolicyGroup is always allowed",
			policy:          policiesv1.NewClusterAdmissionPolicyGroupFactory().WithRules(disallowedRules).Build(),
			expectedAllowed: true,
		},
		{
			name:            "AdmissionPolicy with allowed rules",
			policy:          policiesv1.NewAdmissionPolicyFactory().Build(),
			expectedAllowed: true,
		},
		{
			name:               "AdmissionPolicy with disallowed rules",
			policy:             policiesv1.NewAdmissionPolicyFactory().WithRules(disallowedRules).Build(),
			expectedAllowed:    false,
			expectedDisallowed: []string{"networkpolicies.networking.k8s.io"},
		},
		{
			name:               "AdmissionPolicyGroup with disallowed rules",
			policy:             policiesv1.NewAdmissionPolicyGroupFactory().WithRules(disallowedRules).Build(),
			expectedAllowed:    false,
			expectedDisallowed: []string{"networkpolicies.networking.k8s.io"},
		},
		{
			// A policy is rejected as a whole when even one of its rules
			// targets a not allowed resource. The allowed rule (pods)
			// contributes nothing to the reported targets.
			name:               "AdmissionPolicy with one allowed rule and one not allowed rule",
			policy:             policiesv1.NewAdmissionPolicyFactory().WithRules(mixedRules).Build(),
			expectedAllowed:    false,
			expectedDisallowed: []string{"daemonsets.apps"},
		},
		{
			// The allow list check does not read spec.mutating: a mutating
			// AdmissionPolicy is rejected the same way as a validating one.
			name:               "mutating AdmissionPolicy with disallowed rules",
			policy:             policiesv1.NewAdmissionPolicyFactory().WithMutating(true).WithRules(disallowedRules).Build(),
			expectedAllowed:    false,
			expectedDisallowed: []string{"networkpolicies.networking.k8s.io"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualAllowed, actualDisallowed := isNamespacedPolicyAllowed(test.policy, allowed)
			assert.Equal(t, test.expectedAllowed, actualAllowed)
			if test.expectedAllowed {
				assert.Empty(t, actualDisallowed)
			} else {
				assert.Equal(t, test.expectedDisallowed, actualDisallowed)
			}
		})
	}
}

func TestNamespacedPolicyRejectedMessage(t *testing.T) {
	t.Run("lists the disallowed resources", func(t *testing.T) {
		message := namespacedPolicyRejectedMessage(
			[]string{"serviceaccounts", "networkpolicies.networking.k8s.io"},
			testAllowedResources(),
			constants.DefaultControllerConfigMapName,
		)
		assert.Contains(t, message, "serviceaccounts, networkpolicies.networking.k8s.io")
		assert.Contains(t, message, "namespacedPoliciesAllowedResources")
		assert.NotContains(t, message, "wildcard")
		assert.NotContains(t, message, "empty")
	})

	t.Run("explains that wildcards are not allowed", func(t *testing.T) {
		message := namespacedPolicyRejectedMessage(
			[]string{"*.apps"},
			testAllowedResources(),
			constants.DefaultControllerConfigMapName,
		)
		assert.Contains(t, message, "*.apps")
		assert.Contains(t, message, "wildcards")
	})

	t.Run("explains that the allow list is empty", func(t *testing.T) {
		message := namespacedPolicyRejectedMessage(
			[]string{"pods"},
			namespacedPoliciesAllowedResources{},
			constants.DefaultControllerConfigMapName,
		)
		assert.Contains(t, message, "empty")
		assert.Contains(t, message, constants.DefaultControllerConfigMapName)
		assert.Contains(t, message, constants.ControllerConfigNamespacedPoliciesAllowedResourcesKey)
	})
}

func TestValidateAPIGroup(t *testing.T) {
	tests := []struct {
		name        string
		apiGroup    string
		expectedErr error
	}{
		{"the core apiGroup is valid", "", nil},
		{"a named apiGroup is valid", "apps", nil},
		{"a wildcard apiGroup is not valid", "*", errAllowListWildcard},
		{"a wildcard mixed with a name is not valid", "apps*", errAllowListWildcard},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAPIGroup(test.apiGroup)
			if test.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.expectedErr)
			}
		})
	}
}

func TestValidateResource(t *testing.T) {
	tests := []struct {
		name        string
		resource    string
		expectedErr error
	}{
		{"a named resource is valid", "pods", nil},
		{"an empty resource is not valid", "", errAllowListEmptyItem},
		{"a wildcard resource is not valid", "*", errAllowListWildcard},
		{"a double wildcard resource is not valid", "*/*", errAllowListWildcard},
		{"a subresource is not valid", "pods/exec", errAllowListSubresource},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateResource(test.resource)
			if test.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.expectedErr)
			}
		})
	}
}

func newRule(apiGroups, resources []string) admissionregistrationv1.RuleWithOperations {
	return admissionregistrationv1.RuleWithOperations{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   apiGroups,
			APIVersions: []string{"v1"},
			Resources:   resources,
		},
	}
}
