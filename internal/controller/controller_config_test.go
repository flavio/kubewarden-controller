package controller

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/adm-controller/internal/constants"
)

func TestParseControllerConfig(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected controllerConfig
	}{
		{
			name: "parses a valid configuration",
			data: testControllerConfigYAML,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: testAllowedResources(),
			},
		},
		{
			name:     "empty document gives an empty configuration",
			data:     "",
			expected: controllerConfig{NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{}},
		},
		{
			name:     "empty object gives an empty configuration",
			data:     "{}",
			expected: controllerConfig{NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{}},
		},
		{
			name:     "empty allow list gives an empty allow list",
			data:     "namespacedPoliciesAllowedResources: []",
			expected: controllerConfig{NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{}},
		},
		{
			name:     "invalid YAML gives an empty configuration",
			data:     "namespacedPoliciesAllowedResources: [not valid",
			expected: controllerConfig{},
		},
		{
			name:     "a list instead of an object gives an empty configuration",
			data:     "- apiGroups: [\"\"]\n  resources: [\"pods\"]\n",
			expected: controllerConfig{},
		},
		{
			name: "ignores unknown top-level keys",
			data: `
futureSetting: true
namespacedPoliciesAllowedResources:
  - apiGroups: ["batch"]
    resources: ["jobs"]
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{"batch"}, Resources: []string{"jobs"}},
				},
			},
		},
		{
			name: "ignores the apiVersions and scope fields of an entry",
			data: `
namespacedPoliciesAllowedResources:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    scope: Namespaced
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{""}, Resources: []string{"pods"}},
				},
			},
		},
		{
			name: "skips an apiGroup that contains a wildcard and keeps the other apiGroups",
			data: `
namespacedPoliciesAllowedResources:
  - apiGroups: ["*", "apps"]
    resources: ["deployments", "statefulsets"]
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}},
				},
			},
		},
		{
			name: "skips an entry when no valid apiGroup remains",
			data: `
namespacedPoliciesAllowedResources:
  - apiGroups: ["*"]
    resources: ["pods"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
				},
			},
		},
		{
			name: "skips a resource that contains a wildcard and keeps the other resources",
			data: `
namespacedPoliciesAllowedResources:
  - apiGroups: [""]
    resources: ["pods", "*"]
  - apiGroups: ["apps"]
    resources: ["*/*", "deployments"]
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{""}, Resources: []string{"pods"}},
					{APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
				},
			},
		},
		{
			name: "skips an entry when no valid resource remains",
			data: `
namespacedPoliciesAllowedResources:
  - apiGroups: ["*"]
    resources: ["*"]
  - apiGroups: ["apps"]
    resources: ["*"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{"batch"}, Resources: []string{"jobs"}},
				},
			},
		},
		{
			name: "skips a subresource and keeps the other resources",
			data: `
namespacedPoliciesAllowedResources:
  - apiGroups: [""]
    resources: ["pods/exec", "pods"]
  - apiGroups: ["apps"]
    resources: ["deployments/scale"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{""}, Resources: []string{"pods"}},
					{APIGroups: []string{"batch"}, Resources: []string{"jobs"}},
				},
			},
		},
		{
			name: "skips empty items and empty entries",
			data: `
namespacedPoliciesAllowedResources:
  - apiGroups: []
    resources: ["pods"]
  - apiGroups: [""]
    resources: []
  - apiGroups: [""]
    resources: [""]
  - apiGroups: [""]
    resources: ["", "configmaps"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
`,
			expected: controllerConfig{
				NamespacedPoliciesAllowedResources: namespacedPoliciesAllowedResources{
					{APIGroups: []string{""}, Resources: []string{"configmaps"}},
					{APIGroups: []string{"batch"}, Resources: []string{"jobs"}},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := parseControllerConfig(test.data, logr.Discard())
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestLoadControllerConfig(t *testing.T) {
	tests := []struct {
		name      string
		configMap *corev1.ConfigMap
		expected  controllerConfig
	}{
		{
			name: "reads the configuration from the ConfigMap",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: constants.DefaultControllerConfigMapName, Namespace: testDeploymentsNamespace},
				Data: map[string]string{
					constants.ControllerConfigKey: testControllerConfigYAML,
				},
			},
			expected: controllerConfig{NamespacedPoliciesAllowedResources: testAllowedResources()},
		},
		{
			name:      "missing ConfigMap gives an empty configuration",
			configMap: nil,
			expected:  controllerConfig{},
		},
		{
			name: "missing key gives an empty configuration",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: constants.DefaultControllerConfigMapName, Namespace: testDeploymentsNamespace},
				Data:       map[string]string{"other-key": "value"},
			},
			expected: controllerConfig{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder := fake.NewClientBuilder()
			if test.configMap != nil {
				builder = builder.WithObjects(test.configMap)
			}
			k8sClient := builder.Build()

			actual, err := loadControllerConfig(
				t.Context(), k8sClient, testDeploymentsNamespace, constants.DefaultControllerConfigMapName, logr.Discard())
			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
