package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
)

// TestGetPolicyServerContainerEnvOrdering verifies the env var precedence
// contract for the policy-server container: user-provided vars (Spec.Env) come
// first, and controller-managed vars are appended last so that, under
// kubelet's "last wins" semantics for duplicate names, the controller's values
// always take precedence.
func TestGetPolicyServerContainerEnvOrdering(t *testing.T) {
	const kubewardenPortEnv = "KUBEWARDEN_PORT"
	const userOverrideValue = "9999"

	ps := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: policiesv1.PolicyServerSpec{
			Image: "ghcr.io/kubewarden/policy-server:latest",
			Env: []corev1.EnvVar{
				{Name: "USER_VAR", Value: "user-val"},
				// Deliberately collides with a controller-managed var.
				{Name: kubewardenPortEnv, Value: userOverrideValue},
			},
		},
	}

	container := getPolicyServerContainer(ps)

	// User vars come first.
	if len(container.Env) == 0 || container.Env[0].Name != "USER_VAR" {
		t.Fatalf("expected first env var to be the user-provided USER_VAR, got %+v", container.Env)
	}

	// Controller-managed vars win: the LAST occurrence of KUBEWARDEN_PORT
	// must be the controller's value, not the user's override.
	var lastPort string
	for _, e := range container.Env {
		if e.Name == kubewardenPortEnv {
			lastPort = e.Value
		}
	}
	if lastPort == userOverrideValue {
		t.Fatalf("expected controller-managed %s to override user value %q, but user value won", kubewardenPortEnv, userOverrideValue)
	}
}
