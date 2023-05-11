package admission

import (
	"testing"

	policiesv1 "github.com/kubewarden/kubewarden-controller/apis/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestMetricsEnabled(t *testing.T) {
	reconciler := newReconciler([]client.Object{}, true)
	if !reconciler.MetricsEnabled {
		t.Fatal("Metric not enabled")
	}
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
		},
	}
	service := reconciler.service(policyServer)
	for _, port := range service.Spec.Ports {
		if port.Port == constants.PolicyServerMetricsPort {
			return
		}
	}
	t.Error("Policy Server service is missing metrics port")
}
