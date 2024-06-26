package naming

import (
	"github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1alpha2"
)

func PolicyServerDeploymentNameForPolicyServer(policyServer *v1alpha2.PolicyServer) string {
	return PolicyServerDeploymentNameForPolicyServerName(policyServer.Name)
}

func PolicyServerDeploymentNameForPolicyServerName(policyServerName string) string {
	return "policy-server-" + policyServerName
}
