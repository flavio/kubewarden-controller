package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/kubewarden/adm-controller/internal/constants"
)

// controllerConfig is the configuration of the controller. The Helm chart
// writes it as a YAML object to the config.yaml key of the controller
// configuration ConfigMap.
type controllerConfig struct {
	// NamespacedPoliciesAllowedResources is the list of resources that
	// namespaced policies can target.
	NamespacedPoliciesAllowedResources []admissionregistrationv1.Rule `json:"namespacedPoliciesAllowedResources"`
}

// parseControllerConfig parses the controller configuration file. Unknown
// top-level keys are ignored: a newer chart can add keys that an older
// controller does not know yet. When the file cannot be parsed, the
// function logs the error and returns an empty configuration.
func parseControllerConfig(data string, log logr.Logger) controllerConfig {
	config := controllerConfig{}
	if err := sigsyaml.Unmarshal([]byte(data), &config); err != nil {
		log.Error(err, "cannot parse the controller configuration, all namespaced policies are rejected",
			"key", constants.ControllerConfigKey)
		return controllerConfig{}
	}

	config.NamespacedPoliciesAllowedResources = validateNamespacedPoliciesAllowedResources(config.NamespacedPoliciesAllowedResources, log)

	return config
}

// loadControllerConfig reads the controller configuration from the
// ConfigMap. When the ConfigMap or the config.yaml key does not exist, the
// function returns an empty configuration.
func loadControllerConfig(
	ctx context.Context,
	reader client.Reader,
	namespace, name string,
	log logr.Logger,
) (controllerConfig, error) {
	configMap := corev1.ConfigMap{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &configMap); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("controller configuration ConfigMap not found, all namespaced policies are rejected",
				"configmap", name, "namespace", namespace)
			return controllerConfig{}, nil
		}
		return controllerConfig{}, fmt.Errorf("cannot read the controller configuration ConfigMap %s/%s: %w", namespace, name, err)
	}

	data, found := configMap.Data[constants.ControllerConfigKey]
	if !found {
		log.Info("controller configuration ConfigMap has no configuration file, all namespaced policies are rejected",
			"configmap", name, "namespace", namespace, "key", constants.ControllerConfigKey)
		return controllerConfig{}, nil
	}

	return parseControllerConfig(data, log), nil
}
