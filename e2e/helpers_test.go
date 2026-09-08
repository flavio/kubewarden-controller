package e2e

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

const (
	testTimeout      = 5 * time.Minute
	testPollInterval = 1 * time.Second
)

type contextKey string

const (
	policyServerNameKey contextKey = "policyServerName"
	policyNameKey       contextKey = "policyName"
	policyKey           contextKey = "policy"
	controllerConfigKey contextKey = "controllerConfig"
)

func createNamespaceWithRetry(ctx context.Context, cfg *envconf.Config, name string) error {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	err := cfg.Client().Resources().Create(ctx, namespace)
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func createPolicyServerAndWaitForItsService(ctx context.Context, cfg *envconf.Config, policyServer *policiesv1.PolicyServer) error {
	err := cfg.Client().Resources().Create(ctx, policyServer)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	// Wait for the Service associated with the PolicyServer to be created
	serviceName := policyServer.NameWithPrefix()
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
		},
	}
	serviceList := &corev1.ServiceList{
		Items: []corev1.Service{service},
	}
	err = wait.For(conditions.New(cfg.Client().Resources()).ResourcesFound(serviceList),
		wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
	if err != nil {
		return err
	}

	// Wait for the Deployment to be available
	return wait.For(conditions.New(cfg.Client().Resources()).DeploymentConditionMatch(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespace}},
		appsv1.DeploymentAvailable,
		corev1.ConditionTrue,
	), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
}

// waitForAdmissionPolicyActive waits until the given AdmissionPolicy
// transitions to the active status.
func waitForAdmissionPolicyActive(cfg *envconf.Config, policyName, policyNamespace string) error {
	return wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
		&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
		func(object k8s.Object) bool {
			p := object.(*policiesv1.AdmissionPolicy)
			return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
		},
	), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
}

func getTestCASecret(ctx context.Context, cfg *envconf.Config) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := cfg.Client().Resources(namespace).Get(ctx, constants.CARootSecretName, namespace, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func verifyWebhookMetadata(labels, annotations map[string]string, policyName, policyNamespace string) bool {
	if labels[constants.PartOfLabelKey] != constants.PartOfLabelValue {
		return false
	}
	if annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != policyName {
		return false
	}
	if annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != policyNamespace {
		return false
	}
	return true
}

// containsFinalizer returns true when the list contains the finalizer.
func containsFinalizer(finalizers []string, finalizer string) bool {
	return slices.Contains(finalizers, finalizer)
}

// isPolicyRejectedFor returns true when the policy status is rejected and
// the PolicyActive condition names the given resource.
func isPolicyRejectedFor(status *policiesv1.PolicyStatus, resource string) bool {
	if status.PolicyStatus != policiesv1.PolicyStatusRejected {
		return false
	}
	condition := apimeta.FindStatusCondition(status.Conditions, string(policiesv1.PolicyActive))
	if condition == nil || condition.Status != metav1.ConditionFalse {
		return false
	}
	return condition.Reason == string(policiesv1.PolicyReasonResourcesNotAllowed) && strings.Contains(condition.Message, resource)
}

// getControllerConfig returns the controller configuration file (config.yaml)
// stored in the controller configuration ConfigMap.
func getControllerConfig(ctx context.Context, cfg *envconf.Config) (string, error) {
	configMap := &corev1.ConfigMap{}
	err := cfg.Client().Resources(namespace).Get(ctx, constants.DefaultControllerConfigMapName, namespace, configMap)
	if err != nil {
		return "", err
	}
	return configMap.Data[constants.ControllerConfigKey], nil
}

// setControllerConfig replaces the controller configuration file (config.yaml)
// stored in the controller configuration ConfigMap.
func setControllerConfig(ctx context.Context, cfg *envconf.Config, data string) error {
	configMap := &corev1.ConfigMap{}
	err := cfg.Client().Resources(namespace).Get(ctx, constants.DefaultControllerConfigMapName, namespace, configMap)
	if err != nil {
		return err
	}
	if configMap.Data == nil {
		configMap.Data = map[string]string{}
	}
	configMap.Data[constants.ControllerConfigKey] = data
	return cfg.Client().Resources(namespace).Update(ctx, configMap)
}

// waitForAdmissionPolicyRejected waits until the given AdmissionPolicy
// transitions to the rejected status, with a PolicyActive condition that
// names the given resource.
func waitForAdmissionPolicyRejected(cfg *envconf.Config, policyName, policyNamespace, resource string) error {
	return wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
		&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
		func(object k8s.Object) bool {
			p := object.(*policiesv1.AdmissionPolicy)
			return isPolicyRejectedFor(&p.Status, resource)
		},
	), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
}

// waitForPolicyServerConfigMapPolicy waits until the PolicyServer ConfigMap
// lists the policy (wantPresent true), or until it no longer lists the
// policy (wantPresent false). The check looks at the policies.yml entry.
// ResourceMatch retries the check on a Get error, the same as every other
// waiter in this file.
func waitForPolicyServerConfigMapPolicy(cfg *envconf.Config, policyServerName, policyUniqueName string, wantPresent bool) error {
	return wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "policy-server-" + policyServerName, Namespace: namespace}},
		func(object k8s.Object) bool {
			configMap := object.(*corev1.ConfigMap)
			policies := map[string]json.RawMessage{}
			if err := json.Unmarshal([]byte(configMap.Data[constants.PolicyServerConfigPoliciesEntry]), &policies); err != nil {
				return false
			}
			_, found := policies[policyUniqueName]
			return found == wantPresent
		},
	), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
}
