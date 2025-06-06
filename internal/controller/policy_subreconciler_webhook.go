package controller

import (
	"context"
	"fmt"
	"path/filepath"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=create;delete;list;patch;watch

//nolint:dupl // This function is similar to the other reconcileMutatingWebhookConfiguration
func (r *policySubReconciler) reconcileValidatingWebhookConfiguration(
	ctx context.Context,
	policy policiesv1.Policy,
	admissionSecret *corev1.Secret,
	policyServerNameWithPrefix string,
) error {
	webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.GetUniqueName(),
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, webhook, func() error {
		admissionPath := filepath.Join("/validate", policy.GetUniqueName())
		admissionPort := int32(constants.PolicyServerServicePort)

		service := admissionregistrationv1.ServiceReference{
			Namespace: r.deploymentsNamespace,
			Name:      policyServerNameWithPrefix,
			Path:      &admissionPath,
			Port:      &admissionPort,
		}

		sideEffects := policy.GetSideEffects()
		if sideEffects == nil {
			noneSideEffects := admissionregistrationv1.SideEffectClassNone
			sideEffects = &noneSideEffects
		}

		webhook.Name = policy.GetUniqueName()
		webhook.Labels = map[string]string{
			constants.PartOfLabelKey: constants.PartOfLabelValue,
		}
		webhook.Annotations = map[string]string{
			constants.WebhookConfigurationPolicyNameAnnotationKey:      policy.GetName(),
			constants.WebhookConfigurationPolicyNamespaceAnnotationKey: policy.GetNamespace(),
		}

		webhook.Webhooks = []admissionregistrationv1.ValidatingWebhook{
			{
				Name: policy.GetUniqueName() + ".kubewarden.admission",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &service,
					CABundle: admissionSecret.Data[constants.CARootCert],
				},
				Rules:                   policy.GetRules(),
				FailurePolicy:           policy.GetFailurePolicy(),
				MatchPolicy:             policy.GetMatchPolicy(),
				NamespaceSelector:       r.namespaceSelector(policy),
				ObjectSelector:          policy.GetObjectSelector(),
				SideEffects:             sideEffects,
				TimeoutSeconds:          policy.GetTimeoutSeconds(),
				AdmissionReviewVersions: []string{"v1"},
			},
		}

		if r.featureGateAdmissionWebhookMatchConditions {
			webhook.Webhooks[0].MatchConditions = policy.GetMatchConditions()
		} else if len(policy.GetMatchConditions()) > 0 {
			r.Log.Info("Skipping matchConditions for policy as the feature gate AdmissionWebhookMatchConditions is disabled",
				"policy", policy.GetName())
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("cannot reconcile validating webhook: %w", err)
	}

	return nil
}

func (r *policySubReconciler) reconcileValidatingWebhookConfigurationDeletion(ctx context.Context, admissionPolicy policiesv1.Policy) error {
	webhook := admissionregistrationv1.ValidatingWebhookConfiguration{}
	err := r.Get(ctx, types.NamespacedName{Name: admissionPolicy.GetUniqueName()}, &webhook)
	if err == nil {
		if err = r.Delete(ctx, &webhook); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("cannot delete validating webhook: %w", err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot retrieve validating webhook: %w", err)
	}

	return nil
}

//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=create;delete;list;patch;watch

//nolint:dupl // This function is similar to the other reconcileValidatingWebhookConfiguration
func (r *policySubReconciler) reconcileMutatingWebhookConfiguration(
	ctx context.Context,
	policy policiesv1.Policy,
	admissionSecret *corev1.Secret,
	policyServerNameWithPrefix string,
) error {
	webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.GetUniqueName(),
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, webhook, func() error {
		admissionPath := filepath.Join("/validate", policy.GetUniqueName())
		admissionPort := int32(constants.PolicyServerServicePort)

		service := admissionregistrationv1.ServiceReference{
			Namespace: r.deploymentsNamespace,
			Name:      policyServerNameWithPrefix,
			Path:      &admissionPath,
			Port:      &admissionPort,
		}

		sideEffects := policy.GetSideEffects()
		if sideEffects == nil {
			noneSideEffects := admissionregistrationv1.SideEffectClassNone
			sideEffects = &noneSideEffects
		}
		webhook.Name = policy.GetUniqueName()
		webhook.Labels = map[string]string{
			constants.PartOfLabelKey: constants.PartOfLabelValue,
		}
		webhook.Annotations = map[string]string{
			constants.WebhookConfigurationPolicyNameAnnotationKey:      policy.GetName(),
			constants.WebhookConfigurationPolicyNamespaceAnnotationKey: policy.GetNamespace(),
		}
		webhook.Webhooks = []admissionregistrationv1.MutatingWebhook{
			{
				Name: policy.GetUniqueName() + ".kubewarden.admission",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &service,
					CABundle: admissionSecret.Data[constants.CARootCert],
				},
				Rules:                   policy.GetRules(),
				FailurePolicy:           policy.GetFailurePolicy(),
				MatchPolicy:             policy.GetMatchPolicy(),
				NamespaceSelector:       r.namespaceSelector(policy),
				ObjectSelector:          policy.GetObjectSelector(),
				SideEffects:             sideEffects,
				TimeoutSeconds:          policy.GetTimeoutSeconds(),
				AdmissionReviewVersions: []string{"v1"},
			},
		}

		if r.featureGateAdmissionWebhookMatchConditions {
			webhook.Webhooks[0].MatchConditions = policy.GetMatchConditions()
		} else if len(policy.GetMatchConditions()) > 0 {
			r.Log.Info("Skipping matchConditions for policy as the feature gate AdmissionWebhookMatchConditions is disabled",
				"policy", policy.GetName())
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("cannot reconcile mutating webhook: %w", err)
	}

	return nil
}

func (r *policySubReconciler) reconcileMutatingWebhookConfigurationDeletion(ctx context.Context, admissionPolicy policiesv1.Policy) error {
	webhook := admissionregistrationv1.MutatingWebhookConfiguration{}
	err := r.Get(ctx, types.NamespacedName{Name: admissionPolicy.GetUniqueName()}, &webhook)
	if err == nil {
		if err = r.Delete(ctx, &webhook); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("cannot delete mutating webhook: %w", err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot retrieve mutating webhook: %w", err)
	}

	return nil
}

func (r *policySubReconciler) namespaceSelector(policy policiesv1.Policy) *metav1.LabelSelector {
	switch policy.(type) {
	case *policiesv1.ClusterAdmissionPolicyGroup, *policiesv1.ClusterAdmissionPolicy:
		namespaceSelector := &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "kubernetes.io/metadata.name",
					Operator: "NotIn",
					Values:   []string{r.deploymentsNamespace},
				},
			},
		}

		if policy.GetNamespaceSelector() != nil {
			namespaceSelector.MatchExpressions = append(namespaceSelector.MatchExpressions, policy.GetNamespaceSelector().MatchExpressions...)
		}

		return namespaceSelector

	default:
		return policy.GetNamespaceSelector()
	}
}
