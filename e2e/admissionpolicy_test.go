/*
Copyright 2022.

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

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

func TestAdmissionPolicyController(t *testing.T) {
	policyNamespace := "admission-policy-controller-test"

	validatingFeature := features.New("Validating AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Create namespace
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			// Add scheme
			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create PolicyServer and wait for it to be ready
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, policyServerNameKey, policyServerName)

			// Create validating AdmissionPolicy
			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, policyNameKey, policyName)
			ctx = context.WithValue(ctx, policyKey, policy)

			return ctx
		}).
		Assess("should set the AdmissionPolicy to active sometime after its creation", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)

			// Wait for policy status to be pending
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).
		Assess("should create the ValidatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)
			policyName := ctx.Value(policyNameKey).(string)
			policyServerName := ctx.Value(policyServerNameKey).(string)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: webhookName},
			}

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)

				// Verify labels
				if w.Labels[constants.PartOfLabelKey] != constants.PartOfLabelValue {
					return false
				}

				// Verify annotations
				if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != policyName {
					return false
				}
				if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != policyNamespace {
					return false
				}

				// Verify webhooks
				if len(w.Webhooks) != 1 {
					return false
				}
				if w.Webhooks[0].ClientConfig.Service.Name != "policy-server-"+policyServerName {
					return false
				}
				if *w.Webhooks[0].ClientConfig.Service.Port != int32(constants.PolicyServerServicePort) {
					return false
				}
				if len(w.Webhooks[0].MatchConditions) != 1 {
					return false
				}

				return true
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be created with correct configuration")

			// Verify CA bundle
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			caSecret, err := getTestCASecret(ctx, cfg)
			require.NoError(t, err)
			require.Equal(t, caSecret.Data[constants.CARootCert], webhook.Webhooks[0].ClientConfig.CABundle)

			return ctx
		}).
		Assess("should reconcile the ValidatingWebhookConfiguration to the original state after some change", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			err := cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			// Store original values
			originalLabels := make(map[string]string)
			for k, v := range webhook.Labels {
				originalLabels[k] = v
			}
			originalAnnotations := make(map[string]string)
			for k, v := range webhook.Annotations {
				originalAnnotations[k] = v
			}
			originalServiceName := webhook.Webhooks[0].ClientConfig.Service.Name
			originalCABundle := webhook.Webhooks[0].ClientConfig.CABundle

			// Modify the webhook
			delete(webhook.Labels, constants.PartOfLabelKey)
			delete(webhook.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			webhook.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = "wrong-namespace"
			webhook.Webhooks[0].ClientConfig.Service.Name = "wrong-service"
			webhook.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)

					if w.Labels[constants.PartOfLabelKey] != originalLabels[constants.PartOfLabelKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] {
						return false
					}
					if w.Webhooks[0].ClientConfig.Service.Name != originalServiceName {
						return false
					}
					if string(w.Webhooks[0].ClientConfig.CABundle) != string(originalCABundle) {
						return false
					}
					return true
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be reconciled to original state")

			// Test reconciliation when labels and annotations are nil (simulate Kubewarden <= 1.9.0 behavior)
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			webhook.Labels = nil
			webhook.Annotations = nil
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)
					return w.Labels != nil && w.Annotations != nil &&
						w.Labels[constants.PartOfLabelKey] == originalLabels[constants.PartOfLabelKey] &&
						w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] == originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey]
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be reconciled when labels/annotations are nil")

			return ctx
		}).
		Assess("should delete the ValidatingWebhookConfiguration when the AdmissionPolicy is deleted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)
			webhookName := policy.GetUniqueName()

			// Delete the policy
			err := cfg.Client().Resources().Delete(ctx, policy)
			require.NoError(t, err)

			// Wait for webhook to be deleted
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(
				&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be deleted")

			return ctx
		}).
		Feature()

	mutatingFeature := features.New("Mutating AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Create namespace
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			// Add scheme
			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create PolicyServer and wait for it to be ready
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, policyServerNameKey, policyServerName)

			// Create mutating AdmissionPolicy
			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				WithMutating(true).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, policyNameKey, policyName)
			ctx = context.WithValue(ctx, policyKey, policy)

			return ctx
		}).
		Assess("should set the AdmissionPolicy to active", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)

			// Wait for policy status to be pending
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).
		Assess("should create the MutatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)
			policyName := ctx.Value(policyNameKey).(string)
			policyServerName := ctx.Value(policyServerNameKey).(string)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: webhookName},
			}

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.MutatingWebhookConfiguration)

				// Verify labels
				if w.Labels[constants.PartOfLabelKey] != constants.PartOfLabelValue {
					return false
				}

				// Verify annotations
				if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != policyName {
					return false
				}
				if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != policyNamespace {
					return false
				}

				// Verify webhooks
				if len(w.Webhooks) != 1 {
					return false
				}
				if w.Webhooks[0].ClientConfig.Service.Name != "policy-server-"+policyServerName {
					return false
				}
				if *w.Webhooks[0].ClientConfig.Service.Port != int32(constants.PolicyServerServicePort) {
					return false
				}
				if len(w.Webhooks[0].MatchConditions) != 1 {
					return false
				}

				return true
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be created with correct configuration")

			// Verify CA bundle
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			caSecret, err := getTestCASecret(ctx, cfg)
			require.NoError(t, err)
			require.Equal(t, caSecret.Data[constants.CARootCert], webhook.Webhooks[0].ClientConfig.CABundle)

			return ctx
		}).
		Assess("should reconcile the MutatingWebhookConfiguration to the original state after some change", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{}
			err := cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			// Store original values
			originalLabels := make(map[string]string)
			for k, v := range webhook.Labels {
				originalLabels[k] = v
			}
			originalAnnotations := make(map[string]string)
			for k, v := range webhook.Annotations {
				originalAnnotations[k] = v
			}
			originalServiceName := webhook.Webhooks[0].ClientConfig.Service.Name
			originalCABundle := webhook.Webhooks[0].ClientConfig.CABundle

			// Modify the webhook
			delete(webhook.Labels, constants.PartOfLabelKey)
			delete(webhook.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			webhook.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = "wrong-namespace"
			webhook.Webhooks[0].ClientConfig.Service.Name = "wrong-service"
			webhook.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.MutatingWebhookConfiguration)

					if w.Labels[constants.PartOfLabelKey] != originalLabels[constants.PartOfLabelKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] {
						return false
					}
					if w.Webhooks[0].ClientConfig.Service.Name != originalServiceName {
						return false
					}
					if string(w.Webhooks[0].ClientConfig.CABundle) != string(originalCABundle) {
						return false
					}
					return true
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be reconciled to original state")

			// Test reconciliation when labels and annotations are nil (simulate Kubewarden <= 1.9.0 behavior)
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			webhook.Labels = nil
			webhook.Annotations = nil
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.MutatingWebhookConfiguration)
					return w.Labels != nil && w.Annotations != nil &&
						w.Labels[constants.PartOfLabelKey] == originalLabels[constants.PartOfLabelKey] &&
						w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] == originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey]
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be reconciled when labels/annotations are nil")

			return ctx
		}).
		Assess("should delete the MutatingWebhookConfiguration when the AdmissionPolicy is deleted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)
			webhookName := policy.GetUniqueName()

			// Delete the policy
			err := cfg.Client().Resources().Delete(ctx, policy)
			require.NoError(t, err)

			// Wait for webhook to be deleted
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(
				&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be deleted")

			return ctx
		}).Feature()

	scheduledFeature := features.New("Scheduled AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Create namespace
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			// Add scheme
			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create AdmissionPolicy with non-existent PolicyServer
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				Build()

			err = cfg.Client().Resources().Create(ctx, policy)
			if err != nil && !apierrors.IsAlreadyExists(err) {
				require.NoError(t, err)
			}

			ctx = context.WithValue(ctx, policyNameKey, policyName)
			ctx = context.WithValue(ctx, policyServerNameKey, policyServerName)

			return ctx
		}).
		Assess("should set the policy status to scheduled", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusScheduled
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should have scheduled status")

			return ctx
		}).
		Assess("should set the policy status to active when the PolicyServer is created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyServerName := ctx.Value(policyServerNameKey).(string)
			policyName := ctx.Value(policyNameKey).(string)

			// Create PolicyServer
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err := cfg.Client().Resources().Create(ctx, policyServer)
			if err != nil && !apierrors.IsAlreadyExists(err) {
				require.NoError(t, err)
			}

			// Wait for policy status to be pending
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).Feature()

	// The Helm chart installs a default allow list of resources that
	// namespaced policies can target. NetworkPolicies are not in this list.
	rejectedNamespacedPolicyFeature := features.New("Rejected AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				// This test checks that the deleted policy disappears right
				// away. Without this call, the safety-net finalizer keeps
				// the object present.
				WithoutFinalizers().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"networking.k8s.io"},
							APIVersions: []string{"v1"},
							Resources:   []string{"networkpolicies"},
						},
					},
				}).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, policyNameKey, policyName)
			ctx = context.WithValue(ctx, policyKey, policy)

			return ctx
		}).
		Assess("should set the policy status to rejected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return isPolicyRejectedFor(&p.Status, "networkpolicies.networking.k8s.io")
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should have rejected status with a PolicyActive condition that lists the resources")

			return ctx
		}).
		Assess("should not create the ValidatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			err := cfg.Client().Resources().Get(ctx, policy.GetUniqueName(), "", webhook)
			require.True(t, apierrors.IsNotFound(err), "ValidatingWebhookConfiguration must not exist for a rejected policy")

			return ctx
		}).
		Assess("should delete the policy without waiting for a finalizer", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			var latestPolicy policiesv1.AdmissionPolicy
			err := cfg.Client().Resources().Get(ctx, policy.GetName(), policy.GetNamespace(), &latestPolicy)
			require.NoError(t, err)
			require.False(t, containsFinalizer(latestPolicy.GetFinalizers(), constants.KubewardenFinalizer),
				"the controller must not add its finalizer to a rejected policy")

			err = cfg.Client().Resources().Delete(ctx, &latestPolicy)
			require.NoError(t, err)

			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(policy),
				wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Rejected policy should be deleted")

			return ctx
		}).Feature()

	// The allow list check does not look at spec.mutating. A mutating
	// AdmissionPolicy that targets a resource outside the allow list is
	// rejected the same way as a validating policy.
	rejectedMutatingNamespacedPolicyFeature := features.New("Rejected mutating AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				WithMutating(true).
				// This test checks that the deleted policy disappears right
				// away. Without this call, the safety-net finalizer keeps
				// the object present.
				WithoutFinalizers().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"networking.k8s.io"},
							APIVersions: []string{"v1"},
							Resources:   []string{"networkpolicies"},
						},
					},
				}).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, policyNameKey, policyName)
			ctx = context.WithValue(ctx, policyKey, policy)

			return ctx
		}).
		Assess("should set the policy status to rejected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return isPolicyRejectedFor(&p.Status, "networkpolicies.networking.k8s.io")
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Mutating policy should have rejected status with a PolicyActive condition that lists the resources")

			return ctx
		}).
		Assess("should not create the MutatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{}
			err := cfg.Client().Resources().Get(ctx, policy.GetUniqueName(), "", webhook)
			require.True(t, apierrors.IsNotFound(err), "MutatingWebhookConfiguration must not exist for a rejected policy")

			return ctx
		}).
		Assess("should delete the policy without waiting for a finalizer", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			var latestPolicy policiesv1.AdmissionPolicy
			err := cfg.Client().Resources().Get(ctx, policy.GetName(), policy.GetNamespace(), &latestPolicy)
			require.NoError(t, err)
			require.False(t, containsFinalizer(latestPolicy.GetFinalizers(), constants.KubewardenFinalizer),
				"the controller must not add its finalizer to a rejected mutating policy")

			err = cfg.Client().Resources().Delete(ctx, &latestPolicy)
			require.NoError(t, err)

			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(policy),
				wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Rejected mutating policy should be deleted")

			return ctx
		}).Feature()

	// The chart default allow list contains pods. The policy starts active
	// with a webhook in place. The test removes pods from the allow list.
	// The controller must then reject the policy, delete its webhook, and
	// remove the policy from the PolicyServer configuration. The test then
	// restores the allow list. The controller must deploy the policy again.
	allowListChangeFeature := features.New("AdmissionPolicy rejected after its resource leaves the allow list").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			originalControllerConfig, err := getControllerConfig(ctx, cfg)
			require.NoError(t, err)
			ctx = context.WithValue(ctx, controllerConfigKey, originalControllerConfig)

			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			// The default rule targets pods. The chart default allow list
			// already permits pods. This test skips the safety-net finalizer,
			// so the Teardown step does not leave a Terminating object behind.
			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				WithoutFinalizers().
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, policyNameKey, policyName)
			ctx = context.WithValue(ctx, policyKey, policy)
			ctx = context.WithValue(ctx, policyServerNameKey, policyServerName)

			return ctx
		}).
		Assess("should set the policy to active and create its webhook", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)
			policyServerName := ctx.Value(policyServerNameKey).(string)
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			err := waitForAdmissionPolicyActive(cfg, policyName, policyNamespace)
			require.NoError(t, err, "Policy should transition to active status")

			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: policy.GetUniqueName()},
			}
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)
				return len(w.Webhooks) == 1
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be created")

			err = waitForPolicyServerConfigMapPolicy(cfg, policyServerName, policy.GetUniqueName(), true)
			require.NoError(t, err, "policy should be part of the PolicyServer configuration")

			return ctx
		}).
		Assess("should reject the policy and remove its webhook once pods leave the allow list", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)
			policyServerName := ctx.Value(policyServerNameKey).(string)
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)

			err := setControllerConfig(ctx, cfg, `namespacedPoliciesAllowedResources:
  - apiGroups: ["apps"]
    resources: ["deployments"]
`)
			require.NoError(t, err)

			err = waitForAdmissionPolicyRejected(cfg, policyName, policyNamespace, "pods")
			require.NoError(t, err, "Policy should transition to rejected status")

			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: policy.GetUniqueName()},
			}
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(webhook),
				wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be deleted")

			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return !containsFinalizer(p.Finalizers, constants.KubewardenFinalizer)
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "the finalizer should be removed from the rejected policy")

			err = waitForPolicyServerConfigMapPolicy(cfg, policyServerName, policy.GetUniqueName(), false)
			require.NoError(t, err, "policy should be removed from the PolicyServer configuration")

			return ctx
		}).
		Assess("should deploy the policy again once pods are back in the allow list", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value(policyNameKey).(string)
			policyServerName := ctx.Value(policyServerNameKey).(string)
			policy := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy)
			originalControllerConfig := ctx.Value(controllerConfigKey).(string)

			err := setControllerConfig(ctx, cfg, originalControllerConfig)
			require.NoError(t, err)

			err = waitForAdmissionPolicyActive(cfg, policyName, policyNamespace)
			require.NoError(t, err, "Policy should transition to active status again")

			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: policy.GetUniqueName()},
			}
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)
				return len(w.Webhooks) == 1
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be created again")

			err = waitForPolicyServerConfigMapPolicy(cfg, policyServerName, policy.GetUniqueName(), true)
			require.NoError(t, err, "policy should be part of the PolicyServer configuration again")

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			if originalControllerConfig, ok := ctx.Value(controllerConfigKey).(string); ok {
				_ = setControllerConfig(ctx, cfg, originalControllerConfig)
			}

			if policy, ok := ctx.Value(policyKey).(*policiesv1.AdmissionPolicy); ok {
				_ = cfg.Client().Resources().Delete(ctx, policy)
			}

			return ctx
		}).Feature()

	testenv.Test(t, validatingFeature, mutatingFeature, scheduledFeature, rejectedNamespacedPolicyFeature, rejectedMutatingNamespacedPolicyFeature, allowListChangeFeature)
}
