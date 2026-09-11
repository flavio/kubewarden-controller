package controller

import (
	"context"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// The allow list used by the test suite permits only pods and configmaps
// (core group) plus deployments and statefulsets (apps group). See
// testAllowedResources.
// The specs change the shared allow list ConfigMap, so they must not run
// in parallel with other specs.
var _ = Describe("Allow list of resources for namespaced policies", Serial, func() {
	ctx := context.Background()
	var policyServerName string

	// disallowedRules targets a resource that the test allow list does not
	// contain.
	disallowedRules := []admissionregistrationv1.RuleWithOperations{
		newRule([]string{"networking.k8s.io"}, []string{"networkpolicies"}),
	}

	BeforeEach(func() {
		policyServerName = newName("policy-server")
		createPolicyServerAndWaitForItsService(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build())
	})

	AfterEach(func() {
		// Restore the allow list used by the test suite, some tests change it
		setTestControllerConfig(ctx, controllerConfig{NamespacedPoliciesAllowedResources: testAllowedResources()})
	})

	It("should reject an AdmissionPolicy that targets a resource outside of the allow list", func() {
		policy := policiesv1.NewAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			WithRules(disallowedRules).
			Build()
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
			"Status": MatchFields(IgnoreExtras, Fields{
				"PolicyStatus": Equal(policiesv1.PolicyStatusRejected),
				"Conditions": ContainElement(MatchFields(IgnoreExtras, Fields{
					"Type":    Equal(string(policiesv1.PolicyActive)),
					"Status":  Equal(metav1.ConditionFalse),
					"Reason":  Equal(string(policiesv1.PolicyReasonResourcesNotAllowed)),
					"Message": ContainSubstring("networkpolicies.networking.k8s.io"),
				})),
			}),
		})))

		By("not adding the policy to the PolicyServer configuration")
		Consistently(func() ([]string, error) {
			return getTestPolicyServerConfigMapPolicyNames(ctx, policyServerName)
		}, consistencyTimeout, pollInterval).ShouldNot(ContainElement(policy.GetUniqueName()))
	})

	It("should reject an AdmissionPolicy that targets one allowed and one not allowed resource", func() {
		// pods (core group) is in the test allow list, daemonsets (apps
		// group) is not. The policy is rejected as a whole and the message
		// names only the not allowed resource.
		policy := policiesv1.NewAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			WithRules([]admissionregistrationv1.RuleWithOperations{
				newRule([]string{""}, []string{"pods"}),
				newRule([]string{"apps"}, []string{"daemonsets"}),
			}).
			Build()
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
			"Status": MatchFields(IgnoreExtras, Fields{
				"PolicyStatus": Equal(policiesv1.PolicyStatusRejected),
				"Conditions": ContainElement(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(string(policiesv1.PolicyActive)),
					"Status": Equal(metav1.ConditionFalse),
					"Reason": Equal(string(policiesv1.PolicyReasonResourcesNotAllowed)),
					"Message": And(
						ContainSubstring("daemonsets.apps"),
						Not(ContainSubstring("pods.apps")),
					),
				})),
			}),
		})))

		By("not adding the policy to the PolicyServer configuration")
		Consistently(func() ([]string, error) {
			return getTestPolicyServerConfigMapPolicyNames(ctx, policyServerName)
		}, consistencyTimeout, pollInterval).ShouldNot(ContainElement(policy.GetUniqueName()))
	})

	It("should reject an AdmissionPolicyGroup that targets a resource outside of the allow list", func() {
		policy := policiesv1.NewAdmissionPolicyGroupFactory().
			WithPolicyServer(policyServerName).
			WithRules(disallowedRules).
			Build()
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() (*policiesv1.AdmissionPolicyGroup, error) {
			return getTestAdmissionPolicyGroup(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
			"Status": MatchFields(IgnoreExtras, Fields{
				"PolicyStatus": Equal(policiesv1.PolicyStatusRejected),
				"Conditions": ContainElement(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(string(policiesv1.PolicyActive)),
					"Status": Equal(metav1.ConditionFalse),
					"Reason": Equal(string(policiesv1.PolicyReasonResourcesNotAllowed)),
				})),
			}),
		})))

		Consistently(func() ([]string, error) {
			return getTestPolicyServerConfigMapPolicyNames(ctx, policyServerName)
		}, consistencyTimeout, pollInterval).ShouldNot(ContainElement(policy.GetUniqueName()))
	})

	It("should not reject a ClusterAdmissionPolicy that targets a resource outside of the allow list", func() {
		policy := policiesv1.NewClusterAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			WithRules(disallowedRules).
			Build()
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() ([]string, error) {
			return getTestPolicyServerConfigMapPolicyNames(ctx, policyServerName)
		}, timeout, pollInterval).Should(ContainElement(policy.GetUniqueName()))

		Consistently(func() (*policiesv1.ClusterAdmissionPolicy, error) {
			return getTestClusterAdmissionPolicy(ctx, policy.Name)
		}, consistencyTimeout, pollInterval).ShouldNot(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusRejected)),
		)
	})

	It("should add an AdmissionPolicy that targets allowed resources to the PolicyServer configuration", func() {
		policy := policiesv1.NewAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			WithRules([]admissionregistrationv1.RuleWithOperations{
				newRule([]string{""}, []string{"pods", "pods/exec"}),
				newRule([]string{"apps"}, []string{"deployments"}),
			}).
			Build()
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() ([]string, error) {
			return getTestPolicyServerConfigMapPolicyNames(ctx, policyServerName)
		}, timeout, pollInterval).Should(ContainElement(policy.GetUniqueName()))

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
		)
	})

	It("should remove the webhook configuration of a policy that becomes rejected", func() {
		policy := policiesv1.NewAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			WithRules(disallowedRules).
			Build()

		// In envtest there are no running pods, so the controller never
		// creates the webhook configuration. Create it by hand to simulate a
		// policy that was active before the allow list changed.
		webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: policy.GetUniqueName(),
				Labels: map[string]string{
					constants.PartOfLabelKey: constants.PartOfLabelValue,
				},
			},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{
				{
					Name:                    policy.GetUniqueName() + constants.WebhookNameSuffix,
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admissionregistrationv1.SideEffectClass {
						s := admissionregistrationv1.SideEffectClassNone
						return &s
					}(),
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service: &admissionregistrationv1.ServiceReference{
							Namespace: deploymentsNamespace,
							Name:      policyServerName,
						},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, webhook)).To(Succeed())
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: policy.GetUniqueName()}, &admissionregistrationv1.ValidatingWebhookConfiguration{})
		}, timeout, pollInterval).Should(WithTransform(apierrors.IsNotFound, BeTrue()))

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusRejected)),
		)
	})

	It("should remove the mutating webhook configuration of a mutating policy that becomes rejected", func() {
		policy := policiesv1.NewAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			WithMutating(true).
			WithRules(disallowedRules).
			Build()

		// In envtest there are no running pods, so the controller never
		// creates the webhook configuration. Create it by hand to simulate a
		// mutating policy that was active before the allow list changed.
		webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: policy.GetUniqueName(),
				Labels: map[string]string{
					constants.PartOfLabelKey: constants.PartOfLabelValue,
				},
			},
			Webhooks: []admissionregistrationv1.MutatingWebhook{
				{
					Name:                    policy.GetUniqueName() + constants.WebhookNameSuffix,
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admissionregistrationv1.SideEffectClass {
						s := admissionregistrationv1.SideEffectClassNone
						return &s
					}(),
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service: &admissionregistrationv1.ServiceReference{
							Namespace: deploymentsNamespace,
							Name:      policyServerName,
						},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, webhook)).To(Succeed())
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: policy.GetUniqueName()}, &admissionregistrationv1.MutatingWebhookConfiguration{})
		}, timeout, pollInterval).Should(WithTransform(apierrors.IsNotFound, BeTrue()))

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusRejected)),
		)

		By("not adding the policy to the PolicyServer configuration")
		Consistently(func() ([]string, error) {
			return getTestPolicyServerConfigMapPolicyNames(ctx, policyServerName)
		}, consistencyTimeout, pollInterval).ShouldNot(ContainElement(policy.GetUniqueName()))
	})

	It("should deploy a rejected policy after the allow list changes", func() {
		policy := policiesv1.NewAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			WithRules(disallowedRules).
			Build()
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusRejected)),
		)

		By("adding the resource to the allow list")
		setTestControllerConfig(ctx, controllerConfig{
			NamespacedPoliciesAllowedResources: append(testAllowedResources(),
				admissionregistrationv1.Rule{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}}),
		})

		Eventually(func() ([]string, error) {
			return getTestPolicyServerConfigMapPolicyNames(ctx, policyServerName)
		}, timeout, pollInterval).Should(ContainElement(policy.GetUniqueName()))

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
			"Status": MatchFields(IgnoreExtras, Fields{
				"PolicyStatus": Equal(policiesv1.PolicyStatusPending),
				"Conditions": ContainElement(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(string(policiesv1.PolicyActive)),
					"Reason": Not(Equal(string(policiesv1.PolicyReasonResourcesNotAllowed))),
				})),
			}),
		})))
	})

	It("should reject every namespaced policy when the allow list is empty", func() {
		setTestControllerConfig(ctx, controllerConfig{})

		policy := policiesv1.NewAdmissionPolicyFactory().
			WithPolicyServer(policyServerName).
			Build()
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(ctx, policy.Namespace, policy.Name)
		}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
			"Status": MatchFields(IgnoreExtras, Fields{
				"PolicyStatus": Equal(policiesv1.PolicyStatusRejected),
				"Conditions": ContainElement(MatchFields(IgnoreExtras, Fields{
					"Type":    Equal(string(policiesv1.PolicyActive)),
					"Reason":  Equal(string(policiesv1.PolicyReasonResourcesNotAllowed)),
					"Message": ContainSubstring("empty"),
				})),
			}),
		})))
	})
})

func getTestAdmissionPolicy(ctx context.Context, namespace, name string) (*policiesv1.AdmissionPolicy, error) {
	policy := policiesv1.AdmissionPolicy{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func getTestAdmissionPolicyGroup(ctx context.Context, namespace, name string) (*policiesv1.AdmissionPolicyGroup, error) {
	policy := policiesv1.AdmissionPolicyGroup{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// getTestPolicyServerConfigMapPolicyNames returns the unique names of the
// policies listed in the PolicyServer ConfigMap.
func getTestPolicyServerConfigMapPolicyNames(ctx context.Context, policyServerName string) ([]string, error) {
	configMap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
	if err != nil {
		return nil, err
	}
	policies := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(configMap.Data[constants.PolicyServerConfigPoliciesEntry]), &policies); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	return names, nil
}

// setTestControllerConfig replaces the controller configuration stored in
// the controller configuration ConfigMap.
func setTestControllerConfig(ctx context.Context, config controllerConfig) {
	data, err := sigsyaml.Marshal(config)
	Expect(err).NotTo(HaveOccurred())

	Eventually(func() error {
		configMap := corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.DefaultControllerConfigMapName}, &configMap); err != nil {
			return err
		}
		configMap.Data = map[string]string{
			constants.ControllerConfigKey: string(data),
		}
		return k8sClient.Update(ctx, &configMap)
	}, timeout, pollInterval).Should(Succeed())
}
