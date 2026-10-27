package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// The RBAC rules for the webhook configurations are in policy_subreconciler_webhook.go. The RBAC rules for the
// secrets are in policyserver_controller.go.

// WebhookCABundleReconciler syncs the caBundle of webhook configurations that
// have the annotation kubewarden.io/inject-ca-from to match the CA bundle of
// the CARootSecret.
// The Helm chart sets the annotation kubewarden.io/inject-ca-from on the
// webhook configurations of the controller. The chart renders caBundle at
// install time, and nothing else repairs it: for example, a GitOps tool
// that renders the chart without cluster access creates the object with a
// random CA.
type WebhookCABundleReconciler struct {
	client.Client
	Log                  logr.Logger
	DeploymentsNamespace string
	CARootSecretName     string
}

// SetupWithManager sets up the controller with the Manager.
func (r *WebhookCABundleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// A request carries only a name, and a validating and a mutating webhook configuration can have the same name.
	// Each event maps to one fixed request, and each reconcile handles every webhook configuration.
	enqueueCARootSecret := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: r.caRootSecretKey()}}
	})
	hasInjectCAFromAnnotation := predicate.NewPredicateFuncs(func(object client.Object) bool {
		_, found := object.GetAnnotations()[constants.InjectCAFromAnnotationKey]
		return found
	})

	err := ctrl.NewControllerManagedBy(mgr).
		Named("webhook-cabundle").
		Watches(
			&admissionregistrationv1.ValidatingWebhookConfiguration{},
			enqueueCARootSecret,
			builder.WithPredicates(hasInjectCAFromAnnotation),
		).
		Watches(
			&admissionregistrationv1.MutatingWebhookConfiguration{},
			enqueueCARootSecret,
			builder.WithPredicates(hasInjectCAFromAnnotation),
		).
		Watches(
			&corev1.Secret{},
			enqueueCARootSecret,
			builder.WithPredicates(caRootSecretPredicate(r.DeploymentsNamespace, r.CARootSecretName)),
		).
		Complete(r)
	if err != nil {
		return errors.Join(errors.New("failed enrolling controller with manager"), err)
	}

	return nil
}

// Reconcile writes the CA bundle of the CA root secret into each webhook configuration that asks for it with the
// annotation kubewarden.io/inject-ca-from. It patches only the webhook configurations with a different caBundle.
func (r *WebhookCABundleReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	caRootSecretKey := r.caRootSecretKey()
	caRootSecret := &corev1.Secret{}
	if err := r.Get(ctx, caRootSecretKey, caRootSecret); err != nil {
		if apierrors.IsNotFound(err) {
			// The secret watch starts the reconcile again when the secret is created.
			r.Log.Info("CA root secret not found, waiting for it", "secret", caRootSecretKey.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get CA root secret: %w", err)
	}
	if len(caRootSecret.Data[constants.CARootCert]) == 0 {
		return ctrl.Result{}, fmt.Errorf("CA root secret %s has no %s", caRootSecretKey.String(), constants.CARootCert)
	}
	caBundle := certs.CABundleFromSecret(caRootSecret)

	validatingWebhookConfigurations := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := r.List(ctx, validatingWebhookConfigurations); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list validating webhook configurations: %w", err)
	}
	mutatingWebhookConfigurations := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := r.List(ctx, mutatingWebhookConfigurations); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list mutating webhook configurations: %w", err)
	}

	webhookConfigurations := make([]client.Object, 0, len(validatingWebhookConfigurations.Items)+len(mutatingWebhookConfigurations.Items))
	for i := range validatingWebhookConfigurations.Items {
		webhookConfigurations = append(webhookConfigurations, &validatingWebhookConfigurations.Items[i])
	}
	for i := range mutatingWebhookConfigurations.Items {
		webhookConfigurations = append(webhookConfigurations, &mutatingWebhookConfigurations.Items[i])
	}

	for _, webhookConfiguration := range webhookConfigurations {
		if !r.injectsCABundle(webhookConfiguration) {
			continue
		}
		if err := injectCABundle(ctx, r.Client, r.Log, webhookConfiguration, caBundle); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// injectsCABundle returns true if the annotation kubewarden.io/inject-ca-from of the object names the CA root secret.
// The controller is not a general CA injector: its cache and its RBAC rules for secrets cover only the deployments
// namespace. Thus it skips an annotation that names another secret.
// Each reconcile checks every annotated webhook configuration, so the skip is logged at a debug level: one foreign
// annotation would otherwise write a log line for each event of any annotated object.
func (r *WebhookCABundleReconciler) injectsCABundle(object client.Object) bool {
	value, found := object.GetAnnotations()[constants.InjectCAFromAnnotationKey]
	if !found {
		return false
	}
	if value != r.caRootSecretKey().String() {
		r.Log.V(1).Info("Skipping the webhook configuration, the annotation names another secret",
			"name", object.GetName(),
			"annotation", constants.InjectCAFromAnnotationKey,
			"value", value,
			"accepted", r.caRootSecretKey().String())
		return false
	}
	return true
}

func (r *WebhookCABundleReconciler) caRootSecretKey() types.NamespacedName {
	return types.NamespacedName{Namespace: r.DeploymentsNamespace, Name: r.CARootSecretName}
}
