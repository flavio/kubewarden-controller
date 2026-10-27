package controller

import (
	"bytes"
	"context"
	"fmt"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/kubewarden/adm-controller/internal/certs"
)

// caRootSecretPredicate returns a predicate that passes the events of the CA root secret that can change the CA
// bundle of a webhook configuration: the creation of the secret, and an update that changes its CA bundle.
// A deletion does not pass: without the secret there is no bundle to write, and the creation of the secret
// starts the reconcile again.
func caRootSecretPredicate(namespace, name string) predicate.Funcs {
	isCARootSecret := func(object client.Object) bool {
		return object.GetNamespace() == namespace && object.GetName() == name
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return isCARootSecret(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if !isCARootSecret(e.ObjectNew) {
				return false
			}
			oldSecret, ok := e.ObjectOld.(*corev1.Secret)
			if !ok {
				return false
			}
			newSecret, ok := e.ObjectNew.(*corev1.Secret)
			if !ok {
				return false
			}
			return !bytes.Equal(certs.CABundleFromSecret(oldSecret), certs.CABundleFromSecret(newSecret))
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(event.GenericEvent) bool {
			return false
		},
	}
}

// injectCABundle sets caBundle in every webhook of a validating or a mutating webhook configuration. If a value
// changed, it patches the object and logs the change. It is the only code that writes caBundle into an existing
// webhook configuration.
func injectCABundle(ctx context.Context, c client.Client, log logr.Logger, webhookConfiguration client.Object, caBundle []byte) error {
	original, ok := webhookConfiguration.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("cannot copy webhook configuration %q", webhookConfiguration.GetName())
	}

	kind, clientConfigs, err := webhookClientConfigs(webhookConfiguration)
	if err != nil {
		return err
	}

	changed := false
	for _, clientConfig := range clientConfigs {
		if !bytes.Equal(clientConfig.CABundle, caBundle) {
			clientConfig.CABundle = caBundle
			changed = true
		}
	}
	if !changed {
		return nil
	}

	// The merge patch replaces the whole webhooks list. The optimistic lock makes a concurrent change of the object
	// fail with a conflict, so that the reconcile runs again on the new object instead of overwriting it.
	if err = c.Patch(ctx, webhookConfiguration, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("cannot patch the CA bundle of %s %q: %w", kind, webhookConfiguration.GetName(), err)
	}
	log.Info("Injected the CA bundle", "kind", kind, "name", webhookConfiguration.GetName())

	return nil
}

// webhookClientConfigs returns the kind of a validating or a mutating webhook configuration, and a pointer to the
// client configuration of each of its webhooks.
func webhookClientConfigs(webhookConfiguration client.Object) (string, []*admissionregistrationv1.WebhookClientConfig, error) {
	var clientConfigs []*admissionregistrationv1.WebhookClientConfig
	switch typed := webhookConfiguration.(type) {
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		for i := range typed.Webhooks {
			clientConfigs = append(clientConfigs, &typed.Webhooks[i].ClientConfig)
		}
		return "ValidatingWebhookConfiguration", clientConfigs, nil
	case *admissionregistrationv1.MutatingWebhookConfiguration:
		for i := range typed.Webhooks {
			clientConfigs = append(clientConfigs, &typed.Webhooks[i].ClientConfig)
		}
		return "MutatingWebhookConfiguration", clientConfigs, nil
	default:
		return "", nil, fmt.Errorf("%T is not a webhook configuration", webhookConfiguration)
	}
}
