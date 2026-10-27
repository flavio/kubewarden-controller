package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/kubewarden/adm-controller/internal/constants"
)

const caRootSecretTestNamespace = "kubewarden"

func newTestSecret(namespace, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       data,
	}
}

func newTestCARootSecret(data map[string][]byte) *corev1.Secret {
	return newTestSecret(caRootSecretTestNamespace, constants.CARootSecretName, data)
}

func TestCARootSecretPredicateCreate(t *testing.T) {
	caCert := []byte("ca")
	pred := caRootSecretPredicate(caRootSecretTestNamespace, constants.CARootSecretName)

	tests := []struct {
		name     string
		secret   *corev1.Secret
		expected bool
	}{
		{
			name:     "the creation of the CA root secret passes",
			secret:   newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert}),
			expected: true,
		},
		{
			name:     "the creation of a secret with another name does not pass",
			secret:   newTestSecret(caRootSecretTestNamespace, "other", nil),
			expected: false,
		},
		{
			name:     "the creation of a secret in another namespace does not pass",
			secret:   newTestSecret("other", constants.CARootSecretName, nil),
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, pred.Create(event.CreateEvent{Object: tc.secret}))
		})
	}
}

func TestCARootSecretPredicateUpdate(t *testing.T) {
	caCert := []byte("ca")
	oldCACert := []byte("old-ca")
	pred := caRootSecretPredicate(caRootSecretTestNamespace, constants.CARootSecretName)

	tests := []struct {
		name      string
		oldSecret *corev1.Secret
		newSecret *corev1.Secret
		expected  bool
	}{
		{
			name:      "an update that changes the CA certificate passes",
			oldSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert}),
			newSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: []byte("new-ca")}),
			expected:  true,
		},
		{
			name:      "an update that adds the old CA certificate passes",
			oldSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert}),
			newSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert, constants.OldCARootCert: oldCACert}),
			expected:  true,
		},
		{
			name:      "an update that removes the old CA certificate passes",
			oldSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert, constants.OldCARootCert: oldCACert}),
			newSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert}),
			expected:  true,
		},
		{
			name:      "an update that does not change the CA bundle does not pass",
			oldSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert, constants.CARootPrivateKey: []byte("key")}),
			newSecret: newTestCARootSecret(map[string][]byte{constants.CARootCert: caCert, constants.CARootPrivateKey: []byte("other-key")}),
			expected:  false,
		},
		{
			name:      "an update of another secret does not pass",
			oldSecret: newTestSecret(caRootSecretTestNamespace, "other", map[string][]byte{constants.CARootCert: caCert}),
			newSecret: newTestSecret(caRootSecretTestNamespace, "other", map[string][]byte{constants.CARootCert: []byte("new-ca")}),
			expected:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, pred.Update(event.UpdateEvent{
				ObjectOld: tc.oldSecret,
				ObjectNew: tc.newSecret,
			}))
		})
	}
}

func TestCARootSecretPredicateDelete(t *testing.T) {
	pred := caRootSecretPredicate(caRootSecretTestNamespace, constants.CARootSecretName)

	secret := newTestCARootSecret(map[string][]byte{constants.CARootCert: []byte("ca")})

	require.False(t, pred.Delete(event.DeleteEvent{Object: secret}))
}
