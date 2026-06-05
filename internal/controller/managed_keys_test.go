package controller

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const trackingKey = "kubewarden.io/managed-keys"

func TestApplyManagedKeys(t *testing.T) {
	tests := []struct {
		name         string
		existing     map[string]string
		desired      map[string]string
		tracking     map[string]string
		wantExisting map[string]string
		wantTracking map[string]string // full expected state of the tracking map after the call
	}{
		{
			name:         "first apply, single key",
			existing:     map[string]string{"system-key": "system-value"},
			desired:      map[string]string{"user-key": "user-value"},
			tracking:     map[string]string{},
			wantExisting: map[string]string{"system-key": "system-value", "user-key": "user-value"},
			wantTracking: map[string]string{trackingKey: "user-key"},
		},
		{
			name:         "first apply, multiple keys",
			existing:     map[string]string{"system-key": "system-value"},
			desired:      map[string]string{"user-key-a": "value-a", "user-key-b": "value-b"},
			tracking:     map[string]string{},
			wantExisting: map[string]string{"system-key": "system-value", "user-key-a": "value-a", "user-key-b": "value-b"},
			wantTracking: map[string]string{trackingKey: "user-key-a,user-key-b"},
		},
		{
			name:         "idempotent re-apply",
			existing:     map[string]string{"user-key": "user-value", "system-key": "system-value"},
			desired:      map[string]string{"user-key": "user-value"},
			tracking:     map[string]string{trackingKey: "user-key"},
			wantExisting: map[string]string{"user-key": "user-value", "system-key": "system-value"},
			wantTracking: map[string]string{trackingKey: "user-key"},
		},
		{
			name:         "stale key removed",
			existing:     map[string]string{"old-key": "old-value", "system-key": "system-value"},
			desired:      map[string]string{"new-key": "new-value"},
			tracking:     map[string]string{trackingKey: "old-key"},
			wantExisting: map[string]string{"new-key": "new-value", "system-key": "system-value"},
			wantTracking: map[string]string{trackingKey: "new-key"},
		},
		{
			name:         "2 managed keys reduced to 1",
			existing:     map[string]string{"key-a": "value-a", "key-b": "value-b", "system-key": "system-value"},
			desired:      map[string]string{"key-b": "value-b"},
			tracking:     map[string]string{trackingKey: "key-a,key-b"},
			wantExisting: map[string]string{"key-b": "value-b", "system-key": "system-value"},
			wantTracking: map[string]string{trackingKey: "key-b"},
		},
		{
			name:         "all keys go stale, nil desired",
			existing:     map[string]string{"managed-key": "managed-value", "system-key": "system-value"},
			desired:      nil,
			tracking:     map[string]string{trackingKey: "managed-key"},
			wantExisting: map[string]string{"system-key": "system-value"},
			wantTracking: map[string]string{},
		},
		{
			name:         "all keys go stale, multiple tracked, nil desired",
			existing:     map[string]string{"managed-key-a": "value-a", "managed-key-b": "value-b", "system-key": "system-value"},
			desired:      nil,
			tracking:     map[string]string{trackingKey: "managed-key-a,managed-key-b"},
			wantExisting: map[string]string{"system-key": "system-value"},
			wantTracking: map[string]string{},
		},
		{
			name:         "unmanaged keys preserved when desired is empty",
			existing:     map[string]string{"system-key": "system-value", "another-key": "another-value"},
			desired:      map[string]string{},
			tracking:     map[string]string{trackingKey: ""},
			wantExisting: map[string]string{"system-key": "system-value", "another-key": "another-value"},
			wantTracking: map[string]string{},
		},
		{
			name:         "desired value updated",
			existing:     map[string]string{"user-key": "old-value"},
			desired:      map[string]string{"user-key": "new-value"},
			tracking:     map[string]string{trackingKey: "user-key"},
			wantExisting: map[string]string{"user-key": "new-value"},
			wantTracking: map[string]string{trackingKey: "user-key"},
		},
		{
			name:     "other annotations in tracking map are preserved",
			existing: map[string]string{"user-key": "user-value", "system-key": "system-value"},
			desired:  map[string]string{"user-key": "user-value"},
			tracking: map[string]string{
				trackingKey:             "user-key",
				"some-other-annotation": "some-value",
				"another-annotation":    "another-value",
			},
			wantExisting: map[string]string{"user-key": "user-value", "system-key": "system-value"},
			wantTracking: map[string]string{
				trackingKey:             "user-key",
				"some-other-annotation": "some-value",
				"another-annotation":    "another-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyManagedKeys(tt.existing, tt.desired, tt.tracking, trackingKey)

			assert.Equal(t, tt.wantExisting, tt.existing, "existing map mismatch")

			// Verify the tracking map matches expectations exactly.
			// The trackingKey value is compared order-agnostically since maps.Keys is non-deterministic.
			// All other entries are compared with exact equality via assert.Equal at the end.
			if _, ok := tt.wantTracking[trackingKey]; ok {
				assert.ElementsMatch(t,
					strings.Split(tt.wantTracking[trackingKey], ","),
					strings.Split(tt.tracking[trackingKey], ","),
					"managed keys in tracking annotation mismatch",
				)
			}
			for key, wantVal := range tt.wantTracking {
				if key != trackingKey {
					assert.Equal(t, wantVal, tt.tracking[key], "tracking[%q] mismatch", key)
				}
			}
			for key := range tt.tracking {
				if _, expected := tt.wantTracking[key]; !expected {
					t.Errorf("tracking contains unexpected key %q", key)
				}
			}
		})
	}
}

// TestApplyManagedKeys_LabelTrackingStoredInAnnotations covers the only valid pattern for
// managing labels: desired keys are written into the labels map, but the tracking key is
// always stored in the annotations map. Labels must never carry tracking keys.
func TestApplyManagedKeys_LabelTrackingStoredInAnnotations(t *testing.T) {
	labels := map[string]string{
		"old-label":    "old-value",
		"system-label": "system-value",
	}
	annotations := map[string]string{trackingKey: "old-label"}
	desired := map[string]string{"new-label": "new-value"}

	applyManagedKeys(labels, desired, annotations, trackingKey)

	assert.NotContains(t, labels, "old-label", "stale old-label should be removed from labels")
	assert.Equal(t, "new-value", labels["new-label"], "new-label should be applied to labels")
	assert.Equal(t, "system-value", labels["system-label"], "unmanaged system-label should be preserved")
	assert.Equal(t, "new-label", annotations[trackingKey], "tracking annotation should record new-label")
	assert.NotContains(t, annotations, "new-label", "label key must not leak into the annotations map")
}
