package controller

import (
	"maps"
	"slices"
	"strings"
)

// applyManagedKeys removes keys that were previously managed (recorded in the tracking
// annotation) but are no longer present in the desired user-defined map, then applies the new
// desired keys and records the current managed set in the tracking annotation.
//
// Parameters:
//   - existing: the map to mutate in-place (either the labels or annotations map of the object).
//   - desired: the user-defined map from spec (may be nil).
//   - trackingAnnotations: always the object's annotations map. The tracking key is stored here
//     so that it never pollutes the labels map. When existing is itself the annotations map
//     (i.e. when managing annotations) both parameters point to the same map.
//   - trackingKey: the annotation key used to store the comma-separated list of managed keys.
func applyManagedKeys(existing map[string]string, desired map[string]string, trackingAnnotations map[string]string, trackingKey string) {
	// Remove keys that were managed last time but are no longer desired.
	if prev, found := trackingAnnotations[trackingKey]; found && prev != "" {
		for _, key := range strings.Split(prev, ",") {
			if _, stillDesired := desired[key]; !stillDesired {
				delete(existing, key)
			}
		}
	}

	// Apply desired keys (user-defined values first; system values will overwrite after this call).
	for key, value := range desired {
		existing[key] = value
	}

	// Record the current set of managed keys, or remove the tracking annotation when none remain.
	if len(desired) == 0 {
		delete(trackingAnnotations, trackingKey)
	} else {
		trackingAnnotations[trackingKey] = strings.Join(slices.Collect(maps.Keys(desired)), ",")
	}
}
