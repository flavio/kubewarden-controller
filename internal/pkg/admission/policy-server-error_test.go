package admission

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsPolicyServerNotReady(t *testing.T) {
	err := &PolicyServerNotReadyError{Message: "waiting"}
	if IsPolicyServerNotReady(err) != true {
		t.Errorf("expected error to be identified")
	}

	if IsPolicyServerNotReady(nil) != false {
		t.Errorf("foo")
	}

	errWrapped := fmt.Errorf("this is a wrapped error: %w", err)
	if IsPolicyServerNotReady(errWrapped) != true {
		t.Errorf("expected wrapped error to be identified")
	}

	otherErr := errors.New("this is generic error")
	if IsPolicyServerNotReady(otherErr) != false {
		t.Errorf("expected generic error to not be identified")
	}
}
