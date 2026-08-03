package primitivesauth

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

const testScope coordination.Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fixture struct {
	calls                                               []string
	authErr, actionErr, scopeErr, openErr, operationErr error
	identity                                            Identity
	scope                                               coordination.Digest
}

func (value *fixture) Authenticate(context.Context, RequestAuthentication) (Identity, error) {
	value.calls = append(value.calls, "authenticate")
	return value.identity, value.authErr
}
func (value *fixture) AuthorizeAction(context.Context, Identity, Action) error {
	value.calls = append(value.calls, "action")
	return value.actionErr
}
func (value *fixture) AuthorizeScope(context.Context, Identity, Action, coordination.Digest) error {
	value.calls = append(value.calls, "scope")
	return value.scopeErr
}
func (value *fixture) OpenScope(context.Context, Identity, string) (coordination.Digest, error) {
	value.calls = append(value.calls, "open")
	return value.scope, value.openErr
}
func (value *fixture) Run(context.Context, Identity, Action, coordination.Digest) error {
	value.calls = append(value.calls, "operation")
	return value.operationErr
}

func authentication(t *testing.T) RequestAuthentication {
	t.Helper()
	value, err := NewRequestAuthentication("credential", "a.b.c", "POST", "https://coordination.invalid/coordination-primitives/v1/leases:inspect")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func pipeline(t *testing.T, value *fixture) *Pipeline {
	t.Helper()
	identity, err := NewIdentity("tenant-a", "principal-a")
	if err != nil {
		t.Fatal(err)
	}
	value.identity, value.scope = identity, testScope
	result, err := NewPipeline(value, value, value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSealedOrderIsExact(t *testing.T) {
	value := &fixture{}
	if err := pipeline(t, value).ExecuteSealed(context.Background(), authentication(t), LeaseInspect, "opaque", value, value); err != nil {
		t.Fatal(err)
	}
	expected := []string{"authenticate", "action", "open", "scope", "operation"}
	if !reflect.DeepEqual(value.calls, expected) {
		t.Fatalf("calls: %v", value.calls)
	}
}

func TestPublicOrderSkipsCapabilityOpen(t *testing.T) {
	value := &fixture{}
	if err := pipeline(t, value).ExecutePublic(context.Background(), authentication(t), LeaseAcquire, testScope, value); err != nil {
		t.Fatal(err)
	}
	expected := []string{"authenticate", "action", "scope", "operation"}
	if !reflect.DeepEqual(value.calls, expected) {
		t.Fatalf("calls: %v", value.calls)
	}
}

func TestDenialsAndInvalidCapabilityStopBeforeStore(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*fixture)
		expected  error
		calls     []string
	}{
		{"unauthenticated", func(v *fixture) { v.authErr = errors.New("provider: secret: " + ErrUnauthenticated.Error()) }, ErrTemporarilyUnavailable, []string{"authenticate"}},
		{"action deny", func(v *fixture) { v.actionErr = ErrAccessDenied }, ErrAccessDenied, []string{"authenticate", "action"}},
		{"invalid capability", func(v *fixture) { v.openErr = ErrInvalidCapability }, ErrInvalidCapability, []string{"authenticate", "action", "open"}},
		{"scope deny", func(v *fixture) { v.scopeErr = ErrAccessDenied }, ErrAccessDenied, []string{"authenticate", "action", "open", "scope"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := &fixture{}
			test.configure(value)
			err := pipeline(t, value).ExecuteSealed(context.Background(), authentication(t), LeaseRenew, "opaque", value, value)
			if !errors.Is(err, test.expected) || !reflect.DeepEqual(value.calls, test.calls) {
				t.Fatalf("error/calls: %v %v", err, value.calls)
			}
		})
	}
}

func TestClosedValuesRedactAndRejectJSON(t *testing.T) {
	auth := authentication(t)
	if auth.String() != "RequestAuthentication{REDACTED}" {
		t.Fatal("unsafe authentication formatting")
	}
	if _, err := json.Marshal(auth); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("authentication serialized: %v", err)
	}
	identity, _ := NewIdentity("tenant-a", "principal-a")
	if identity.String() != "Identity{REDACTED}" {
		t.Fatal("unsafe identity formatting")
	}
	if _, err := json.Marshal(identity); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("identity serialized: %v", err)
	}
}
