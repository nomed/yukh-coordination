package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/primitivesstaging"
)

type applicationFixture struct{ err error }

func (fixture applicationFixture) Run(context.Context) error { return fixture.err }

func TestBuildRevisionIsClosed(t *testing.T) {
	if validBuildRevision("yukh-coordination-revision:unrecorded") || validBuildRevision("yukh-coordination-revision:"+strings.Repeat("A", 40)) || !validBuildRevision("yukh-coordination-revision:"+strings.Repeat("a", 40)) {
		t.Fatal("build revision validation drifted")
	}
}

func TestExecuteUsesOnlyOneConfigArgumentAndFixedDescriptors(t *testing.T) {
	called := false
	capture := func(nats, key int) (*primitivesstaging.SecretDescriptors, error) {
		if nats != natsCredentialDescriptor || key != capabilityKeyDescriptor {
			t.Fatal("descriptor slots changed")
		}
		return primitivesstaging.NewSecretDescriptors(10000, 10001)
	}
	opener := func(_ context.Context, path string, descriptors *primitivesstaging.SecretDescriptors, now func() time.Time) (application, error) {
		called = true
		if path != "/private/config.json" || descriptors == nil || now == nil || strings.Contains(descriptors.String(), "3") || strings.Contains(descriptors.String(), "4") {
			t.Fatal("unsafe executable input contract")
		}
		return applicationFixture{}, nil
	}
	if err := execute(context.Background(), []string{"binary", "/private/config.json"}, capture, opener); err != nil || !called {
		t.Fatalf("execute = %v, called=%v", err, called)
	}
	for _, args := range [][]string{{"binary"}, {"binary", "relative.json"}, {"binary", "one", "two"}} {
		called = false
		if err := execute(context.Background(), args, capture, opener); !errors.Is(err, primitivesstaging.ErrInvalid) || called {
			t.Fatalf("args=%v err=%v called=%v", args, err, called)
		}
	}
}

func TestExecuteMapsConstructionAndRuntimeDetails(t *testing.T) {
	privateError := errors.New("private endpoint and credential detail")
	capture := func(int, int) (*primitivesstaging.SecretDescriptors, error) {
		return primitivesstaging.NewSecretDescriptors(10000, 10001)
	}
	construct := func(context.Context, string, *primitivesstaging.SecretDescriptors, func() time.Time) (application, error) {
		return nil, privateError
	}
	if err := execute(context.Background(), []string{"binary", "/private/config.json"}, capture, construct); !errors.Is(err, primitivesstaging.ErrUnavailable) || strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("construction error = %v", err)
	}
	runtime := func(context.Context, string, *primitivesstaging.SecretDescriptors, func() time.Time) (application, error) {
		return applicationFixture{err: privateError}, nil
	}
	if err := execute(context.Background(), []string{"binary", "/private/config.json"}, capture, runtime); !errors.Is(err, primitivesstaging.ErrUnavailable) || strings.Contains(err.Error(), "credential") {
		t.Fatalf("runtime error = %v", err)
	}
}
