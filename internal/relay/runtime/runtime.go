// Package runtime composes the qualified relay layers and owns their process
// lifecycle. Provider selection and external configuration do not belong here.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
	"github.com/nomed/yukh-coordination/internal/relay/service"
)

var ErrAlreadyRun = errors.New("relay runtime: Run may be called only once")

var resourceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

type State string

const (
	StateConstructed State = "constructed"
	StateStarting    State = "starting"
	StateReady       State = "ready"
	StateDraining    State = "draining"
	StateStopped     State = "stopped"
	StateFailed      State = "failed"
)

type Resource struct {
	Name  string
	Close func(context.Context) error
}

type ServerConfig struct {
	HTTP              httpapi.Config
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	ShutdownTimeout   time.Duration
}

type Config struct {
	Store         relay.Store
	Subscriptions service.SubscriptionSource
	Authenticator httpapi.Authenticator
	Authorizer    httpapi.Authorizer
	Signer        service.Signer
	Validator     *protocol.Validator
	Listener      net.Listener
	Server        ServerConfig
	Resources     []Resource
}

type Runtime struct {
	mu        sync.RWMutex
	state     State
	run       bool
	server    *http.Server
	listener  net.Listener
	shutdown  time.Duration
	resources []Resource
	ready     chan struct{}
	done      chan struct{}
}

func New(config Config) (*Runtime, error) {
	if isNil(config.Store) || isNil(config.Subscriptions) || isNil(config.Authenticator) ||
		isNil(config.Authorizer) || isNil(config.Signer) || config.Validator == nil || isNil(config.Listener) {
		return nil, relay.ErrInvalidArgument
	}
	if err := validateServerConfig(config.Server); err != nil {
		return nil, err
	}
	resources, err := validateResources(config.Resources)
	if err != nil {
		return nil, err
	}
	appendService, err := service.NewAppendService(config.Store, config.Signer)
	if err != nil {
		return nil, err
	}
	application, err := service.NewRelayApplication(config.Store, appendService, config.Validator, config.Subscriptions)
	if err != nil {
		return nil, err
	}
	handler, err := httpapi.New(config.Authenticator, config.Authorizer, application, config.Server.HTTP)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: config.Server.ReadHeaderTimeout,
		IdleTimeout:       config.Server.IdleTimeout,
		MaxHeaderBytes:    config.Server.MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return &Runtime{
		state: StateConstructed, server: server, listener: config.Listener,
		shutdown: config.Server.ShutdownTimeout, resources: resources,
		ready: make(chan struct{}), done: make(chan struct{}),
	}, nil
}

func (r *Runtime) Ready() <-chan struct{} { return r.ready }
func (r *Runtime) Done() <-chan struct{}  { return r.done }

func (r *Runtime) State() State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.state
}

func (r *Runtime) Run(parent context.Context) error {
	if parent == nil {
		return relay.ErrInvalidArgument
	}
	r.mu.Lock()
	if r.run {
		r.mu.Unlock()
		return ErrAlreadyRun
	}
	r.run = true
	r.state = StateStarting
	r.mu.Unlock()
	defer close(r.done)

	baseContext, cancelRequests := context.WithCancel(parent)
	r.server.BaseContext = func(net.Listener) context.Context { return baseContext }
	serveErrors := make(chan error, 1)
	go func() {
		r.setState(StateReady)
		close(r.ready)
		serveErrors <- r.server.Serve(r.listener)
	}()

	var lifecycleErrors []error
	select {
	case <-parent.Done():
	case err := <-serveErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			lifecycleErrors = append(lifecycleErrors, stageError{stage: "serve", err: err})
		}
		serveErrors = nil
	}

	r.setState(StateDraining)
	cancelRequests()
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), r.shutdown)
	shutdownErr := r.server.Shutdown(shutdownContext)
	cancelShutdown()
	if shutdownErr != nil {
		lifecycleErrors = append(lifecycleErrors, stageError{stage: "shutdown", err: shutdownErr})
		if err := r.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lifecycleErrors = append(lifecycleErrors, stageError{stage: "force-close", err: err})
		}
	}
	if serveErrors != nil {
		if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
			lifecycleErrors = append(lifecycleErrors, stageError{stage: "serve", err: err})
		}
	}
	cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), r.shutdown)
	defer cancelCleanup()
	for index := len(r.resources) - 1; index >= 0; index-- {
		resource := r.resources[index]
		if err := resource.Close(cleanupContext); err != nil {
			lifecycleErrors = append(lifecycleErrors, stageError{stage: "close", resource: resource.Name, err: err})
		}
	}
	if len(lifecycleErrors) == 0 {
		r.setState(StateStopped)
		return nil
	}
	r.setState(StateFailed)
	return errors.Join(lifecycleErrors...)
}

func (r *Runtime) setState(state State) {
	r.mu.Lock()
	r.state = state
	r.mu.Unlock()
}

func validateServerConfig(config ServerConfig) error {
	if config.HTTP.HeartbeatInterval <= 0 || config.HTTP.MaxStreamLifetime <= 0 || config.HTTP.MaxStreamLifetime > 15*time.Minute ||
		config.HTTP.WriteTimeout <= 0 || config.ReadHeaderTimeout <= 0 || config.IdleTimeout <= 0 ||
		config.MaxHeaderBytes < 1024 || config.MaxHeaderBytes > 1<<20 || config.ShutdownTimeout <= 0 {
		return relay.ErrInvalidArgument
	}
	return nil
}

func validateResources(input []Resource) ([]Resource, error) {
	result := make([]Resource, len(input))
	names := make(map[string]struct{}, len(input))
	for index, resource := range input {
		if !resourceNamePattern.MatchString(resource.Name) || resource.Close == nil {
			return nil, relay.ErrInvalidArgument
		}
		if _, exists := names[resource.Name]; exists {
			return nil, relay.ErrInvalidArgument
		}
		names[resource.Name] = struct{}{}
		result[index] = resource
	}
	return result, nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

type stageError struct {
	stage    string
	resource string
	err      error
}

func (e stageError) Error() string {
	if e.resource == "" {
		return fmt.Sprintf("relay runtime: %s failed", e.stage)
	}
	return fmt.Sprintf("relay runtime: %s %s failed", e.stage, e.resource)
}

func (e stageError) Unwrap() error { return e.err }
