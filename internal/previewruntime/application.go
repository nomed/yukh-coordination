package previewruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Application struct {
	coordinator        *Coordinator
	supervisor         *http.Server
	supervisorListener net.Listener
}

func OpenApplication(ctx context.Context, configPath string) (*Application, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificate(), config.TLSPrivateKey())
	if err != nil {
		return nil, ErrIdentityUnavailable
	}
	tokenRaw, err := os.ReadFile(config.SupervisorToken())
	if err != nil || strings.TrimSpace(string(tokenRaw)) != string(tokenRaw) {
		clear(tokenRaw)
		return nil, ErrIdentityUnavailable
	}
	token := string(tokenRaw)
	clear(tokenRaw)
	publicRaw, err := net.Listen("tcp", config.PublicBind())
	if err != nil {
		return nil, ErrIdentityUnavailable
	}
	closePublic := true
	defer func() {
		if closePublic {
			_ = publicRaw.Close()
		}
	}()
	supervisorRaw, err := net.Listen("tcp", config.SupervisorBind())
	if err != nil {
		return nil, ErrIdentityUnavailable
	}
	closeSupervisor := true
	defer func() {
		if closeSupervisor {
			_ = supervisorRaw.Close()
		}
	}()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	authority := NewAuthority()
	coordinator, err := NewCoordinator(ctx, CoordinatorConfig{NATSURL: config.NATSURL(), PublicBaseURI: config.PublicBaseURI(), Listener: tls.NewListener(publicRaw, tlsConfig.Clone()), Authority: authority})
	if err != nil {
		return nil, err
	}
	supervisor, err := NewSupervisor(authority, token, coordinator.ReceiptPublicKey())
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler: supervisor, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0),
	}
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	serverTLS := tls.NewListener(supervisorRaw, tlsConfig.Clone())
	closePublic, closeSupervisor = false, false
	return &Application{coordinator: coordinator, supervisor: server, supervisorListener: serverTLS}, nil
}

func (a *Application) Run(ctx context.Context) error {
	if a == nil || a.coordinator == nil || a.supervisor == nil || a.supervisorListener == nil || ctx == nil {
		return ErrIdentityUnavailable
	}
	operation, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsOut := make(chan error, 2)
	go func() { errorsOut <- a.coordinator.Run(operation) }()
	go func() { errorsOut <- a.supervisor.Serve(a.supervisorListener) }()
	var runErr error
	received := 0
	select {
	case <-ctx.Done():
	case runErr = <-errorsOut:
		received = 1
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	shutdownErr := a.supervisor.Shutdown(shutdown)
	for received < 2 {
		err := <-errorsOut
		received++
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = errors.Join(runErr, err)
		}
	}
	return errors.Join(runErr, shutdownErr)
}
