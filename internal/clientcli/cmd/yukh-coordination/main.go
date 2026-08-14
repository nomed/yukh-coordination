package main

import (
	"context"
	"net/http"
	"os"

	"github.com/nomed/yukh-coordination/internal/clientauth"
	"github.com/nomed/yukh-coordination/internal/clientauth/macosprofile"
	"github.com/nomed/yukh-coordination/internal/clientauth/secretservice"
	"github.com/nomed/yukh-coordination/internal/clientauth/tokenfd"
	"github.com/nomed/yukh-coordination/internal/clientauth/workstation"
	"github.com/nomed/yukh-coordination/internal/clientcli"
)

func main() {
	os.Exit(command().Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout))
}

func command() clientcli.Command {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	linux, err := workstation.NewFactory(workstation.Dependencies{
		RootKeys:    secretservice.NewRootKeyFactory(),
		TokenReader: tokenfd.NewReader(),
		Transport:   transport,
	})
	if err != nil {
		return clientcli.Command{}
	}
	macos, err := macosprofile.NewFactory(macosprofile.Dependencies{
		TokenReader: tokenfd.NewReader(),
		Transport:   transport,
	})
	if err != nil {
		return clientcli.Command{}
	}
	return clientcli.Command{Bootstrap: clientcli.BootstrapRunner{Open: func(ctx context.Context, configPath string, tokenFD, busFD int) (clientcli.BootstrapOperation, error) {
		if _, err := macosprofile.LoadConfigFile(configPath); err == nil {
			return macos.Open(ctx, configPath, tokenFD)
		}
		if busFD < 3 {
			return nil, clientauth.ErrInvalidCredential
		}
		return linux.Open(ctx, configPath, tokenFD, busFD)
	}}}
}
