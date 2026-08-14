package main

import (
	"context"
	"io"
	"net/http"
	"os"

	"github.com/nomed/yukh-coordination/internal/clientauth/keychain"
	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
	"github.com/nomed/yukh-coordination/internal/clientauth/macosprofile"
	"github.com/nomed/yukh-coordination/internal/clientauth/secretservice"
	"github.com/nomed/yukh-coordination/internal/clientauth/tokenfd"
	"github.com/nomed/yukh-coordination/internal/clientauth/workstation"
	"github.com/nomed/yukh-coordination/internal/clientcli"
)

func main() {
	os.Exit(command().Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout))
}

type application struct {
	executable  clientcli.Executable
	workstation clientcli.WorkstationBootstrapRunner
}

func (a application) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) >= 2 && args[0] == "session" && args[1] == "bootstrap" && len(args) > 2 && args[2] == "--config" {
		return a.workstation.Run(ctx, args[2:], stdout)
	}
	return a.executable.Run(ctx, args, stdin, stdout)
}

func command() application {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	reader := tokenfd.NewReader()
	linux, linuxErr := workstation.NewFactory(workstation.Dependencies{
		RootKeys: secretservice.NewRootKeyFactory(), TokenReader: reader, Transport: transport,
	})
	macos, macosErr := macosprofile.NewFactory(macosprofile.Dependencies{
		RootKeys: func(binding keychain.Binding, policy keychain.CreationPolicy) (localcustody.RootKeySource, error) {
			return keychain.NewSource(binding, policy)
		},
		TokenReader: reader, Transport: transport,
	})
	return application{workstation: clientcli.WorkstationBootstrapRunner{Open: func(ctx context.Context, configPath string, tokenFD, busFD int) (clientcli.WorkstationBootstrapOperation, error) {
		if macosErr == nil {
			if _, err := macosprofile.LoadConfigFile(configPath); err == nil {
				return macos.Open(ctx, configPath, tokenFD)
			}
		}
		if linuxErr != nil || busFD < 3 {
			return nil, workstation.ErrInvalidConfiguration
		}
		return linux.Open(ctx, configPath, tokenFD, busFD)
	}}}
}
