package clientcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	coordclient "github.com/nomed/yukh-coordination/internal/client"
	"github.com/nomed/yukh-coordination/internal/clientauth"
	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
	"github.com/nomed/yukh-coordination/internal/clientevent"
)

const maxExecutableConfig = 32 << 10

type executableConfig struct {
	Schema          int                     `json:"schema"`
	Profile         string                  `json:"profile"`
	BaseURI         string                  `json:"base_uri"`
	ChannelID       string                  `json:"channel_id"`
	ChannelURI      string                  `json:"channel_uri"`
	TranscriptEpoch uint64                  `json:"transcript_epoch"`
	PageLimit       int                     `json:"page_limit"`
	MaxRecords      int                     `json:"max_records"`
	WatchDeadlineMS int                     `json:"watch_deadline_ms"`
	SourceURI       string                  `json:"source_uri"`
	Participant     clientevent.Participant `json:"participant"`
	CustodyDatabase string                  `json:"custody_database"`
	CACertificate   string                  `json:"ca_certificate,omitempty"`
	ReceiptKeys     []executableReceiptKey  `json:"receipt_keys"`
}

type executableReceiptKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// Executable owns process-level configuration and composes the closed client
// command. Secret values enter only through inherited descriptors.
type Executable struct{ httpClient *http.Client }

func (e Executable) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "version") {
		return (Command{}).Run(ctx, args, stdin, stdout)
	}
	configPath, rootDescriptor, tokenDescriptor, commandArgs, ok := executableArgs(args)
	if !ok {
		return write(stdout, output{Schema: 1, Status: "error", Command: "unknown", Code: "YKC-INPUT-001"}, 2)
	}
	config, err := readExecutableConfig(configPath)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-INPUT-001"}, 2)
	}
	clientConfig := coordclient.Config{BaseURI: config.BaseURI, ChannelID: config.ChannelID, ChannelURI: config.ChannelURI, TranscriptEpoch: config.TranscriptEpoch, PageLimit: config.PageLimit, MaxRecords: config.MaxRecords}
	verifier, verifyErr := executableVerifier(config.ReceiptKeys)
	builder, buildErr := clientevent.New(clientevent.Config{ChannelURI: config.ChannelURI, SourceURI: config.SourceURI, Participant: config.Participant})
	if coordclient.ValidateConfig(clientConfig) != nil || verifyErr != nil || buildErr != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-INPUT-001"}, 2)
	}
	root, err := localcustody.NewDescriptorRootKeySource(rootDescriptor, config.Profile)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-CUSTODY-001"}, 8)
	}
	defer root.Close()
	store, err := localcustody.Open(config.CustodyDatabase, root)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-CUSTODY-001"}, 8)
	}
	defer store.Close()
	authorizer, err := clientauth.NewAuthorizer(store, store, config.Profile)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-INPUT-001"}, 2)
	}
	httpClient, transportErr := closedHTTPClient(e.httpClient, config.CACertificate)
	if transportErr != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-INPUT-001"}, 2)
	}
	client, err := coordclient.New(clientConfig, httpClient, authorizer, verifier)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-INPUT-001"}, 2)
	}
	command := Command{
		Read:    Runner{Open: func(coordclient.Config) (ReplayClient, error) { return client, nil }},
		Signals: SignalRunner{Builder: builder, Publisher: client},
	}
	if commandName(commandArgs) == "session bootstrap" {
		if tokenDescriptor < 3 {
			return write(stdout, output{Schema: 1, Status: "error", Command: "session bootstrap", Code: "YKC-INPUT-001"}, 2)
		}
		tokens, tokenErr := clientauth.NewDescriptorTokenSource(tokenDescriptor)
		issuer, issuerErr := clientauth.NewHTTPIssuer(config.BaseURI, httpClient)
		bootstrapper, bootstrapErr := clientauth.NewBootstrapper(store, store, tokens, issuer, config.Profile)
		if tokenErr != nil || issuerErr != nil || bootstrapErr != nil {
			return write(stdout, output{Schema: 1, Status: "error", Command: "session bootstrap", Code: "YKC-INPUT-001"}, 2)
		}
		command.Bootstrap = BootstrapRunner{Bootstrapper: bootstrapper}
	} else if tokenDescriptor != -1 {
		return write(stdout, output{Schema: 1, Status: "error", Command: commandName(commandArgs), Code: "YKC-INPUT-001"}, 2)
	}
	if commandName(commandArgs) == "events watch" {
		if config.WatchDeadlineMS < 1000 || config.WatchDeadlineMS > 900000 {
			return write(stdout, output{Schema: 1, Status: "error", Command: "events watch", Code: "YKC-INPUT-001"}, 2)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.WatchDeadlineMS)*time.Millisecond)
		defer cancel()
	}
	return command.Run(ctx, executableCommandArgs(commandArgs, config), stdin, stdout)
}

func executableArgs(args []string) (string, int, int, []string, bool) {
	if len(args) < 6 || args[0] != "--config" || args[2] != "--root-key-fd" {
		return "", 0, 0, nil, false
	}
	root, err := canonicalDescriptor(args[3])
	if err != nil || !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] {
		return "", 0, 0, nil, false
	}
	index, token := 4, -1
	if len(args) > 5 && args[4] == "--external-token-fd" {
		token, err = canonicalDescriptor(args[5])
		if err != nil || token == root {
			return "", 0, 0, nil, false
		}
		index = 6
	}
	if len(args[index:]) < 1 {
		return "", 0, 0, nil, false
	}
	return args[1], root, token, append([]string(nil), args[index:]...), true
}

func canonicalDescriptor(raw string) (int, error) {
	value, err := canonicalUint(raw)
	if err != nil || value < 3 || value > 1024 {
		return 0, coordclient.ErrInvalidInput
	}
	return int(value), nil
}

func readExecutableConfig(path string) (executableConfig, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 2 || info.Size() > maxExecutableConfig {
		return executableConfig{}, coordclient.ErrInvalidInput
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return executableConfig{}, coordclient.ErrInvalidInput
	}
	var config executableConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF || config.Schema != 1 || config.Profile == "" || !filepath.IsAbs(config.CustodyDatabase) || filepath.Clean(config.CustodyDatabase) != config.CustodyDatabase {
		return executableConfig{}, coordclient.ErrInvalidInput
	}
	return config, nil
}

func executableVerifier(entries []executableReceiptKey) (*coordclient.Ed25519ReceiptVerifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(entries))
	for _, entry := range entries {
		key, err := base64.RawURLEncoding.Strict().DecodeString(entry.PublicKey)
		if err != nil || keys[entry.KeyID] != nil {
			return nil, coordclient.ErrInvalidInput
		}
		keys[entry.KeyID] = ed25519.PublicKey(key)
	}
	return coordclient.NewEd25519ReceiptVerifier(keys)
}

func closedHTTPClient(base *http.Client, caCertificate string) (*http.Client, error) {
	if base == nil {
		base = &http.Client{Transport: http.DefaultTransport}
	}
	result := *base
	transport, ok := result.Transport.(*http.Transport)
	if !ok {
		if caCertificate != "" {
			return nil, coordclient.ErrInvalidInput
		}
	} else {
		closedTransport := transport.Clone()
		closedTransport.Proxy = nil
		if caCertificate != "" {
			roots, err := certificatePool(caCertificate)
			if err != nil {
				return nil, err
			}
			if closedTransport.TLSClientConfig == nil {
				closedTransport.TLSClientConfig = &tls.Config{}
			} else {
				closedTransport.TLSClientConfig = closedTransport.TLSClientConfig.Clone()
			}
			closedTransport.TLSClientConfig.RootCAs = roots
		}
		result.Transport = closedTransport
	}
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if result.Timeout <= 0 || result.Timeout > 10*time.Second {
		result.Timeout = 10 * time.Second
	}
	return &result, nil
}

func certificatePool(path string) (*x509.CertPool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, coordclient.ErrInvalidInput
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > 64<<10 {
		return nil, coordclient.ErrInvalidInput
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, coordclient.ErrInvalidInput
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, coordclient.ErrInvalidInput
	}
	return pool, nil
}

func executableCommandArgs(args []string, config executableConfig) []string {
	if commandName(args) != "events replay" && commandName(args) != "events watch" && commandName(args) != "work inspect" {
		return args
	}
	result := append([]string(nil), args...)
	result = append(result, "--base-uri", config.BaseURI, "--channel-id", config.ChannelID, "--channel-uri", config.ChannelURI, "--transcript-epoch", strconv.FormatUint(config.TranscriptEpoch, 10), "--limit", strconv.Itoa(config.PageLimit), "--max-records", strconv.Itoa(config.MaxRecords))
	return result
}

func commandName(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	if len(args) >= 2 {
		return args[0] + " " + args[1]
	}
	return "unknown"
}
