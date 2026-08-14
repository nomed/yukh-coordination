package previewruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nats-io/nats.go"
	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/jetstream"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
	relayruntime "github.com/nomed/yukh-coordination/internal/relay/runtime"
	"github.com/nomed/yukh-coordination/internal/relay/service"
)

const (
	PreviewTenantID   = "tenant:local-preview"
	PreviewChannelID  = "channel:local-preview"
	PreviewChannelURI = "https://preview.local/channels/local-preview"
	PreviewEpoch      = "1"
	previewDigest     = "sha-256:1111111111111111111111111111111111111111111111111111111111111111"
)

type CoordinatorConfig struct {
	NATSURL       string
	PublicBaseURI string
	Listener      net.Listener
	Authority     *Authority
}

type Coordinator struct {
	runtime   *relayruntime.Runtime
	publicKey ed25519.PublicKey
}

func NewCoordinator(ctx context.Context, config CoordinatorConfig) (*Coordinator, error) {
	if ctx == nil || config.Authority == nil || config.Listener == nil || !localNATSURL(config.NATSURL) || !httpsBase(config.PublicBaseURI) {
		return nil, relay.ErrInvalidArgument
	}
	connection, err := nats.Connect(config.NATSURL, nats.Name("yukh-local-preview-relay"), nats.NoReconnect(), nats.Timeout(3*time.Second))
	if err != nil {
		return nil, ErrIdentityUnavailable
	}
	closeConnection := func() { connection.Close() }
	store, err := jetstream.Open(ctx, connection, jetstream.Config{Replicas: 1, Bootstrap: true})
	if err != nil {
		closeConnection()
		return nil, err
	}
	validator, err := protocol.NewValidator()
	if err != nil {
		closeConnection()
		return nil, err
	}
	channel, err := previewChannel(validator)
	if err != nil {
		closeConnection()
		return nil, err
	}
	if err := store.CreateChannel(ctx, channel); err != nil {
		closeConnection()
		return nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		closeConnection()
		return nil, err
	}
	runtime, err := relayruntime.New(relayruntime.Config{
		Store: store, Subscriptions: store, Bootstrapper: config.Authority, Authenticator: config.Authority,
		Authorizer: previewAuthorizer{}, Signer: previewSigner{privateKey: privateKey}, Validator: validator, Listener: config.Listener,
		Server: relayruntime.ServerConfig{
			HTTP:              httpapi.Config{PublicBaseURI: config.PublicBaseURI, HeartbeatInterval: 5 * time.Second, MaxStreamLifetime: 15 * time.Minute, WriteTimeout: 5 * time.Second},
			ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16_384, ShutdownTimeout: 5 * time.Second,
		},
		Resources: []relayruntime.Resource{{Name: "nats", Close: func(context.Context) error { closeConnection(); return nil }}},
	})
	if err != nil {
		closeConnection()
		return nil, err
	}
	return &Coordinator{runtime: runtime, publicKey: publicKey}, nil
}

func (c *Coordinator) Run(ctx context.Context) error {
	if c == nil || c.runtime == nil {
		return relay.ErrInvalidArgument
	}
	return c.runtime.Run(ctx)
}

func (c *Coordinator) Ready() <-chan struct{} {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.Ready()
}

func (c *Coordinator) ReceiptPublicKey() string {
	if c == nil || len(c.publicKey) != ed25519.PublicKeySize {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(c.publicKey)
}

type previewSigner struct{ privateKey ed25519.PrivateKey }

func (previewSigner) Select(context.Context) (service.SigningSelection, error) {
	return service.SigningSelection{KeyID: "local-preview-receipt-1", Algorithm: "ed25519"}, nil
}

func (s previewSigner) Sign(_ context.Context, record relay.AcceptedRecord) ([]byte, error) {
	if len(s.privateKey) != ed25519.PrivateKeySize || len(record.UnsignedReceiptPreimage) == 0 {
		return nil, relay.ErrInvalidArgument
	}
	return ed25519.Sign(s.privateKey, record.UnsignedReceiptPreimage), nil
}

type previewAuthorizer struct{}

func (previewAuthorizer) Authorize(_ context.Context, request httpapi.AccessRequest) (httpapi.Decision, error) {
	if request.Identity.TenantID != PreviewTenantID || request.Channel != (relay.ChannelKey{TenantID: PreviewTenantID, ChannelID: PreviewChannelID, TranscriptEpoch: PreviewEpoch}) {
		return httpapi.Decision{}, relay.ErrChannelNotFound
	}
	if request.Action != httpapi.ActionPublish && request.Action != httpapi.ActionReplay && request.Action != httpapi.ActionWatch {
		return httpapi.Decision{}, relay.ErrChannelNotFound
	}
	binding := []byte(`{"profile":"yukh-coordination/local-preview-v1"}`)
	return httpapi.Decision{Allowed: true, CanonicalBinding: binding, ACLPolicyVersion: "local-preview-v1", ACLPolicyDigest: previewDigest, DecisionReceiptID: "local-preview-decision", Revoked: make(chan struct{})}, nil
}

func previewChannel(validator *protocol.Validator) (relay.Channel, error) {
	document, err := json.Marshal(map[string]any{
		"acl_policy_digest": previewDigest, "acl_policy_version": "local-preview-v1",
		"channel_id": PreviewChannelID, "channel_uri": PreviewChannelURI,
		"created_at": "2026-08-14T00:00:00.000Z", "retention_epoch": 0,
		"retention_policy_digest": previewDigest, "specversion": "0.1", "tenant_id": PreviewTenantID,
	})
	if err != nil {
		return relay.Channel{}, err
	}
	document, err = jsoncanonicalizer.Transform(document)
	if err != nil {
		return relay.Channel{}, err
	}
	metadata, err := validator.ValidateChannelMetadata(document)
	if err != nil {
		return relay.Channel{}, err
	}
	return relay.Channel{Key: relay.ChannelKey{TenantID: PreviewTenantID, ChannelID: PreviewChannelID, TranscriptEpoch: PreviewEpoch}, URI: PreviewChannelURI, CanonicalMetadata: document, MetadataDigest: metadata.Digest, Lifecycle: "active"}, nil
}

func localNATSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "nats" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "" && parsed.Port() != "" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "nats") && parsed.String() == value
}

func httpsBase(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "" && !strings.HasSuffix(value, "/") && parsed.String() == value
}

var _ service.Signer = previewSigner{}
var _ httpapi.Authorizer = previewAuthorizer{}
