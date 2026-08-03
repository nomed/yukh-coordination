// Package jetstream implements the RFC-0006 distributed relay adapter.
package jetstream

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/relay"
)

const (
	StreamName      = "YUKH_COORDINATION_V1"
	SubjectPattern  = "yukh.coordination.v1.tenant.*.log"
	MaxCommandBytes = int32(131_072)
	adapterVersion  = "1"
)

type Config struct {
	Replicas  int
	Bootstrap bool
}

type Store struct {
	js     natsjs.JetStream
	stream natsjs.Stream
	config Config
}

func Open(ctx context.Context, connection *nats.Conn, config Config) (*Store, error) {
	if connection == nil || config.Replicas < 1 || config.Replicas > 5 {
		return nil, relay.ErrInvalidArgument
	}
	js, err := natsjs.New(connection)
	if err != nil {
		return nil, fmt.Errorf("create JetStream client: %w", err)
	}
	stream, err := js.Stream(ctx, StreamName)
	if errors.Is(err, natsjs.ErrStreamNotFound) && config.Bootstrap {
		stream, err = js.CreateStream(ctx, ExpectedStreamConfig(config.Replicas))
	}
	if err != nil {
		return nil, fmt.Errorf("open JetStream relay stream: %w", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect JetStream relay stream: %w", err)
	}
	if err := ValidateStreamConfig(info.Config, config.Replicas); err != nil {
		return nil, err
	}
	return &Store{js: js, stream: stream, config: config}, nil
}

func ExpectedStreamConfig(replicas int) natsjs.StreamConfig {
	return natsjs.StreamConfig{
		Name: StreamName, Description: "Yukh Coordination RFC-0006 tenant command logs",
		Subjects: []string{SubjectPattern}, Retention: natsjs.LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
		Discard: natsjs.DiscardNew, Storage: natsjs.FileStorage, Replicas: replicas,
		MaxMsgSize: MaxCommandBytes, DenyDelete: true, DenyPurge: true,
		AllowRollup: false, AllowAtomicPublish: false, AllowMsgTTL: false,
		AllowMsgCounter: false, AllowMsgSchedules: false, AllowDirect: false,
		Metadata: map[string]string{"yukh.adapter": "jetstream", "yukh.adapter.version": adapterVersion},
	}
}

func ValidateStreamConfig(actual natsjs.StreamConfig, replicas int) error {
	expected := ExpectedStreamConfig(replicas)
	if actual.Name != expected.Name || !reflect.DeepEqual(actual.Subjects, expected.Subjects) ||
		actual.Retention != expected.Retention || actual.MaxConsumers != expected.MaxConsumers ||
		actual.MaxMsgs != expected.MaxMsgs || actual.MaxBytes != expected.MaxBytes || actual.MaxAge != 0 ||
		actual.MaxMsgsPerSubject != expected.MaxMsgsPerSubject || actual.Discard != expected.Discard ||
		actual.Storage != expected.Storage || actual.Replicas != expected.Replicas || actual.NoAck ||
		actual.MaxMsgSize != expected.MaxMsgSize || !actual.DenyDelete || !actual.DenyPurge ||
		actual.AllowRollup || actual.AllowAtomicPublish || actual.AllowMsgTTL || actual.AllowMsgCounter ||
		actual.AllowMsgSchedules || actual.AllowDirect || actual.RePublish != nil || actual.Mirror != nil ||
		len(actual.Sources) != 0 || !validMetadata(actual.Metadata, expected.Metadata) {
		return fmt.Errorf("%w: JetStream stream configuration mismatch", relay.ErrInvalidArgument)
	}
	return nil
}

func validMetadata(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	for key := range actual {
		if !strings.HasPrefix(key, "_nats.") {
			if _, ok := expected[key]; !ok {
				return false
			}
		}
	}
	return true
}

func TenantToken(tenantID string) (string, error) {
	if tenantID == "" {
		return "", relay.ErrInvalidArgument
	}
	digest := sha256.Sum256([]byte(tenantID))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])), nil
}

func TenantSubject(tenantID string) (string, error) {
	token, err := TenantToken(tenantID)
	if err != nil {
		return "", err
	}
	return "yukh.coordination.v1.tenant." + token + ".log", nil
}
