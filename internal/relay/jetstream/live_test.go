package jetstream

import (
	"context"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay"
)

func TestLiveSubscriptionClosesSubscribeBeforeReadRace(t *testing.T) {
	connection := startServer(t, "14225")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true})
	if err != nil {
		t.Fatal(err)
	}
	base := liveTestChannel("tenant:live", "channel:live", "1")
	if err := store.CreateChannel(ctx, base); err != nil {
		t.Fatal(err)
	}

	updates, unsubscribe, err := store.Subscribe(ctx, base.Key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if consumers := consumerCount(t, ctx, store); consumers != 1 {
		t.Fatalf("Subscribe returned before consumer setup: %d consumers", consumers)
	}

	next := liveTestChannel("tenant:live", "channel:live", "2")
	if err := store.CreateChannel(ctx, next); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupChannel(ctx, next.Key); err != nil {
		t.Fatalf("durable read did not observe concurrent command: %v", err)
	}
	select {
	case _, open := <-updates:
		if !open {
			t.Fatal("live subscription closed unexpectedly")
		}
	case <-time.After(time.Second):
		t.Fatal("tenant command did not wake subscription")
	}

	otherTenant := liveTestChannel("tenant:other", "channel:other", "1")
	if err := store.CreateChannel(ctx, otherTenant); err != nil {
		t.Fatal(err)
	}
	select {
	case <-updates:
		t.Fatal("cross-tenant command leaked into subscription")
	case <-time.After(150 * time.Millisecond):
	}

	for _, epoch := range []string{"3", "4", "5"} {
		channel := liveTestChannel("tenant:live", "channel:live", epoch)
		if err := store.CreateChannel(ctx, channel); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if buffered := len(updates); buffered != 1 {
		t.Fatalf("wake-ups were not coalesced into one bounded signal: %d", buffered)
	}

	unsubscribe()
	unsubscribe()
	waitForConsumerCount(t, ctx, store, 0)
	waitForSubscriptionClose(t, updates)
}

func TestLiveSubscriptionCancellationDeletesConsumer(t *testing.T) {
	connection := startServer(t, "14226")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true})
	if err != nil {
		t.Fatal(err)
	}
	key := relay.ChannelKey{TenantID: "tenant:cancel", ChannelID: "channel:cancel", TranscriptEpoch: "1"}
	subscriptionContext, stop := context.WithCancel(ctx)
	updates, _, err := store.Subscribe(subscriptionContext, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	waitForSubscriptionClose(t, updates)
	waitForConsumerCount(t, ctx, store, 0)
}

func TestLiveConsumerFailureClosesSubscription(t *testing.T) {
	connection := startServer(t, "14227")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true})
	if err != nil {
		t.Fatal(err)
	}
	key := relay.ChannelKey{TenantID: "tenant:failure", ChannelID: "channel:failure", TranscriptEpoch: "1"}
	updates, _, err := store.Subscribe(ctx, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	waitForSubscriptionClose(t, updates)
}

func liveTestChannel(tenantID, channelID, epoch string) relay.Channel {
	return relay.Channel{Key: relay.ChannelKey{TenantID: tenantID, ChannelID: channelID, TranscriptEpoch: epoch}, URI: "https://coord.example/" + tenantID + "/" + channelID, CanonicalMetadata: []byte(`{"specversion":"0.1"}`), MetadataDigest: "sha-256:test", Lifecycle: "active"}
}

func consumerCount(t *testing.T, ctx context.Context, store *Store) int {
	t.Helper()
	info, err := store.stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return info.State.Consumers
}

func waitForConsumerCount(t *testing.T, ctx context.Context, store *Store, expected int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if consumerCount(t, ctx, store) == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("consumer count did not reach %d", expected)
}

func waitForSubscriptionClose(t *testing.T, updates <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case _, open := <-updates:
			if !open {
				return
			}
		case <-timer.C:
			t.Fatal("subscription did not close")
		}
	}
}
