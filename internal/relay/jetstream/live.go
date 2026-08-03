package jetstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/relay"
)

const liveConsumerCleanupTimeout = 2 * time.Second

// Subscribe establishes the JetStream wake-up path before returning. The
// cursor is intentionally ignored: JetStream revisions are not Yukh cursors,
// and the caller closes races by reading durable state after subscription.
func (s *Store) Subscribe(ctx context.Context, key relay.ChannelKey, _ uint64) (<-chan struct{}, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := validateKey(key); err != nil {
		return nil, nil, err
	}
	subject, err := TenantSubject(key.TenantID)
	if err != nil {
		return nil, nil, err
	}
	consumer, err := s.stream.OrderedConsumer(ctx, natsjs.OrderedConsumerConfig{
		FilterSubjects:    []string{subject},
		DeliverPolicy:     natsjs.DeliverNewPolicy,
		InactiveThreshold: 30 * time.Second,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create live tenant consumer: %w", err)
	}
	info := consumer.CachedInfo()
	if info == nil || info.Name == "" {
		return nil, nil, fmt.Errorf("live tenant consumer has no server identity")
	}

	updates := make(chan struct{}, 1)
	var once sync.Once
	var lifecycle sync.Mutex
	closed := false
	var consumption natsjs.ConsumeContext
	finish := func() {
		once.Do(func() {
			lifecycle.Lock()
			closed = true
			active := consumption
			lifecycle.Unlock()
			if active != nil {
				active.Stop()
			}
			cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), liveConsumerCleanupTimeout)
			defer cancel()
			_ = s.stream.DeleteConsumer(cleanupContext, info.Name)
			lifecycle.Lock()
			close(updates)
			lifecycle.Unlock()
		})
	}

	started, err := consumer.Consume(func(message natsjs.Msg) {
		if message.Subject() != subject {
			go finish()
			return
		}
		lifecycle.Lock()
		defer lifecycle.Unlock()
		if closed {
			return
		}
		select {
		case updates <- struct{}{}:
		default:
		}
	}, natsjs.PullMaxMessages(1), natsjs.ConsumeErrHandler(func(_ natsjs.ConsumeContext, _ error) {
		go finish()
	}))
	if err != nil {
		finish()
		return nil, nil, fmt.Errorf("start live tenant consumer: %w", err)
	}
	lifecycle.Lock()
	consumption = started
	finishedDuringSetup := closed
	lifecycle.Unlock()
	if finishedDuringSetup {
		started.Stop()
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-started.Closed():
		}
		finish()
	}()
	return updates, finish, nil
}

// Notify is a no-op because every successful JetStream Store mutation already
// publishes the durable command that wakes filtered consumers. Core NATS is
// deliberately not introduced as a second, lossy notification path.
func (s *Store) Notify(relay.ChannelKey) {}
