package service

import (
	"context"
	"sync"

	"github.com/nomed/yukh-coordination/internal/relay"
)

// LiveChanges is the bounded single-process notification adapter used by the
// SQLite reference relay. Durable reads, not notifications, carry records.
type LiveChanges struct {
	mu          sync.Mutex
	nextID      uint64
	subscribers map[relay.ChannelKey]map[uint64]chan struct{}
}

func NewLiveChanges() *LiveChanges {
	return &LiveChanges{subscribers: make(map[relay.ChannelKey]map[uint64]chan struct{})}
}

func (l *LiveChanges) Subscribe(ctx context.Context, key relay.ChannelKey, _ uint64) (<-chan struct{}, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if key.TenantID == "" || key.ChannelID == "" || key.TranscriptEpoch == "" {
		return nil, nil, relay.ErrInvalidArgument
	}
	l.mu.Lock()
	l.nextID++
	id := l.nextID
	updates := make(chan struct{}, 1)
	if l.subscribers[key] == nil {
		l.subscribers[key] = make(map[uint64]chan struct{})
	}
	l.subscribers[key][id] = updates
	l.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			l.mu.Lock()
			delete(l.subscribers[key], id)
			if len(l.subscribers[key]) == 0 {
				delete(l.subscribers, key)
			}
			l.mu.Unlock()
		})
	}
	return updates, unsubscribe, nil
}

func (l *LiveChanges) Notify(key relay.ChannelKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, updates := range l.subscribers[key] {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
}
