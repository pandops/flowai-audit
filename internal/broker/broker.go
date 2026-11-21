// Package broker adapts NATS JetStream to audit's consumer and reads.
package broker

import (
	"context"
	"time"

	"github.com/pandops/flowai-audit/internal/audit"
)

// Broker names used by audit. The stream and the durable consumer are
// created by the deployment before publishers start.
const (
	Stream        = "ALL_AUDIT"
	Durable       = "audit"
	FilterSubject = "*.audit.*.sub"
	ListSubject   = "audit.ui.list.sub"
	GetSubject    = "audit.ui.get.sub"
	QueueGroup    = "audit"
	StatusHeader  = "status"
)

// BatchSize is the most deliveries fetched at once.
const BatchSize = 64

// Subjects returns every subject audit subscribes to or consumes.
func Subjects() []string { return []string{FilterSubject, ListSubject, GetSubject} }

// Fetcher pulls deliveries from the durable consumer.
type Fetcher interface {
	Fetch(ctx context.Context, max int) ([]audit.Delivery, error)
}

// RunConsumer pulls and handles deliveries until ctx ends, retrying fetch
// errors after backoff without restarting. healthy reports fetch state.
// It returns ctx's error once ctx ends.
// Deliveries are handled one at a time: audit is a single serial consumer.
func RunConsumer(ctx context.Context, f Fetcher, c *audit.Consumer, backoff time.Duration, healthy func(bool)) error {
	for ctx.Err() == nil {
		batch, err := f.Fetch(ctx, BatchSize)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			healthy(false)
			wait(ctx, backoff)
			continue
		}
		healthy(true)
		retry := false
		for _, d := range batch {
			if ctx.Err() != nil {
				break
			}
			if c.Handle(ctx, d) == audit.ResultRetry {
				retry = true
			}
		}
		if retry {
			wait(ctx, backoff)
		}
	}
	return ctx.Err()
}

func wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
