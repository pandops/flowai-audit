// Package app wires audit's consumer, reads and probes; main uses it with
// the PostgreSQL store and the NATS durable consumer.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/broker"
	"github.com/pandops/flowai-audit/internal/cursor"
	"github.com/pandops/flowai-audit/internal/health"
)

// Deps are the service's boundaries.
type Deps struct {
	Store   audit.Store
	Fetcher broker.Fetcher
	Keys    *cursor.Keyring
	Logger  *slog.Logger
	Backoff time.Duration
	// Checks are further readiness dependencies (the NATS connection).
	Checks []health.Check
}

// Service is one running audit instance.
type Service struct {
	deps     Deps
	consumer *audit.Consumer
	reader   *audit.Reader
	fetching atomic.Bool
	handler  http.Handler
}

var errBrokerDown = errors.New("durable consumer is not reachable")

// New wires the service.
func New(d Deps) *Service {
	if d.Backoff <= 0 {
		d.Backoff = time.Second
	}
	s := &Service{deps: d, consumer: audit.NewConsumer(d.Store, d.Logger), reader: audit.NewReader(d.Store, d.Keys, d.Logger)}
	checks := []health.Check{
		{Name: "database", Fn: d.Store.Ping},
		{Name: "broker", Fn: func(context.Context) error {
			if !s.fetching.Load() {
				return errBrokerDown
			}
			return nil
		}},
	}
	s.handler = health.NewRouter(append(checks, d.Checks...)...)
	return s
}

// Run consumes ALL_AUDIT until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	defer s.fetching.Store(false)
	return broker.RunConsumer(ctx, s.deps.Fetcher, s.consumer, s.deps.Backoff, func(ok bool) {
		if ok != s.fetching.Load() {
			s.fetching.Store(ok)
			if ok {
				s.deps.Logger.Info("durable consumer reachable", slog.String("durable", broker.Durable))
			} else {
				s.deps.Logger.Warn("durable consumer unreachable, retrying", slog.String("durable", broker.Durable))
			}
		}
	})
}

// Handler serves /v1/livez and /v1/readyz.
func (s *Service) Handler() http.Handler { return s.handler }

// Serve answers one ui request.
func (s *Service) Serve(ctx context.Context, req audit.Request) audit.Reply {
	return s.reader.Serve(ctx, req)
}
