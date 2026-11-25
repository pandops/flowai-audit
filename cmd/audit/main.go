// Command audit consumes ALL_AUDIT, stores each human action once and serves
// team-filtered audit reads to API Gateway over NATS.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/pandops/flowai-audit/internal/app"
	"github.com/pandops/flowai-audit/internal/broker"
	"github.com/pandops/flowai-audit/internal/config"
	"github.com/pandops/flowai-audit/internal/health"
	"github.com/pandops/flowai-audit/internal/migrations"
	"github.com/pandops/flowai-audit/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(slog.String("service", "audit"))
	if err := run(logger); err != nil {
		logger.Error("audit stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	path := flag.String("config", "/etc/flowai/config.yaml", "configuration file")
	flag.Parse()
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("pgx", cfg.DSN())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := migrateUntilDone(ctx, db, cfg.DB.Schema, logger); err != nil {
		return err
	}
	st, err := store.New(db, cfg.DB.Schema)
	if err != nil {
		return err
	}

	nc, err := broker.Connect(broker.ConnectOptions{URL: cfg.NATS.URL, CAPEM: cfg.NATSCAPEM,
		UserJWT: cfg.NATSUserJWT, UserSeed: cfg.NATSUserSeed, InboxPrefix: cfg.NATS.InboxPrefix})
	if err != nil {
		return err
	}
	defer nc.Close()
	fetcher, err := broker.NewJetStreamFetcher(nc)
	if err != nil {
		return err
	}
	svc := app.New(app.Deps{Store: st, Fetcher: fetcher, Keys: cfg.Keyring, Logger: logger, Backoff: time.Second,
		Checks: []health.Check{{Name: "nats", Fn: func(context.Context) error {
			if nc.Status() != nats.CONNECTED {
				return errors.New("nats is not connected")
			}
			return nil
		}}}})
	subs, err := broker.ServeRequests(nc, cfg.RequestTimeout, svc.Serve)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range subs {
			_ = s.Drain()
		}
	}()

	server := &http.Server{Addr: cfg.HTTP.Listen, Handler: svc.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 2)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	go func() { errc <- svc.Run(ctx) }()
	logger.Info("audit started", slog.String("listen", cfg.HTTP.Listen), slog.String("schema", cfg.DB.Schema))

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	if errors.Is(err, context.Canceled) {
		err = nil // normal shutdown
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	return err
}

// migrateUntilDone retries the migration while the database is unreachable;
// the probes stay down until it succeeds because the listener is not up yet.
func migrateUntilDone(ctx context.Context, db *sql.DB, schema string, logger *slog.Logger) error {
	for {
		err := migrations.Apply(ctx, db, schema)
		if err == nil {
			return nil
		}
		if db.PingContext(ctx) == nil {
			return err // reachable but not migratable: a configuration error
		}
		logger.Warn("database unreachable, retrying migration")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
