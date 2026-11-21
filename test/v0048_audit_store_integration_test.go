//go:build integration

package test

// 1.7 rows for audit: audit_id from audit's one global commit sequence
// (unique and increasing under concurrent stores, never reused after a
// rollback, continued after a restart), idempotent storage by
// (publisher, publisher_seq) under concurrent redelivery, and immutable
// entries (team ownership never changes).

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/migrations"
	"github.com/pandops/flowai-audit/internal/store"
)

func migratedStore(t *testing.T) (*sql.DB, *store.Store) {
	t.Helper()
	db := freshDB(t)
	if err := migrations.Apply(context.Background(), db, "audit_schema"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s, err := store.New(db, "audit_schema")
	if err != nil {
		t.Fatal(err)
	}
	return db, s
}

func operatorEntry(publisher string, seq, team int64) audit.Entry {
	actor, res := int64(12), int64(4)
	return audit.Entry{TeamID: &team, Publisher: publisher, PublisherSeq: seq, SourceService: publisher,
		ActorType: audit.ActorOperator, ActorID: &actor, Action: "flow_updated", ResourceType: "flow",
		ResourceID: &res, RequestID: 7001, Outcome: "succeeded", OccurredAt: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)}
}

func TestV0048AuditStoreIntegration(t *testing.T) {
	ctx := context.Background()

	t.Run("Concurrent creates get unique increasing numbers", func(t *testing.T) {
		_, s := migratedStore(t)
		var mu sync.Mutex
		var ids []int64
		var wg sync.WaitGroup
		for i := 1; i <= 20; i++ {
			wg.Add(1)
			go func(seq int64) {
				defer wg.Done()
				e, inserted, err := s.Insert(ctx, operatorEntry("flow-registry", seq, 3))
				if err != nil || !inserted {
					t.Errorf("insert %d: %v %v", seq, inserted, err)
					return
				}
				mu.Lock()
				ids = append(ids, e.AuditID)
				mu.Unlock()
			}(int64(i))
		}
		wg.Wait()
		seen := map[int64]bool{}
		for _, id := range ids {
			if id < 1 || seen[id] {
				t.Fatalf("audit_ids %v are not distinct positive numbers", ids)
			}
			seen[id] = true
		}
		next, _, err := s.Insert(ctx, operatorEntry("flow-registry", 21, 3))
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		if next.AuditID <= ids[len(ids)-1] {
			t.Fatalf("later commit got audit_id %d, not above %d", next.AuditID, ids[len(ids)-1])
		}
	})

	t.Run("Redelivered message stored once under concurrency", func(t *testing.T) {
		_, s := migratedStore(t)
		var wg sync.WaitGroup
		var mu sync.Mutex
		inserted := 0
		got := map[int64]bool{}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e, ins, err := s.Insert(ctx, operatorEntry("flow-registry", 120, 3))
				if err != nil {
					t.Errorf("insert: %v", err)
					return
				}
				mu.Lock()
				if ins {
					inserted++
				}
				got[e.AuditID] = true
				mu.Unlock()
			}()
		}
		wg.Wait()
		if inserted != 1 || len(got) != 1 {
			t.Fatalf("inserted %d times with audit_ids %v, want one entry", inserted, got)
		}
		seen, err := s.Seen(ctx, "flow-registry", 120)
		if err != nil || !seen {
			t.Fatalf("Seen = %v %v", seen, err)
		}
		if seen, _ := s.Seen(ctx, "task-manager", 120); seen {
			t.Fatal("another publisher's equal sequence is reported as seen")
		}
	})

	t.Run("Rolled-back transaction neither publishes nor reuses its sequence", func(t *testing.T) {
		db, s := migratedStore(t)
		first, _, _ := s.Insert(ctx, operatorEntry("flow-registry", 1, 3))
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var taken int64
		if err := tx.QueryRowContext(ctx, `SELECT nextval('audit_schema.audit_id_seq')`).Scan(&taken); err != nil {
			t.Fatalf("allocate from audit_id_seq: %v", err)
		}
		_ = tx.Rollback()
		next, _, err := s.Insert(ctx, operatorEntry("flow-registry", 2, 3))
		if err != nil {
			t.Fatal(err)
		}
		if taken <= first.AuditID || next.AuditID <= taken {
			t.Fatalf("ids first=%d rolled-back=%d next=%d, want strictly increasing with no reuse", first.AuditID, taken, next.AuditID)
		}
	})

	t.Run("a restart continues the sequence", func(t *testing.T) {
		db, s := migratedStore(t)
		before, _, _ := s.Insert(ctx, operatorEntry("flow-registry", 1, 3))
		if err := migrations.Apply(ctx, db, "audit_schema"); err != nil {
			t.Fatal(err)
		}
		again, err := store.New(db, "audit_schema")
		if err != nil {
			t.Fatal(err)
		}
		after, _, err := again.Insert(ctx, operatorEntry("flow-registry", 2, 3))
		if err != nil || after.AuditID <= before.AuditID {
			t.Fatalf("after restart audit_id %d (err %v), want above %d", after.AuditID, err, before.AuditID)
		}
	})

	t.Run("Team-owned parent keeps its team", func(t *testing.T) {
		db, s := migratedStore(t)
		e, _, _ := s.Insert(ctx, operatorEntry("flow-registry", 1, 3))
		var team int64
		if err := db.QueryRowContext(ctx, `SELECT team_id FROM audit_schema.audit_entries WHERE audit_id = $1`, e.AuditID).Scan(&team); err != nil || team != 3 {
			t.Fatalf("stored row not visible through this connection: team %d %v", team, err)
		}
		for _, q := range []string{
			`UPDATE audit_schema.audit_entries SET team_id = 4 WHERE audit_id = $1`,
			`DELETE FROM audit_schema.audit_entries WHERE audit_id = $1`,
		} {
			_, err := db.ExecContext(ctx, q, e.AuditID)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "55000" || !strings.Contains(pg.Message, "audit entries are immutable") {
				t.Fatalf("%s: err %v, want SQLSTATE 55000 'audit entries are immutable'", q, err)
			}
		}
		got, err := s.GetTeam(ctx, 3, e.AuditID)
		if err != nil || *got.TeamID != 3 {
			t.Fatalf("entry after attempts: %+v %v", got, err)
		}
	})

	t.Run("administrator entries and rejected messages", func(t *testing.T) {
		_, s := migratedStore(t)
		subject := "admin-sub-1"
		res := int64(3)
		admin := audit.Entry{Publisher: "team-registry", PublisherSeq: 5, SourceService: "team-registry",
			ActorType: audit.ActorAdministrator, ActorSubject: &subject, Action: "team_updated", ResourceType: "team",
			ResourceID: &res, RequestID: 9001, Outcome: "succeeded", OccurredAt: time.Now().UTC(),
			Changes: []byte(`{"default_image":{"old":"registry.example/flowai/runtime:1.0.0","new":"registry.example/flowai/runtime:1.1.0"}}`)}
		e, _, err := s.Insert(ctx, admin)
		if err != nil {
			t.Fatalf("insert administrator entry: %v", err)
		}
		if _, err := s.GetTeam(ctx, 3, e.AuditID); !errors.Is(err, audit.ErrNotFound) {
			t.Fatalf("team 3 get of administrator entry = %v, want ErrNotFound", err)
		}
		if err := s.RecordRejected(ctx, "flow-registry", 30, "flow-registry.audit.flow_updated.sub", "team_mismatch"); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordRejected(ctx, "flow-registry", 30, "flow-registry.audit.flow_updated.sub", "team_mismatch"); err != nil {
			t.Fatalf("second rejection of the same pair: %v", err)
		}
		if seen, _ := s.Seen(ctx, "flow-registry", 30); !seen {
			t.Fatal("rejected pair not seen")
		}
		if err := s.Ping(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
