// Package store is audit's PostgreSQL implementation of audit.Store.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/migrations"
)

// Store keeps audit entries in one schema.
type Store struct {
	db     *sql.DB
	schema string
	q      queries
}

type queries struct {
	lock, exists, seen, insert, reject, list, listAfter, get string
}

const columns = `audit_id, team_id, publisher, publisher_seq, source_service, actor_type, actor_id,
	actor_subject, action, resource_type, resource_id, request_id, outcome, occurred_at, changes`

// New returns a store over schema.
func New(db *sql.DB, schema string) (*Store, error) {
	if db == nil {
		return nil, errors.New("store: nil database")
	}
	if !migrations.ValidSchema(schema) {
		return nil, fmt.Errorf("store: invalid schema %q", schema)
	}
	t := schema + ".audit_entries"
	match := `($2 = '' OR action ILIKE $3 ESCAPE '\' OR actor_id::text ILIKE $3 ESCAPE '\' OR resource_id::text ILIKE $3 ESCAPE '\')`
	return &Store{db: db, schema: schema, q: queries{
		// One advisory lock per schema serializes stores, so audit_id
		// order is commit order.
		lock:   `SELECT pg_advisory_xact_lock(hashtext('audit-entries:' || $1))`,
		exists: `SELECT ` + columns + ` FROM ` + t + ` WHERE publisher = $1 AND publisher_seq = $2`,
		seen: `SELECT EXISTS (SELECT 1 FROM ` + t + ` WHERE publisher = $1 AND publisher_seq = $2)
			OR EXISTS (SELECT 1 FROM ` + schema + `.rejected_messages WHERE publisher = $1 AND publisher_seq = $2)`,
		insert: `INSERT INTO ` + t + ` (` + columns + `)
			VALUES (nextval('` + schema + `.audit_id_seq'), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			RETURNING audit_id`,
		reject: `INSERT INTO ` + schema + `.rejected_messages (publisher, publisher_seq, subject, reason)
			VALUES ($1, $2, $3, $4) ON CONFLICT (publisher, publisher_seq) DO NOTHING`,
		list: `SELECT ` + columns + ` FROM ` + t + ` WHERE team_id = $1 AND ` + match + `
			ORDER BY occurred_at DESC, audit_id DESC LIMIT $4`,
		listAfter: `SELECT ` + columns + ` FROM ` + t + ` WHERE team_id = $1 AND ` + match + `
			AND (occurred_at, audit_id) < ($5, $6)
			ORDER BY occurred_at DESC, audit_id DESC LIMIT $4`,
		get: `SELECT ` + columns + ` FROM ` + t + ` WHERE team_id = $1 AND audit_id = $2`,
	}}, nil
}

type scanner interface{ Scan(dest ...any) error }

func scan(r scanner) (audit.Entry, error) {
	var (
		e                     audit.Entry
		team, actor, resource sql.NullInt64
		subject               sql.NullString
		changes               []byte
	)
	if err := r.Scan(&e.AuditID, &team, &e.Publisher, &e.PublisherSeq, &e.SourceService, &e.ActorType, &actor,
		&subject, &e.Action, &e.ResourceType, &resource, &e.RequestID, &e.Outcome, &e.OccurredAt, &changes); err != nil {
		return audit.Entry{}, err
	}
	if team.Valid {
		e.TeamID = &team.Int64
	}
	if actor.Valid {
		e.ActorID = &actor.Int64
	}
	if resource.Valid {
		e.ResourceID = &resource.Int64
	}
	if subject.Valid {
		e.ActorSubject = &subject.String
	}
	if len(changes) > 0 {
		e.Changes = changes
	}
	e.OccurredAt = e.OccurredAt.UTC()
	return e, nil
}

func (s *Store) Seen(ctx context.Context, publisher string, seq int64) (bool, error) {
	var seen bool
	err := s.db.QueryRowContext(ctx, s.q.seen, publisher, seq).Scan(&seen)
	return seen, err
}

func (s *Store) Insert(ctx context.Context, e audit.Entry) (audit.Entry, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return audit.Entry{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.q.lock, s.schema); err != nil {
		return audit.Entry{}, false, err
	}
	stored, err := scan(tx.QueryRowContext(ctx, s.q.exists, e.Publisher, e.PublisherSeq))
	if err == nil {
		return stored, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return audit.Entry{}, false, err
	}
	var changes any
	if len(e.Changes) > 0 {
		changes = string(e.Changes)
	}
	if err := tx.QueryRowContext(ctx, s.q.insert, e.TeamID, e.Publisher, e.PublisherSeq, e.SourceService, e.ActorType,
		e.ActorID, e.ActorSubject, e.Action, e.ResourceType, e.ResourceID, e.RequestID, e.Outcome,
		e.OccurredAt.UTC().Truncate(time.Microsecond), changes).Scan(&e.AuditID); err != nil {
		return audit.Entry{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return audit.Entry{}, false, err
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	return e, true, nil
}

func (s *Store) RecordRejected(ctx context.Context, publisher string, seq int64, subject, reason string) error {
	_, err := s.db.ExecContext(ctx, s.q.reject, publisher, seq, subject, reason)
	return err
}

// likePattern escapes LIKE wildcards so search is a plain substring.
func likePattern(search string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search) + "%"
}

func (s *Store) ListTeam(ctx context.Context, q audit.ListQuery) ([]audit.Entry, error) {
	args := []any{q.TeamID, q.Search, likePattern(q.Search), q.Limit}
	query := s.q.list
	if q.After != nil {
		query = s.q.listAfter
		args = append(args, q.After.OccurredAt.UTC(), q.After.AuditID)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetTeam(ctx context.Context, teamID, auditID int64) (audit.Entry, error) {
	e, err := scan(s.db.QueryRowContext(ctx, s.q.get, teamID, auditID))
	if errors.Is(err, sql.ErrNoRows) {
		return audit.Entry{}, audit.ErrNotFound
	}
	return e, err
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
