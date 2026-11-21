// Package audit holds audit's domain logic: the ALL_AUDIT consumer and the
// team-filtered reads served to API Gateway.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Actor types.
const (
	ActorOperator      = "operator"
	ActorAdministrator = "administrator"
)

// ErrNotFound is returned by Store.GetTeam for an unknown, foreign or
// administrator entry.
var ErrNotFound = errors.New("audit entry not found")

// Entry is one stored, immutable audit entry.
type Entry struct {
	AuditID       int64
	TeamID        *int64 // nil for an administrator entry
	Publisher     string
	PublisherSeq  int64
	SourceService string
	ActorType     string
	ActorID       *int64  // operator entries
	ActorSubject  *string // administrator entries
	Action        string
	ResourceType  string
	ResourceID    *int64 // nil when the action had no target
	RequestID     int64
	Outcome       string
	OccurredAt    time.Time
	Changes       json.RawMessage // optional JSON object of display values
}

// Position orders entries by (occurred_at DESC, audit_id DESC).
type Position struct {
	OccurredAt time.Time
	AuditID    int64
}

// ListQuery is one team-scoped list read.
type ListQuery struct {
	TeamID int64
	Search string
	After  *Position
	Limit  int // the store returns at most Limit rows
}

// Store is audit's persistence boundary.
type Store interface {
	// Seen reports whether (publisher, publisher_seq) is stored or rejected.
	Seen(ctx context.Context, publisher string, seq int64) (bool, error)
	// Insert stores e and assigns its audit_id from the global commit
	// sequence. inserted is false when the pair is already stored; the
	// returned entry is then the stored one.
	Insert(ctx context.Context, e Entry) (stored Entry, inserted bool, err error)
	// RecordRejected keeps a rejected message's pair and reason only.
	RecordRejected(ctx context.Context, publisher string, seq int64, subject, reason string) error
	// ListTeam returns up to q.Limit team entries after q.After.
	ListTeam(ctx context.Context, q ListQuery) ([]Entry, error)
	// GetTeam returns one entry of the team, or ErrNotFound.
	GetTeam(ctx context.Context, teamID, auditID int64) (Entry, error)
	// Ping reports database reachability.
	Ping(ctx context.Context) error
}
