// Package mocks holds in-process fakes of audit's boundaries for unit tests:
// an in-memory audit.Store and a fake JetStream durable consumer. Production
// wiring never uses them.
package mocks

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pandops/flowai-audit/internal/audit"
)

type pair struct {
	publisher string
	seq       int64
}

// Rejected is one message recorded as rejected.
type Rejected struct {
	Publisher string
	Seq       int64
	Subject   string
	Reason    string
}

// MemStore is an in-memory audit.Store with a global audit_id sequence.
type MemStore struct {
	mu       sync.Mutex
	next     int64
	entries  []audit.Entry
	byPair   map[pair]int
	rejected map[pair]Rejected

	// Reads counts ListTeam and GetTeam calls.
	Reads int
	// FailInsert makes the next n Insert calls fail before storing.
	FailInsert int
	// Down makes every call fail, as an unreachable database.
	Down bool
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{byPair: map[pair]int{}, rejected: map[pair]Rejected{}}
}

var errDown = errors.New("database unavailable")

func (m *MemStore) Seen(_ context.Context, publisher string, seq int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Down {
		return false, errDown
	}
	k := pair{publisher, seq}
	_, stored := m.byPair[k]
	_, rejected := m.rejected[k]
	return stored || rejected, nil
}

func (m *MemStore) Insert(_ context.Context, e audit.Entry) (audit.Entry, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Down {
		return audit.Entry{}, false, errDown
	}
	if m.FailInsert > 0 {
		m.FailInsert--
		return audit.Entry{}, false, errors.New("insert failed")
	}
	k := pair{e.Publisher, e.PublisherSeq}
	if i, ok := m.byPair[k]; ok {
		return m.entries[i], false, nil
	}
	m.next++
	e.AuditID = m.next
	m.byPair[k] = len(m.entries)
	m.entries = append(m.entries, e)
	return e, true, nil
}

func (m *MemStore) RecordRejected(_ context.Context, publisher string, seq int64, subject, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Down {
		return errDown
	}
	m.rejected[pair{publisher, seq}] = Rejected{publisher, seq, subject, reason}
	return nil
}

func matches(e audit.Entry, search string) bool {
	if search == "" {
		return true
	}
	s := strings.ToLower(search)
	if strings.Contains(strings.ToLower(e.Action), s) || (e.ResourceID != nil && strings.Contains(strconv.FormatInt(*e.ResourceID, 10), s)) {
		return true
	}
	return e.ActorID != nil && strings.Contains(strconv.FormatInt(*e.ActorID, 10), s)
}

func before(e audit.Entry, p audit.Position) bool {
	if e.OccurredAt.Equal(p.OccurredAt) {
		return e.AuditID < p.AuditID
	}
	return e.OccurredAt.Before(p.OccurredAt)
}

func (m *MemStore) ListTeam(_ context.Context, q audit.ListQuery) ([]audit.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Reads++
	if m.Down {
		return nil, errDown
	}
	var out []audit.Entry
	for _, e := range m.entries {
		if e.TeamID == nil || *e.TeamID != q.TeamID || !matches(e, q.Search) {
			continue
		}
		if q.After != nil && !before(e, *q.After) {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].AuditID > out[j].AuditID
		}
		return out[i].OccurredAt.After(out[j].OccurredAt)
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (m *MemStore) GetTeam(_ context.Context, teamID, auditID int64) (audit.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Reads++
	if m.Down {
		return audit.Entry{}, errDown
	}
	for _, e := range m.entries {
		if e.AuditID == auditID && e.TeamID != nil && *e.TeamID == teamID {
			return e, nil
		}
	}
	return audit.Entry{}, audit.ErrNotFound
}

func (m *MemStore) Ping(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Down {
		return errDown
	}
	return nil
}

// Entries returns a copy of every stored entry in audit_id order.
func (m *MemStore) Entries() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]audit.Entry(nil), m.entries...)
}

// RejectedMessages returns every message recorded as rejected.
func (m *MemStore) RejectedMessages() []Rejected {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Rejected, 0, len(m.rejected))
	for _, r := range m.rejected {
		out = append(out, r)
	}
	return out
}

// Delivery is a fake JetStream message.
type Delivery struct {
	mu       sync.Mutex
	subject  string
	headers  map[string]string
	data     []byte
	Acked    int
	Termed   int
	AckError error
}

// NewDelivery builds a fake delivery.
func NewDelivery(subject string, headers map[string]string, data []byte) *Delivery {
	return &Delivery{subject: subject, headers: headers, data: data}
}

func (d *Delivery) Subject() string        { return d.subject }
func (d *Delivery) Header(k string) string { return d.headers[k] }
func (d *Delivery) Data() []byte           { return d.data }

func (d *Delivery) Ack() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.AckError != nil {
		return d.AckError
	}
	d.Acked++
	return nil
}

func (d *Delivery) Term() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Termed++
	return nil
}

// Settled reports whether the delivery was acknowledged or terminated.
func (d *Delivery) Settled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Acked > 0 || d.Termed > 0
}

// Stream is a fake durable consumer: messages stay pending until acknowledged
// or terminated and are delivered again on the next fetch otherwise.
type Stream struct {
	mu      sync.Mutex
	pending []*Delivery
	// Errors are returned by the next fetches, one per fetch, before any
	// message, as a broker outage.
	Errors []error
	// Fetches counts Fetch calls.
	Fetches int
}

// Publish appends a message to the backlog.
func (s *Stream) Publish(d *Delivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, d)
}

// Backlog returns the number of unsettled messages.
func (s *Stream) Backlog() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	return len(s.pending)
}

func (s *Stream) prune() {
	kept := s.pending[:0]
	for _, d := range s.pending {
		if !d.Settled() {
			kept = append(kept, d)
		}
	}
	s.pending = kept
}

// Fetch returns up to max unsettled messages in stream order.
func (s *Stream) Fetch(ctx context.Context, max int) ([]audit.Delivery, error) {
	s.mu.Lock()
	s.Fetches++
	if len(s.Errors) > 0 {
		err := s.Errors[0]
		s.Errors = s.Errors[1:]
		s.mu.Unlock()
		return nil, err
	}
	s.prune()
	n := len(s.pending)
	if n > max {
		n = max
	}
	out := make([]audit.Delivery, 0, n)
	for _, d := range s.pending[:n] {
		out = append(out, d)
	}
	s.mu.Unlock()
	if n == 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return out, nil
}
