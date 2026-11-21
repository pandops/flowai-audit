package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/pandops/flowai-audit/internal/ids"
)

// Delivery is one JetStream message of the ALL_AUDIT durable consumer.
type Delivery interface {
	Subject() string
	Header(key string) string
	Data() []byte
	Ack() error
	Term() error
}

// Result is what the consumer did with a delivery.
type Result string

const (
	ResultStored     Result = "stored"     // committed, acknowledged
	ResultDuplicate  Result = "duplicate"  // pair already known, acknowledged
	ResultRejected   Result = "rejected"   // recorded as rejected, acknowledged
	ResultTerminated Result = "terminated" // malformed, terminated (+TERM)
	ResultRetry      Result = "retry"      // not acknowledged, will be redelivered
)

// TeamAdmin is the team header value of administrator messages.
const TeamAdmin = "admin"

// ReasonTeamMismatch is recorded when the payload names another team than
// the trusted team header.
const ReasonTeamMismatch = "team_mismatch"

var token = regexp.MustCompile(`^[a-z0-9]+([_-][a-z0-9]+)*$`)

// Consumer stores ALL_AUDIT messages.
type Consumer struct {
	store  Store
	logger *slog.Logger
}

// NewConsumer builds the consumer.
func NewConsumer(store Store, logger *slog.Logger) *Consumer {
	return &Consumer{store: store, logger: logger}
}

// errMalformed marks a message that can never be stored.
var errMalformed = errors.New("malformed audit message")

// pairAttrs are the only message values audit logs.
func pairAttrs(subject, publisher string, seq int64) []any {
	attrs := []any{slog.String("subject", subject)}
	if publisher != "" {
		attrs = append(attrs, slog.String("publisher", publisher))
	}
	if seq > 0 {
		attrs = append(attrs, slog.Int64("publisher_seq", seq))
	}
	return attrs
}

// Handle processes one delivery and acknowledges, terminates or leaves it.
func (c *Consumer) Handle(ctx context.Context, d Delivery) Result {
	subject := d.Subject()
	e, payloadTeam, publisher, seq, err := parse(subject, d.Header("team"), d.Data())
	if err != nil {
		c.logger.Warn("audit message terminated", append(pairAttrs(subject, publisher, seq), slog.String("reason", err.Error()))...)
		if terr := d.Term(); terr != nil {
			c.logger.Warn("audit message terminate failed", pairAttrs(subject, publisher, seq)...)
			return ResultRetry
		}
		return ResultTerminated
	}
	attrs := pairAttrs(subject, publisher, seq)
	seen, err := c.store.Seen(ctx, publisher, seq)
	if err != nil {
		c.logger.Warn("audit store unavailable, message left for redelivery", attrs...)
		return ResultRetry
	}
	if seen {
		return c.ack(d, ResultDuplicate, attrs)
	}
	if e.TeamID != nil && payloadTeam != *e.TeamID {
		if err := c.store.RecordRejected(ctx, publisher, seq, subject, ReasonTeamMismatch); err != nil {
			c.logger.Warn("audit store unavailable, message left for redelivery", attrs...)
			return ResultRetry
		}
		c.logger.Warn("audit message rejected", append(attrs, slog.String("reason", ReasonTeamMismatch))...)
		return c.ack(d, ResultRejected, attrs)
	}
	_, inserted, err := c.store.Insert(ctx, e)
	if err != nil {
		c.logger.Warn("audit store unavailable, message left for redelivery", attrs...)
		return ResultRetry
	}
	if !inserted {
		return c.ack(d, ResultDuplicate, attrs)
	}
	return c.ack(d, ResultStored, attrs)
}

func (c *Consumer) ack(d Delivery, r Result, attrs []any) Result {
	if err := d.Ack(); err != nil {
		c.logger.Warn("audit message acknowledgement failed, it will be redelivered", attrs...)
		return ResultRetry
	}
	return r
}

// parse validates one message. It returns the entry to store (TeamID is the
// trusted header team), the payload team_id of an operator message, and the
// publisher pair once it is known.
func parse(subject, teamHeader string, data []byte) (e Entry, payloadTeam int64, publisher string, seq int64, err error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 4 || parts[1] != "audit" || parts[3] != "sub" || !token.MatchString(parts[0]) || !token.MatchString(parts[2]) {
		return e, 0, "", 0, errors.New("subject is not an audit subject")
	}
	svc, action := parts[0], parts[2]
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return e, 0, "", 0, errors.New("payload is not a JSON object")
	}
	if s, ok := str(m, "publisher"); !ok || s != svc {
		return e, 0, "", 0, errors.New("publisher does not match the subject")
	}
	publisher = svc
	seq, err = id(m, "publisher_seq")
	if err != nil {
		return e, 0, publisher, 0, errors.New("publisher_seq is not a positive integer")
	}
	fail := func(msg string) (Entry, int64, string, int64, error) {
		return Entry{}, 0, publisher, seq, errors.New(msg)
	}
	if raw, ok := m["action"]; ok {
		var a string
		if json.Unmarshal(raw, &a) != nil || a != action {
			return fail("action does not match the subject")
		}
	}
	e = Entry{Publisher: publisher, PublisherSeq: seq, SourceService: svc, Action: action}
	actorType, _ := str(m, "actor_type")
	switch actorType {
	case ActorOperator:
		if teamHeader == TeamAdmin {
			return fail("operator message with team admin")
		}
		team, err := ids.ParseDecimal(teamHeader)
		if err != nil {
			return fail("team header is not a team identifier")
		}
		actor, err := id(m, "actor_id")
		if err != nil {
			return fail("actor_id is not a positive integer")
		}
		payloadTeam, err = id(m, "team_id")
		if err != nil {
			return fail("team_id is not a positive integer")
		}
		e.TeamID, e.ActorID = &team, &actor
	case ActorAdministrator:
		if teamHeader != TeamAdmin {
			return fail("administrator message without team admin")
		}
		subj, ok := str(m, "actor_subject")
		if !ok || subj == "" {
			return fail("actor_subject is missing")
		}
		e.ActorSubject = &subj
	default:
		return fail("actor_type is unknown")
	}
	e.ActorType = actorType
	if e.ResourceType, _ = str(m, "resource_type"); e.ResourceType == "" {
		return fail("resource_type is missing")
	}
	raw, ok := m["resource_id"]
	if !ok {
		return fail("resource_id is missing")
	}
	if string(bytes.TrimSpace(raw)) != "null" {
		r, err := ids.ParseJSON(raw)
		if err != nil {
			return fail("resource_id is not a positive integer or null")
		}
		e.ResourceID = &r
	}
	if e.RequestID, err = id(m, "request_id"); err != nil {
		return fail("request_id is not a positive integer")
	}
	if e.Outcome, _ = str(m, "outcome"); e.Outcome == "" {
		return fail("outcome is missing")
	}
	at, _ := str(m, "occurred_at")
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return fail("occurred_at is not an RFC 3339 time")
	}
	e.OccurredAt = t.UTC().Truncate(time.Microsecond)
	if raw, ok := m["changes"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			return fail("changes is not an object")
		}
		compact := &bytes.Buffer{}
		if json.Compact(compact, raw) != nil {
			return fail("changes is not an object")
		}
		e.Changes = compact.Bytes()
	}
	return e, payloadTeam, publisher, seq, nil
}

func str(m map[string]json.RawMessage, k string) (string, bool) {
	raw, ok := m[k]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func id(m map[string]json.RawMessage, k string) (int64, error) {
	raw, ok := m[k]
	if !ok {
		return 0, ids.ErrInvalid
	}
	return ids.ParseJSON(raw)
}
