package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/pandops/flowai-audit/internal/cursor"
	"github.com/pandops/flowai-audit/internal/ids"
)

// Operations served on audit.ui.<operation>.sub.
const (
	OperationList = "list"
	OperationGet  = "get"
)

// Page sizes accepted by list.
const DefaultLimit = 10

var allowedLimits = map[int64]bool{10: true, 25: true, 50: true, 100: true}

// Cursor binding values of the list read.
const (
	cursorOperation = "audit.ui.list"
	cursorOrdering  = "occurred_at_desc,audit_id_desc"
	cursorDirection = "forward"
)

// Request is one core NATS request from API Gateway.
type Request struct {
	Operation string
	Header    func(key string) string
	Body      []byte
}

// Reply is the status header and body of a reply.
type Reply struct {
	Status int
	Body   []byte
}

// Reader serves the team-filtered reads.
type Reader struct {
	store  Store
	keys   *cursor.Keyring
	logger *slog.Logger
}

// NewReader builds the reader.
func NewReader(store Store, keys *cursor.Keyring, logger *slog.Logger) *Reader {
	return &Reader{store: store, keys: keys, logger: logger}
}

// item is the reply shape of one entry (baseline Audit with integer ids).
type item struct {
	AuditID      int64  `json:"audit_id"`
	ActorID      int64  `json:"actor_id"`
	ActorType    string `json:"actor_type"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   *int64 `json:"resource_id"`
	RequestID    int64  `json:"request_id"`
	Outcome      string `json:"outcome"`
	OccurredAt   string `json:"occurred_at"`
}

type page struct {
	Items      []item  `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// errorReply omits request_id when the request carried no valid one (D12).
type errorReply struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID int64  `json:"request_id,omitempty"`
}

type replyError struct {
	status  int
	code    string
	message string
}

var (
	errInvalidRequest    = &replyError{400, "invalid_request", "request is invalid"}
	errInvalidPagination = &replyError{400, "invalid_pagination", "pagination is invalid"}
	errNotFound          = &replyError{404, "resource_not_found", "resource not found"}
	errUnavailable       = &replyError{503, "service_unavailable", "service is unavailable"}
)

func toItem(e Entry) item {
	var actor int64
	if e.ActorID != nil {
		actor = *e.ActorID
	}
	return item{AuditID: e.AuditID, ActorID: actor, ActorType: e.ActorType, Action: e.Action,
		ResourceType: e.ResourceType, ResourceID: e.ResourceID, RequestID: e.RequestID,
		Outcome: e.Outcome, OccurredAt: e.OccurredAt.UTC().Format(time.RFC3339Nano)}
}

// context is the trusted ui request context.
type uiContext struct {
	team, operator, request int64
}

// Serve answers one request.
func (r *Reader) Serve(ctx context.Context, req Request) Reply {
	requestID, _ := ids.ParseDecimal(req.Header("request_id"))
	body, rerr := r.serve(ctx, req)
	if rerr != nil {
		raw, _ := json.Marshal(errorReply{Code: rerr.code, Message: rerr.message, RequestID: requestID})
		return Reply{Status: rerr.status, Body: raw}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		raw, _ = json.Marshal(errorReply{Code: errUnavailable.code, Message: errUnavailable.message, RequestID: requestID})
		return Reply{Status: errUnavailable.status, Body: raw}
	}
	return Reply{Status: 200, Body: raw}
}

func (r *Reader) serve(ctx context.Context, req Request) (any, *replyError) {
	if req.Operation != OperationList && req.Operation != OperationGet {
		return nil, errInvalidRequest
	}
	uc, ok := trustedContext(req.Header)
	if !ok {
		return nil, errInvalidRequest
	}
	params, ok := decodeParams(req.Body)
	if !ok {
		return nil, errInvalidRequest
	}
	allowed := map[string]bool{"team_id": true, "search": true, "cursor": true, "limit": true}
	if req.Operation == OperationGet {
		allowed = map[string]bool{"team_id": true, "audit_id": true}
	}
	for k := range params {
		if !allowed[k] {
			return nil, errInvalidRequest
		}
	}
	team, err := ids.ParseJSON(params["team_id"])
	if err != nil || team != uc.team {
		return nil, errInvalidRequest
	}
	if req.Operation == OperationGet {
		auditID, err := ids.ParseJSON(params["audit_id"])
		if err != nil {
			return nil, errInvalidRequest
		}
		e, err := r.store.GetTeam(ctx, uc.team, auditID)
		if errors.Is(err, ErrNotFound) {
			return nil, errNotFound
		}
		if err != nil {
			r.logger.Warn("audit read failed", slog.String("operation", req.Operation))
			return nil, errUnavailable
		}
		return toItem(e), nil
	}
	return r.list(ctx, uc, params)
}

func (r *Reader) list(ctx context.Context, uc uiContext, params map[string]json.RawMessage) (any, *replyError) {
	var search, token string
	if raw, ok := params["search"]; ok {
		if !jsonString(raw, &search) || len([]rune(search)) > 200 {
			return nil, errInvalidRequest
		}
	}
	if raw, ok := params["cursor"]; ok {
		if !jsonString(raw, &token) {
			return nil, errInvalidRequest
		}
	}
	limit := int64(DefaultLimit)
	if raw, ok := params["limit"]; ok {
		v, err := ids.ParseJSON(raw)
		if err != nil || !allowedLimits[v] {
			return nil, errInvalidPagination
		}
		limit = v
	}
	binding := cursor.Binding{Operation: cursorOperation, TeamID: uc.team, OperatorID: uc.operator,
		Search: search, Ordering: cursorOrdering, Direction: cursorDirection}
	q := ListQuery{TeamID: uc.team, Search: search, Limit: int(limit) + 1}
	if _, ok := params["cursor"]; ok {
		pos, err := r.keys.Decode(token, binding)
		if err != nil {
			return nil, errInvalidPagination
		}
		q.After = &Position{OccurredAt: time.UnixMicro(pos.OccurredAtMicros).UTC(), AuditID: pos.AuditID}
	}
	rows, err := r.store.ListTeam(ctx, q)
	if err != nil {
		r.logger.Warn("audit read failed", slog.String("operation", OperationList))
		return nil, errUnavailable
	}
	out := page{Items: make([]item, 0, len(rows))}
	if int64(len(rows)) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next, err := r.keys.Encode(binding, cursor.Position{OccurredAtMicros: last.OccurredAt.UnixMicro(), AuditID: last.AuditID})
		if err != nil {
			return nil, errUnavailable
		}
		out.NextCursor = &next
	}
	for _, e := range rows {
		out.Items = append(out.Items, toItem(e))
	}
	return out, nil
}

func trustedContext(h func(string) string) (uiContext, bool) {
	team, err := ids.ParseDecimal(h("team"))
	if err != nil {
		return uiContext{}, false
	}
	op, err := ids.ParseDecimal(h("operator_id"))
	if err != nil {
		return uiContext{}, false
	}
	rid, err := ids.ParseDecimal(h("request_id"))
	if err != nil {
		return uiContext{}, false
	}
	return uiContext{team: team, operator: op, request: rid}, true
}

func decodeParams(body []byte) (map[string]json.RawMessage, bool) {
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) != nil || env == nil {
		return nil, false
	}
	for k := range env {
		if k != "params" {
			return nil, false
		}
	}
	var params map[string]json.RawMessage
	raw, ok := env["params"]
	if !ok || json.Unmarshal(raw, &params) != nil || params == nil {
		return nil, false
	}
	return params, true
}

func jsonString(raw json.RawMessage, out *string) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, out) == nil
}
