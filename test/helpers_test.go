package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/cursor"
	"github.com/pandops/flowai-audit/internal/mocks"
)

// serviceDir is the absolute path of the audit checkout.
func serviceDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	return filepath.Dir(filepath.Dir(file))
}

// contractFixtureDir locates the staged publisher schemas.
func contractFixtureDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("FLOWAI_CONTRACT_FIXTURE_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("set FLOWAI_CONTRACT_FIXTURE_DIR to an absolute path")
	}
	return filepath.Clean(dir)
}

// logBuffer is a concurrency-safe log sink.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newLogger() (*slog.Logger, *logBuffer) {
	b := &logBuffer{}
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})), b
}

// fields is an audit message payload.
type fields map[string]any

// operatorMsg is a valid operator audit message of team for publisher.
func operatorMsg(publisher string, seq int64, team int64, action string) fields {
	return fields{
		"publisher":     publisher,
		"publisher_seq": seq,
		"team_id":       team,
		"actor_type":    "operator",
		"actor_id":      12,
		"action":        action,
		"resource_type": "flow",
		"resource_id":   4,
		"request_id":    7001,
		"outcome":       "succeeded",
		"occurred_at":   "2026-11-07T10:00:00Z",
	}
}

// adminMsg is a valid administrator audit message (header team: admin).
func adminMsg(publisher string, seq int64, action string, affectedTeam int64) fields {
	f := fields{
		"publisher":     publisher,
		"publisher_seq": seq,
		"actor_type":    "administrator",
		"actor_subject": "admin-sub-1",
		"action":        action,
		"resource_type": "team",
		"resource_id":   affectedTeam,
		"request_id":    9001,
		"outcome":       "succeeded",
		"occurred_at":   "2026-11-07T10:00:00Z",
	}
	if affectedTeam > 0 {
		f["team_id"] = affectedTeam
	}
	return f
}

// delivery builds a fake ALL_AUDIT delivery on <publisher>.audit.<action>.sub.
func delivery(t *testing.T, team string, f fields) *mocks.Delivery {
	t.Helper()
	pub, _ := f["publisher"].(string)
	action, _ := f["action"].(string)
	return deliveryOn(t, pub+".audit."+action+".sub", team, f)
}

func deliveryOn(t *testing.T, subject, team string, f fields) *mocks.Delivery {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	h := map[string]string{}
	if team != "" {
		h["team"] = team
	}
	if pub, ok := f["publisher"].(string); ok {
		if seq, ok := f["publisher_seq"].(int64); ok {
			h["Nats-Msg-Id"] = pub + "-" + strconv.FormatInt(seq, 10)
		}
	}
	return mocks.NewDelivery(subject, h, data)
}

func team(n int64) string { return strconv.FormatInt(n, 10) }

// testKeys is the cursor keyring of every unit test (key_id 1, active).
var testSecret = bytes.Repeat([]byte{0x42}, 32)

func testKeyring(t *testing.T) *cursor.Keyring {
	t.Helper()
	k, err := cursor.NewKeyring(1, []cursor.Key{{ID: 1, Secret: testSecret}, {ID: 2, Secret: bytes.Repeat([]byte{0x24}, 32)}})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return k
}

// harness is the consumer and reader over one in-memory store.
type harness struct {
	store    *mocks.MemStore
	consumer *audit.Consumer
	reader   *audit.Reader
	logs     *logBuffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	logger, logs := newLogger()
	store := mocks.NewMemStore()
	return &harness{
		store:    store,
		consumer: audit.NewConsumer(store, logger),
		reader:   audit.NewReader(store, testKeyring(t), logger),
		logs:     logs,
	}
}

// handle runs one delivery and returns its result.
func (h *harness) handle(t *testing.T, d *mocks.Delivery) audit.Result {
	t.Helper()
	return h.consumer.Handle(context.Background(), d)
}

// headers are ui request context headers.
type headers map[string]string

func uiHeaders(teamID int64) headers {
	return headers{"team": team(teamID), "operator_id": "12", "request_id": "7001", "team_name": "team" + team(teamID)}
}

// call sends one ui request with params and returns the reply.
func (h *harness) call(t *testing.T, op string, hdr headers, params map[string]any) audit.Reply {
	t.Helper()
	body, err := json.Marshal(map[string]any{"params": params})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return h.callRaw(t, op, hdr, body)
}

func (h *harness) callRaw(t *testing.T, op string, hdr headers, body []byte) audit.Reply {
	t.Helper()
	return h.reader.Serve(context.Background(), audit.Request{
		Operation: op,
		Header:    func(k string) string { return hdr[k] },
		Body:      body,
	})
}

// page is a decoded AuditPage.
type page struct {
	Items      []map[string]any `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

func decodePage(t *testing.T, r audit.Reply) page {
	t.Helper()
	if r.Status != 200 {
		t.Fatalf("list status = %d body=%s, want 200", r.Status, r.Body)
	}
	var p page
	if err := json.Unmarshal(r.Body, &p); err != nil {
		t.Fatalf("decode page: %v body=%s", err, r.Body)
	}
	return p
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID int64  `json:"request_id"`
}

// expectError checks status and code of an error reply.
func expectError(t *testing.T, r audit.Reply, status int, code string) errorBody {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d body=%s, want %d %s", r.Status, r.Body, status, code)
	}
	var e errorBody
	if err := json.Unmarshal(r.Body, &e); err != nil {
		t.Fatalf("decode error body: %v body=%s", err, r.Body)
	}
	if e.Code != code {
		t.Fatalf("code = %q, want %q", e.Code, code)
	}
	return e
}

// seed stores n operator entries of team via the consumer; the i-th entry
// (1-based) occurs i minutes after base and carries action.
func (h *harness) seed(t *testing.T, publisher string, firstSeq int64, teamID int64, n int, action string) {
	t.Helper()
	base := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		f := operatorMsg(publisher, firstSeq+int64(i), teamID, action)
		f["occurred_at"] = base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		if got := h.handle(t, delivery(t, team(teamID), f)); got != audit.ResultStored {
			t.Fatalf("seed %s/%d: result %s, want stored", publisher, firstSeq+int64(i), got)
		}
	}
}

// schemas compiles the owned schemas.
type schemaSet struct {
	compiled map[string]*jsonschema.Schema
}

func loadSchemas(t *testing.T) schemaSet {
	t.Helper()
	dir := filepath.Join(serviceDir(t), "schemas")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read schemas: %v", err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	ids := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") || e.Name() == "consumers.json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		id, _ := doc.(map[string]any)["$id"].(string)
		if id == "" {
			t.Fatalf("%s has no $id", e.Name())
		}
		if err := c.AddResource(id, doc); err != nil {
			t.Fatalf("add %s: %v", e.Name(), err)
		}
		ids[e.Name()] = id
	}
	set := schemaSet{compiled: map[string]*jsonschema.Schema{}}
	for name, id := range ids {
		s, err := c.Compile(id)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		set.compiled[name] = s
	}
	return set
}

func (s schemaSet) validate(name string, data []byte) error {
	sch, ok := s.compiled[name]
	if !ok {
		return fmt.Errorf("no schema %s", name)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}

func ptr[T any](v T) *T { return &v }
