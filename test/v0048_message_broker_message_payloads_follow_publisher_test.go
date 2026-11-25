package test

// Requirement: message-broker message payloads follow publisher-owned JSON
// Schemas. audit publishes no stream message (coordinator decision); it
// publishes only replies, validated against schemas/. As a
// consumer it reads every publisher's audit message schema.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048MessageBrokerPayloadsFollowSchemas(t *testing.T) {
	t.Run("Publisher message violates its own schema", func(t *testing.T) {
		s := loadSchemas(t)
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 3, 1, "flow_updated")
		good := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 1})
		if err := s.validate("ui.get.reply.schema.json", good.Body); err != nil {
			t.Fatalf("reply violates its schema: %v", err)
		}
		var item map[string]any
		_ = json.Unmarshal(good.Body, &item)
		for name, mutate := range map[string]func(m map[string]any){
			"text audit_id":    func(m map[string]any) { m["audit_id"] = "1" },
			"missing actor_id": func(m map[string]any) { delete(m, "actor_id") },
			"extra team_id":    func(m map[string]any) { m["team_id"] = 3 },
		} {
			m := map[string]any{}
			for k, v := range item {
				m[k] = v
			}
			mutate(m)
			raw, _ := json.Marshal(m)
			if err := s.validate("ui.get.reply.schema.json", raw); err == nil {
				t.Errorf("%s: schema accepted an invalid reply", name)
			}
		}
		for _, name := range []string{"ui.list.request.schema.json", "ui.get.request.schema.json", "ui.list.reply.schema.json", "error.reply.schema.json"} {
			if _, ok := s.compiled[name]; !ok {
				t.Errorf("schema %s missing", name)
			}
		}
	})

	t.Run("Consumer contract test reads the publisher schema", func(t *testing.T) {
		declared := declaredForAudit(t)
		docs := map[string]map[string]any{}
		for _, rel := range declared {
			raw, err := os.ReadFile(filepath.Join(contractFixtureDir(t), rel))
			if err != nil {
				t.Errorf("declared schema %s cannot be read: %v", rel, err)
				continue
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Errorf("declared schema %s is not a JSON object: %v", rel, err)
				continue
			}
			docs[rel] = doc
		}
		// Audit message schemas are recognized by content, never by path.
		var messages []string
		for _, rel := range declared {
			if _, ok := docs[rel]; ok && isAuditMessageSchema(t, filepath.Join(contractFixtureDir(t), rel)) {
				messages = append(messages, rel)
			}
		}
		if len(messages) == 0 {
			t.Fatal("gitea-declarations.json declares no publisher audit message schema for audit")
		}
		referenced := map[string]bool{}
		for _, rel := range messages {
			collectRefs(t, rel, referenced)
		}
		for _, rel := range declared {
			if _, ok := docs[rel]; ok && !isAuditMessageSchema(t, filepath.Join(contractFixtureDir(t), rel)) && !referenced[rel] {
				t.Errorf("declared schema %s is neither an audit message schema nor referenced by one", rel)
			}
		}
		exercised := 0
		for _, rel := range messages {
			passed := t.Run(rel, func(t *testing.T) {
				sch, doc := compilePublisherSchema(t, filepath.Join(contractFixtureDir(t), rel))
				candidates := exampleMessages(doc)
				candidates = append(candidates, synthesizeMessages(t, filepath.Join(contractFixtureDir(t), rel), doc)...)
				accepted := 0
				for _, msg := range candidates {
					raw, _ := json.Marshal(msg)
					inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
					if err := sch.Validate(inst); err != nil {
						continue
					}
					accepted++
					h := newHarness(t)
					pub, _ := msg["publisher"].(string)
					action, _ := msg["action"].(string)
					hdr := "admin"
					if tid, ok := msg["team_id"].(float64); ok && msg["actor_type"] == "operator" {
						hdr = team(int64(tid))
					}
					d := deliveryOn(t, pub+".audit."+action+".sub", hdr, msg)
					if got := h.handle(t, d); got != audit.ResultStored {
						t.Fatalf("valid %s message %s: result %s, want stored; logs %s", pub, raw, got, h.logs.String())
					}
				}
				if accepted == 0 {
					t.Fatalf("no example or synthesized message validates against %s", rel)
				}
			})
			if passed {
				exercised++
			}
		}
		if exercised != len(messages) {
			t.Fatalf("audit stored messages of %d of %d declared audit message schemas", exercised, len(messages))
		}
	})

	t.Run("Schema change selects its consumers", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(serviceDir(t), "qualification/gitea-declarations.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Schemas map[string][]string `json:"schemas"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("gitea-declarations.json: %v", err)
		}
		for _, f := range publisherAuditSchemas(t) {
			rel, _ := filepath.Rel(contractFixtureDir(t), f)
			found := false
			if list := doc.Schemas[filepath.ToSlash(rel)]; len(list) > 1 {
				for _, c := range list[1:] {
					found = found || c == "audit"
				}
			}
			if !found {
				t.Errorf("gitea-declarations.json does not declare audit as a consumer of %s", rel)
			}
		}
	})
}

// declaredForAudit lists the schema files gitea-declarations.json declares
// with audit as a consumer (not audit's own files).
func declaredForAudit(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(serviceDir(t), "qualification/gitea-declarations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schemas map[string][]string `json:"schemas"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("gitea-declarations.json: %v", err)
	}
	var out []string
	for path, services := range doc.Schemas {
		if len(services) < 2 || services[0] == "audit" {
			continue
		}
		for _, c := range services[1:] {
			if c == "audit" {
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
}

var (
	auditMessageTitle   = regexp.MustCompile(`^[a-z0-9]+([_-][a-z0-9]+)*\.audit\.[^.\s]+\.pub$`)
	auditMessageSubject = regexp.MustCompile(`\b[a-z0-9]+([_-][a-z0-9]+)*\.audit\.[a-z0-9]+([_-][a-z0-9]+)*\.pub\b`)
)

// isAuditMessageSchema recognizes a publisher's audit message schema by its
// content, never by its path: a <publisher>.audit.<action>.pub title, a title
// or description naming such a subject or ALL_AUDIT, or an actor_type
// property after $ref, allOf, anyOf and oneOf are resolved.
func isAuditMessageSchema(t *testing.T, file string) bool {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	title, _ := doc["title"].(string)
	desc, _ := doc["description"].(string)
	if auditMessageTitle.MatchString(title) || auditMessageSubject.MatchString(title+" "+desc) || strings.Contains(title+" "+desc, "ALL_AUDIT") {
		return true
	}
	return hasActorType(t, file, doc, map[string]bool{})
}

// hasActorType reports whether node, with its references resolved, declares
// an actor_type property.
func hasActorType(t *testing.T, file string, node map[string]any, visited map[string]bool) bool {
	if props, ok := node["properties"].(map[string]any); ok {
		if _, ok := props["actor_type"]; ok {
			return true
		}
	}
	if ref, ok := node["$ref"].(string); ok {
		if f, target, ok := resolveRef(t, file, ref); ok && !visited[f+"#"+ref] {
			visited[f+"#"+ref] = true
			if hasActorType(t, f, target, visited) {
				return true
			}
		}
	}
	for _, k := range []string{"allOf", "anyOf", "oneOf"} {
		items, _ := node[k].([]any)
		for _, it := range items {
			if m, ok := it.(map[string]any); ok && hasActorType(t, file, m, visited) {
				return true
			}
		}
	}
	return false
}

// schemaIDs maps every $id under the schemas directory holding file to its path.
func schemaIDs(file string) map[string]string {
	schemaRoot := strings.Split(filepath.ToSlash(file), "/schemas/")[0] + "/schemas"
	byID := map[string]string{}
	_ = filepath.WalkDir(schemaRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		raw, _ := os.ReadFile(p)
		var doc map[string]any
		if json.Unmarshal(raw, &doc) == nil {
			if id, _ := doc["$id"].(string); id != "" {
				byID[strings.TrimSuffix(id, "#")] = p
			}
		}
		return nil
	})
	return byID
}

// refFile resolves the file part of ref, made in file, to a path ("" = file).
func refFile(file, ref string) string {
	target, _, _ := strings.Cut(ref, "#")
	if target == "" {
		return file
	}
	raw, _ := os.ReadFile(file)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	baseID, _ := doc["$id"].(string)
	byID := schemaIDs(file)
	if u, err := url.Parse(target); err == nil && u.IsAbs() {
		if p := byID[target]; p != "" {
			return p
		}
	} else if base, err := url.Parse(baseID); err == nil && base.IsAbs() {
		if r, err := base.Parse(target); err == nil && byID[r.String()] != "" {
			return byID[r.String()]
		}
	}
	return filepath.Join(filepath.Dir(file), filepath.FromSlash(target))
}

// resolveRef returns the file and the JSON node ref points to.
func resolveRef(t *testing.T, file, ref string) (string, map[string]any, bool) {
	f := refFile(file, ref)
	raw, err := os.ReadFile(f)
	if err != nil {
		return f, nil, false
	}
	var node any
	if json.Unmarshal(raw, &node) != nil {
		return f, nil, false
	}
	_, frag, _ := strings.Cut(ref, "#")
	for _, tok := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		if tok == "" {
			continue
		}
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		m, ok := node.(map[string]any)
		if !ok {
			return f, nil, false
		}
		node = m[tok]
	}
	m, ok := node.(map[string]any)
	return f, m, ok
}

// collectRefs adds to out every repository-relative schema file that rel
// references through $ref, transitively. References resolve as paths
// relative to the referring file or as $id URLs of the publisher's schemas.
func collectRefs(t *testing.T, rel string, out map[string]bool) {
	t.Helper()
	root := contractFixtureDir(t)
	queue := []string{filepath.Join(root, rel)}
	visited := map[string]bool{}
	for len(queue) > 0 {
		file := queue[0]
		queue = queue[1:]
		if visited[file] {
			continue
		}
		visited[file] = true
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("schema %s cannot be read: %v", file, err)
			continue
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue
		}
		var refs []string
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, child := range x {
					if s, ok := child.(string); ok && k == "$ref" {
						refs = append(refs, s)
					} else {
						walk(child)
					}
				}
			case []any:
				for _, child := range x {
					walk(child)
				}
			}
		}
		walk(doc)
		for _, ref := range refs {
			p := refFile(file, ref)
			if p == file {
				continue
			}
			if r, err := filepath.Rel(root, p); err == nil {
				out[filepath.ToSlash(r)] = true
			}
			queue = append(queue, p)
		}
	}
}

// publisherAuditSchemas lists every other service's audit message schema.
func publisherAuditSchemas(t *testing.T) []string {
	t.Helper()
	var out []string
	root := filepath.Join(contractFixtureDir(t), "svc")
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 3 || parts[0] == "audit" || parts[1] != "schemas" {
			return nil
		}
		if isAuditMessageSchema(t, p) {
			out = append(out, p)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("scan publisher schemas: %v", walkErr)
	}
	if len(out) == 0 {
		t.Fatal("no publisher audit message schemas in contract fixtures")
	}
	sort.Strings(out)
	return out
}

// compilePublisherSchema compiles f with every sibling schema of its
// service available for $ref.
func compilePublisherSchema(t *testing.T, f string) (*jsonschema.Schema, map[string]any) {
	t.Helper()
	parts := strings.Split(filepath.ToSlash(f), "/schemas/")
	schemaRoot := parts[0] + "/schemas"
	c := jsonschema.NewCompiler()
	var target map[string]any
	var targetID string
	walkErr := filepath.WalkDir(schemaRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		id, _ := m["$id"].(string)
		if id == "" {
			id = "file://" + filepath.ToSlash(p)
		}
		_ = c.AddResource(id, doc)
		if p == f {
			target, targetID = m, id
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("load schemas of %s: %v", f, walkErr)
	}
	if target == nil {
		t.Fatalf("cannot load %s", f)
	}
	sch, err := c.Compile(targetID)
	if err != nil {
		t.Fatalf("compile %s: %v", f, err)
	}
	return sch, target
}

func exampleMessages(doc map[string]any) []map[string]any {
	var out []map[string]any
	ex, _ := doc["examples"].([]any)
	for _, e := range ex {
		if m, ok := e.(map[string]any); ok {
			out = append(out, normalize(m))
		}
	}
	return out
}

// normalize turns json.Number values into float64 like json.Unmarshal.
func normalize(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// schemaProperties merges the properties of doc and of every schema it
// reaches through $ref and allOf; doc's own definitions win.
func schemaProperties(t *testing.T, file string, doc map[string]any, visited map[string]bool) map[string]any {
	out := map[string]any{}
	if ref, ok := doc["$ref"].(string); ok && !visited[file+"#"+ref] {
		visited[file+"#"+ref] = true
		if f, target, ok := resolveRef(t, file, ref); ok {
			for k, v := range schemaProperties(t, f, target, visited) {
				out[k] = v
			}
		}
	}
	items, _ := doc["allOf"].([]any)
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			for k, v := range schemaProperties(t, file, m, visited) {
				out[k] = v
			}
		}
	}
	props, _ := doc["properties"].(map[string]any)
	for k, v := range props {
		if m, ok := v.(map[string]any); ok {
			out[k] = m
		} else if _, seen := out[k]; !seen {
			out[k] = v
		}
	}
	return out
}

// synthesizeMessages builds minimal messages from a publisher schema's
// const/enum values, with $ref and allOf resolved. An administrator message
// is offered with team_id (equal to resource_id) and without it (resource_id
// null), since publishers make team_id conditional.
func synthesizeMessages(t *testing.T, file string, doc map[string]any) []map[string]any {
	props := schemaProperties(t, file, doc, map[string]bool{})
	pick := func(name string, fallback any) any {
		p, _ := props[name].(map[string]any)
		if p == nil {
			return fallback
		}
		if v, ok := p["const"]; ok {
			return v
		}
		if e, ok := p["enum"].([]any); ok && len(e) > 0 {
			return e[0]
		}
		return fallback
	}
	required := map[string]bool{}
	if req, ok := doc["required"].([]any); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	}
	actorType := pick("actor_type", "operator")
	publisher := pick("publisher", pick("source_service", ""))
	m := map[string]any{
		"publisher":      publisher,
		"publisher_seq":  41,
		"occurred_at":    "2026-11-07T10:00:00.000Z",
		"source_service": pick("source_service", publisher),
		"actor_type":     actorType,
		"action":         pick("action", "action"),
		"resource_type":  pick("resource_type", "resource"),
		"resource_id":    5,
		"request_id":     7001,
		"outcome":        pick("outcome", "succeeded"),
	}
	if actorType == "operator" {
		m["actor_id"] = 12
		m["team_id"] = 3
	} else {
		m["actor_subject"] = "admin-sub-1"
	}
	if required["reason"] {
		m["reason"] = pick("reason", "insufficient_admin_role")
	}
	if required["changes"] {
		m["changes"] = map[string]any{}
	}
	if actorType == "operator" {
		return []map[string]any{normalize(m)}
	}
	withTeam := normalize(m)
	withTeam["team_id"] = float64(5)
	withoutTeam := normalize(m)
	withoutTeam["resource_id"] = nil
	return []map[string]any{withTeam, withoutTeam}
}
