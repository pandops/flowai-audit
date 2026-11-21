package test

// Requirement: message-broker names subjects from immutable identifiers.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/pandops/flowai-audit/internal/broker"
)

var operationToken = regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`)

func TestV0048MessageBrokerSubjects(t *testing.T) {
	t.Run("Team appears as a subject token only in the task queue and Source intake", func(t *testing.T) {
		subjects := broker.Subjects()
		want := map[string]bool{"audit.ui.list.sub": false, "audit.ui.get.sub": false, "*.audit.*.sub": false}
		for _, s := range subjects {
			if strings.HasPrefix(s, "flowai.") {
				t.Errorf("subject %s has the flowai. prefix", s)
			}
			if !strings.HasSuffix(s, ".sub") {
				t.Errorf("audit reads %s, which is not a .sub subject", s)
			}
			for _, tok := range strings.Split(s, ".") {
				if tok != "*" && strings.Trim(tok, "0123456789") == "" {
					t.Errorf("subject %s carries an identifier token %s", s, tok)
				}
			}
			if parts := strings.Split(s, "."); len(parts) == 4 && parts[1] == "ui" && !operationToken.MatchString(parts[2]) {
				t.Errorf("operation token %q is not lowercase words joined by -", parts[2])
			}
			if _, ok := want[s]; ok {
				want[s] = true
			}
		}
		for s, seen := range want {
			if !seen {
				t.Errorf("audit does not use %s", s)
			}
		}
		if broker.Stream != "ALL_AUDIT" || broker.Durable != "audit" || broker.FilterSubject != "*.audit.*.sub" {
			t.Fatalf("consumer = %s/%s/%s, want ALL_AUDIT/audit/*.audit.*.sub", broker.Stream, broker.Durable, broker.FilterSubject)
		}
	})
}
