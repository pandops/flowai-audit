package test

// Requirement: message-broker never carries secrets in streams or logs.
// audit publishes no stream message; its logs and replies must not carry
// secret material from the messages it consumes.

import (
	"strings"
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048MessageBrokerNoSecretsInLogs(t *testing.T) {
	t.Run("Stream content inspection", func(t *testing.T) {
		h := newHarness(t)
		for i, mutate := range []func(f fields){
			func(f fields) {},                       // stored
			func(f fields) { f["team_id"] = 4 },     // rejected
			func(f fields) { delete(f, "outcome") }, // terminated
		} {
			f := operatorMsg("env-registry", int64(600+i), 3, "secret_replaced")
			for k, v := range secretMaterial {
				f[k] = v
			}
			mutate(f)
			h.handle(t, delivery(t, "3", f))
		}
		h.store.Down = true
		f := operatorMsg("env-registry", 700, 3, "secret_replaced")
		for k, v := range secretMaterial {
			f[k] = v
		}
		h.handle(t, delivery(t, "3", f)) // retried, logged
		logs := h.logs.String()
		if logs == "" {
			t.Fatal("consumer logged nothing about rejected or failed messages")
		}
		for k, v := range secretMaterial {
			if strings.Contains(logs, v) {
				t.Errorf("log contains %s material", k)
			}
		}
		_ = audit.ResultStored
	})
}
