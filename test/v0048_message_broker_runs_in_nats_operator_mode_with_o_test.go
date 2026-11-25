package test

// Requirement: message-broker runs in NATS operator mode with one user JWT
// per identity (audit's side: it refuses to start without its credentials).

import (
	"strings"
	"testing"

	"github.com/pandops/flowai-audit/internal/config"
)

func TestV0048MessageBrokerOperatorModeCredentials(t *testing.T) {
	t.Run("valid credentials load", func(t *testing.T) {
		f := writeTrustFiles(t)
		l, err := config.Parse([]byte(validYAML(f)), f.dir)
		if err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
		if l.NATSUserJWT != f.userJWT || len(l.NATSUserSeed) == 0 {
			t.Fatal("user JWT or seed not loaded from the credentials file")
		}
	})

	t.Run("Service credential is missing", func(t *testing.T) {
		f := writeTrustFiles(t)
		base := validYAML(f)
		for name, yaml := range map[string]string{
			"no credentials_file":      strings.Replace(base, "  credentials_file: "+f.creds+"\n", "", 1),
			"credentials file missing": strings.Replace(base, f.creds, f.dir+"/absent.creds", 1),
			"credentials without seed": strings.Replace(base, f.creds, f.jwtOnly, 1),
			"credentials without JWT":  strings.Replace(base, f.creds, f.seedOnly, 1),
			"no NATS CA":               strings.Replace(base, "  ca_file: "+f.natsCA+"\n", "", 1),
			"NATS CA is not PEM":       strings.Replace(base, f.natsCA, f.creds, 1),
			"plaintext NATS URL":       strings.Replace(base, "tls://nats", "nats://nats", 1),
			"no NATS URL":              strings.Replace(base, "  url: tls://nats.flowai.svc:4222\n", "", 1),
		} {
			if _, err := config.Parse([]byte(yaml), f.dir); err == nil {
				t.Errorf("%s: configuration accepted, want startup failure", name)
			}
		}
	})
}
