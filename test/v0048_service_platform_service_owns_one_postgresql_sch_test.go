package test

// Requirement: service-platform service owns one PostgreSQL schema and role.
// "Access to a foreign schema is denied" runs against PostgreSQL in
// v0048_schema_integration_test.go.

import (
	"strings"
	"testing"

	"github.com/pandops/flowai-audit/internal/migrations"
)

func TestV0048ServicePlatformOwnsOneSchema(t *testing.T) {
	t.Run("schema identifiers", func(t *testing.T) {
		for _, ok := range []string{"audit_schema", "audit_v2_schema"} {
			if !migrations.ValidSchema(ok) {
				t.Errorf("%s rejected", ok)
			}
		}
		for _, bad := range []string{"", "Audit", "audit-schema", "x;drop", "pg_catalog", "public", strings.Repeat("a", 64)} {
			if migrations.ValidSchema(bad) {
				t.Errorf("%q accepted", bad)
			}
		}
	})
}
