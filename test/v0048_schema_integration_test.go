//go:build integration

package test

// 1.7 row: each service writes only its own <name>_schema with its own role;
// another schema is refused. Also service-platform "Access to a foreign
// schema is denied" and "Configured schema and host are used".

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/migrations"
	"github.com/pandops/flowai-audit/internal/store"
)

// serviceRole creates a login role owning schema (as the deployment does)
// and returns a connection as that role.
func serviceRole(t *testing.T, admin *sql.DB, dbName, schema string, ownSchema bool) *sql.DB {
	t.Helper()
	ctx := context.Background()
	suffix, _ := randomToken(4)
	role := "audit_role_" + suffix
	password, _ := randomToken(12)
	mustExec(t, admin, `CREATE ROLE `+role+` LOGIN PASSWORD '`+password+`'`)
	mustExec(t, admin, `GRANT CONNECT ON DATABASE "`+dbName+`" TO `+role)
	if ownSchema {
		mustExec(t, admin, `CREATE SCHEMA `+schema+` AUTHORIZATION `+role)
	}
	db, err := sql.Open("pgx", shared.roleDSN(role, password, dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if ownSchema {
			_, _ = admin.ExecContext(c, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		}
		_, _ = admin.ExecContext(c, `DROP OWNED BY `+role)
		if _, err := admin.ExecContext(c, `DROP ROLE `+role); err != nil {
			t.Errorf("cleanup: drop role %s: %v", role, err)
		}
	})
	return db
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func TestV0048SchemaIsolationIntegration(t *testing.T) {
	ctx := context.Background()
	admin := freshDB(t)
	dbName := lastDBName
	mustExec(t, admin, `CREATE SCHEMA task_manager_schema`)
	mustExec(t, admin, `CREATE TABLE task_manager_schema.tasks (team_id bigint, task_id bigint)`)
	mustExec(t, admin, `INSERT INTO task_manager_schema.tasks VALUES (3, 1010)`)
	role := serviceRole(t, admin, dbName, "audit_schema", true)

	if err := migrations.Apply(ctx, role, "audit_schema"); err != nil {
		t.Fatalf("migrate audit_schema as the audit role: %v", err)
	}
	if err := migrations.Apply(ctx, role, "audit_schema"); err != nil {
		t.Fatalf("second migrate is not idempotent: %v", err)
	}

	t.Run("migrations create objects only in audit_schema", func(t *testing.T) {
		rows, err := admin.QueryContext(ctx, `
			SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE pg_get_userbyid(c.relowner) <> 'flowai' AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var ns, rel string
			_ = rows.Scan(&ns, &rel)
			count++
			if ns != "audit_schema" {
				t.Errorf("migration created %s.%s outside audit_schema", ns, rel)
			}
		}
		if count == 0 {
			t.Fatal("migration created no object")
		}
	})

	t.Run("Access to a foreign schema is denied", func(t *testing.T) {
		var n int
		err := role.QueryRowContext(ctx, `SELECT count(*) FROM task_manager_schema.tasks`).Scan(&n)
		if sqlState(err) != "42501" {
			t.Fatalf("read of task_manager_schema = %v (n=%d), want permission denied 42501", err, n)
		}
		_, err = role.ExecContext(ctx, `INSERT INTO task_manager_schema.tasks VALUES (4, 1)`)
		if sqlState(err) != "42501" {
			t.Fatalf("write to task_manager_schema = %v, want permission denied", err)
		}
		_, err = role.ExecContext(ctx, `CREATE TABLE public.audit_leak (x int)`)
		if sqlState(err) != "42501" {
			t.Fatalf("create in public = %v, want permission denied", err)
		}
		var rows int
		_ = admin.QueryRowContext(ctx, `SELECT count(*) FROM task_manager_schema.tasks`).Scan(&rows)
		if rows != 1 {
			t.Fatalf("foreign table has %d rows, want the untouched 1", rows)
		}
	})

	t.Run("store works as the audit role", func(t *testing.T) {
		s, err := store.New(role, "audit_schema")
		if err != nil {
			t.Fatal(err)
		}
		team := int64(3)
		actor := int64(12)
		res := int64(4)
		e, inserted, err := s.Insert(ctx, audit.Entry{TeamID: &team, Publisher: "flow-registry", PublisherSeq: 1, SourceService: "flow-registry",
			ActorType: audit.ActorOperator, ActorID: &actor, Action: "flow_updated", ResourceType: "flow", ResourceID: &res,
			RequestID: 7001, Outcome: "succeeded", OccurredAt: time.Now().UTC()})
		if err != nil || !inserted || e.AuditID < 1 {
			t.Fatalf("insert as role: %+v %v %v", e, inserted, err)
		}
	})

	t.Run("Configured schema and host are used", func(t *testing.T) {
		other := serviceRole(t, admin, dbName, "audit_v2_schema", true)
		if err := migrations.Apply(ctx, other, "audit_v2_schema"); err != nil {
			t.Fatalf("migrate audit_v2_schema: %v", err)
		}
		var n int
		if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='audit_v2_schema'`).Scan(&n); err != nil || n == 0 {
			t.Fatalf("tables in audit_v2_schema = %d %v, want some", n, err)
		}
		_, err := other.ExecContext(ctx, `SELECT 1 FROM audit_schema.audit_entries`)
		if sqlState(err) != "42501" {
			t.Fatalf("second role reads the first schema: %v", err)
		}
	})
}
