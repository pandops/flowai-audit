// Package migrations creates and changes audit's objects, only in its own schema.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

//go:embed sql/*.sql
var files embed.FS

var schemaName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// ValidSchema reports whether name is an acceptable schema identifier.
func ValidSchema(name string) bool {
	if !schemaName.MatchString(name) || name == "public" || strings.HasPrefix(name, "pg_") || name == "information_schema" {
		return false
	}
	return true
}

// lockKey serializes concurrent migrations of one schema.
const lockSQL = `SELECT pg_advisory_xact_lock(hashtext('audit-migrations:' || $1))`

// Apply migrates schema to the latest version. The deployment pre-creates
// the schema and the service role has no CREATE on the database, so the
// schema is created only when it is missing.
func Apply(ctx context.Context, db *sql.DB, schema string) error {
	if !ValidSchema(schema) {
		return fmt.Errorf("invalid schema name %q", schema)
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, schema).Scan(&exists); err != nil {
		return fmt.Errorf("look up schema: %w", err)
	}
	if !exists {
		if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
			return fmt.Errorf("create schema %s: %w", schema, err)
		}
	}
	names, err := files.ReadDir("sql")
	if err != nil {
		return err
	}
	var versions []string
	for _, n := range names {
		versions = append(versions, n.Name())
	}
	sort.Strings(versions)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, lockSQL, schema); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+schema+`.schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	for _, v := range versions {
		var done bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+schema+`.schema_migrations WHERE version = $1)`, v).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		raw, err := files.ReadFile(path.Join("sql", v))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, strings.ReplaceAll(string(raw), "{{schema}}", schema)); err != nil {
			return fmt.Errorf("migration %s: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+schema+`.schema_migrations (version) VALUES ($1)`, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}
