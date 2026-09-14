package stack

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed assets/002-groups.sql
var groupsSQL string

const databaseReady = "GUACDEPLOY_DATABASE_READY"

// TCP readiness excludes the temporary, socket-only server used by the image
// entrypoint. Credentials remain in container process memory, never argv/stdin.
const databasePSQL = `set -eu
PGPASSWORD="$(cat /run/secrets/postgres-password)" exec psql -X --no-password --host=127.0.0.1 --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --set=ON_ERROR_STOP=1 "$@"`

var schemaObject = regexp.MustCompile(`(?m)^CREATE (TABLE|TYPE|(?:UNIQUE )?INDEX) (guacamole_[a-z_]+)\b`)
var schemaConstraint = regexp.MustCompile(`(?m)^\s*CONSTRAINT (guacamole_[a-z_0-9]+)\b`)

func validateSchema(sql string) error {
	if err := looksLikeSQL(sql); err != nil {
		return err
	}
	for _, want := range []string{"CREATE TABLE guacamole_entity", "CREATE TABLE guacamole_user_group"} {
		if !strings.Contains(sql, want) {
			return fmt.Errorf("the generated SQL does not contain %q; refusing to publish it", want)
		}
	}
	return nil
}

// databaseBootstrap checks the live database against the pinned image's schema.
// Existing complete databases receive no DDL or group changes. Empty databases
// can be initialized only during unfinished setup. Any partial import stops.
func databaseBootstrap(cfg Config) (string, error) {
	schema, err := os.ReadFile(filepath.Join(cfg.InstallDir, "init/001-initdb.sql"))
	if err != nil {
		return "", fmt.Errorf("read the database schema: %w", err)
	}
	if err := validateSchema(string(schema)); err != nil {
		return "", err
	}
	var checks []string
	for _, m := range schemaObject.FindAllStringSubmatch(string(schema), -1) {
		name := m[2] // regex restricts this to an SQL identifier; no user input
		if m[1] == "TYPE" {
			checks = append(checks, fmt.Sprintf("EXISTS (SELECT 1 FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typname = '%s' AND typtype = 'e')", name))
		} else {
			kind := "r"
			if strings.Contains(m[1], "INDEX") {
				kind = "i"
			}
			checks = append(checks, fmt.Sprintf("EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relname = '%s' AND relkind = '%s')", name, kind))
		}
	}
	for _, m := range schemaConstraint.FindAllStringSubmatch(string(schema), -1) {
		checks = append(checks, fmt.Sprintf("EXISTS (SELECT 1 FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND conname = '%s')", m[1]))
	}
	if len(checks) < 2 {
		return "", fmt.Errorf("database schema has no recognizable Guacamole table definitions")
	}
	var sql strings.Builder
	// All setup changes commit together. The advisory lock also serializes an
	// accidental concurrent bootstrap outside the deployment's state lock.
	sql.WriteString("SELECT pg_advisory_xact_lock(1869767527, 1);\nSET LOCAL search_path TO public;\n")
	fmt.Fprintf(&sql, "SELECT (%s) AS schema_ready \\gset\n\\if :schema_ready\n", strings.Join(checks, " AND\n"))
	if cfg.InitializeDatabase {
		sql.WriteString(`SELECT (
  EXISTS (SELECT 1 FROM guacamole_user_group g JOIN guacamole_entity e USING (entity_id) WHERE e.name = :'admin_group' AND e.type = 'USER_GROUP')
  AND EXISTS (SELECT 1 FROM guacamole_user_group g JOIN guacamole_entity e USING (entity_id) WHERE e.name = :'operator_group' AND e.type = 'USER_GROUP')
  AND NOT EXISTS (SELECT 1 FROM guacamole_entity WHERE name = 'guacadmin' AND type = 'USER')
) AS groups_ready \gset
\if :groups_ready
\else
DO $$ BEGIN RAISE EXCEPTION 'The schema exists but its initial authorization groups or default-login removal are incomplete. Setup preserved the database. Review the group initialization before resuming.'; END $$;
\endif
`)
	}
	sql.WriteString("-- The complete schema is already present. Preserve its data and groups.\n\\else\n")
	if !cfg.InitializeDatabase {
		sql.WriteString("DO $$ BEGIN RAISE EXCEPTION 'Database schema is missing or incomplete. Automatic initialization is disabled for a completed deployment. Restore the database or resume unfinished setup.'; END $$;\n")
	} else {
		sql.WriteString(`DO $guard$
BEGIN
  IF EXISTS (
    SELECT 1 FROM (
      SELECT relnamespace AS ns FROM pg_class
      UNION ALL SELECT typnamespace FROM pg_type
      UNION ALL SELECT pronamespace FROM pg_proc
    ) objects JOIN pg_namespace n ON n.oid = objects.ns
    WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'
  ) OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public', 'information_schema') AND nspname !~ '^pg_')
    OR EXISTS (SELECT 1 FROM pg_largeobject_metadata)
    OR EXISTS (SELECT 1 FROM pg_extension WHERE extname <> 'plpgsql') THEN
    RAISE EXCEPTION 'Database contains application objects but its Guacamole schema is incomplete. Setup preserved the database. Review or restore it before resuming.';
  END IF;
END
$guard$;
`)
		sql.Write(schema)
		sql.WriteString("\n")
		sql.WriteString(groupsSQL)
	}
	sql.WriteString("\n\\endif\n")
	// Exercise the same columns as the health check, within the transaction.
	sql.WriteString("SELECT entity_id FROM guacamole_entity LIMIT 0; SELECT user_group_id FROM guacamole_user_group LIMIT 0;\n")
	fmt.Fprintf(&sql, "\\echo %s\n", databaseReady)
	return sql.String(), nil
}

func startDatabase(ctx context.Context, run Runner, cfg Config, fresh bool, bootstrap string) error {
	args := []string{"up", "--detach", "--no-deps"}
	if fresh {
		args = append(args, "--force-recreate")
	}
	args = append(args, "postgres")
	if out, err := run(ctx, "", "docker", cfg.composeArgs(args...)...); err != nil {
		return fmt.Errorf("starting PostgreSQL failed: %w\n%s", err, tail(out))
	}
	readyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		out, err := run(readyCtx, "", "docker", cfg.composeArgs("exec", "-T", "postgres", "sh", "-c", databasePSQL, "guacdeploy-database", "--quiet", "--command=SELECT 1")...)
		if err == nil {
			break
		}
		select {
		case <-readyCtx.Done():
			return fmt.Errorf("PostgreSQL did not accept authenticated connections: %w\n%s", readyCtx.Err(), tail(out))
		case <-time.After(time.Second):
		}
	}
	out, err := run(ctx, bootstrap, "docker", cfg.composeArgs("exec", "-T", "postgres", "sh", "-c", databasePSQL,
		"guacdeploy-database", "--quiet", "--single-transaction", "--set=admin_group="+cfg.AdminGroup,
		"--set=operator_group="+cfg.OperatorGroup, "--file=-")...)
	if err != nil {
		return fmt.Errorf("database initialization failed; setup stopped before starting application services: %w\n%s", err, tail(out))
	}
	if !strings.Contains(out, databaseReady) {
		return fmt.Errorf("database initialization returned no completion result; setup stopped before starting application services")
	}
	return nil
}
