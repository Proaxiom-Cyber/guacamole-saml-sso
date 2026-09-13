package stack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderWritesAssetsAndCertOnce(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{InstallDir: dir, Hostname: "guac.example.test", AdminGroup: "GA", OperatorGroup: "GO"}
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compose), "SAML_IDP_METADATA_URL") {
		t.Fatal("SAML block rendered without a metadata URL")
	}
	env, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(env), "GUAC_HOSTNAME=guac.example.test") {
		t.Fatalf(".env: %s", env)
	}
	if info, _ := os.Stat(filepath.Join(dir, ".env")); info.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode %v", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Join(dir, "nginx/certs/privkey.pem")); info.Mode().Perm() != 0o600 {
		t.Fatalf("privkey mode %v", info.Mode().Perm())
	}

	// SAML block appears once the metadata URL exists.
	cfg.SAMLMetadataURL = "https://login.example/metadata"
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	compose, _ = os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if !strings.Contains(string(compose), "SAML_IDP_METADATA_URL") {
		t.Fatal("SAML block missing despite metadata URL")
	}

	// The certificate survives re-rendering.
	before, _ := os.ReadFile(filepath.Join(dir, "nginx/certs/fullchain.pem"))
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "nginx/certs/fullchain.pem"))
	if string(before) != string(after) {
		t.Fatal("certificate was regenerated on re-render")
	}
}

const goodSQL = "CREATE TABLE guacamole_entity (x int);\nCREATE TABLE guacamole_user_group (y int);\n"

func TestGenerateSchemaValidatesAndCaches(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{InstallDir: dir}
	os.MkdirAll(filepath.Join(dir, "init"), 0o750)

	calls := 0
	bad := func(context.Context, string, ...string) (string, string, error) {
		calls++
		return "-- nothing useful", "", nil
	}
	if err := GenerateSchema(context.Background(), bad, cfg); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("invalid SQL accepted: %v", err)
	}

	good := func(context.Context, string, ...string) (string, string, error) {
		calls++
		return goodSQL, "", nil
	}
	if err := GenerateSchema(context.Background(), good, cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "init/001-initdb.sql"))
	if !strings.Contains(string(b), "schema complete: "+GuacVersion) {
		t.Fatalf("marker missing:\n%s", b)
	}
	calls = 0
	if err := GenerateSchema(context.Background(), good, cfg); err != nil || calls != 0 {
		t.Fatalf("cached schema regenerated (calls=%d, err=%v)", calls, err)
	}
}

func TestUpKeepsPasswordOutOfArgumentsAndStdin(t *testing.T) {
	var gotStdin string
	var gotArgs []string
	run := func(_ context.Context, stdin, name string, args ...string) (string, error) {
		gotStdin, gotArgs = stdin, append([]string{name}, args...)
		return "ok", nil
	}
	cfg := Config{InstallDir: t.TempDir(), RuntimeSecretsDir: filepath.Join(runtimeTestDir(t), "run")}
	if err := Up(context.Background(), run, cfg, "pa$sword", "tok$en"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotStdin, "pa$sword") || strings.Contains(gotStdin, "tok$en") {
		t.Fatal("a credential was piped to docker on stdin")
	}
	for _, a := range gotArgs {
		if strings.Contains(a, "pa$sword") || strings.Contains(a, "tok$en") {
			t.Fatalf("a credential leaked into argv: %v", gotArgs)
		}
	}
}

func TestProbeAcceptsGuacamoleRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/guacamole/" {
			http.Redirect(w, r, "/guacamole/#/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cfg := Config{InstallDir: t.TempDir(), Hostname: u.Hostname(), HTTPSPort: u.Port()}
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := (Probe{Timeout: 3 * time.Second, Client: client}).Check(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

// TestGenerateSchemaRejectsNonSQLPrefix pins the defect found on the live
// Rocky host: docker writes image-pull progress to stderr, and capturing
// combined output prepended that text to the schema. psql then failed on
// the first statement, so the database came up with no Guacamole tables
// while the file still contained every expected CREATE TABLE further
// down. Only stdout may reach the schema, and a non-SQL first line must
// be refused rather than published.
func TestGenerateSchemaRejectsNonSQLPrefix(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{InstallDir: dir}
	os.MkdirAll(filepath.Join(dir, "init"), 0o755)

	noisy := func(context.Context, string, ...string) (string, string, error) {
		return "Unable to find image 'guacamole/guacamole:1.6.0' locally\n" +
			"1.6.0: Pulling from guacamole/guacamole\n" + goodSQL, "", nil
	}
	err := GenerateSchema(context.Background(), noisy, cfg)
	if err == nil || !strings.Contains(err.Error(), "not SQL") {
		t.Fatalf("schema with pull noise accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "init/001-initdb.sql")); !os.IsNotExist(statErr) {
		t.Fatal("a corrupt schema was published")
	}

	// Pull noise on stderr must not reach the file at all.
	clean := func(context.Context, string, ...string) (string, string, error) {
		return goodSQL, "1.6.0: Pulling from guacamole/guacamole\n", nil
	}
	if err := GenerateSchema(context.Background(), clean, cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "init/001-initdb.sql"))
	if strings.Contains(string(b), "Pulling from") {
		t.Fatalf("stderr text reached the schema file:\n%s", b)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(b)), "CREATE TABLE guacamole_entity") {
		t.Fatalf("schema does not start with SQL:\n%s", b)
	}
}

// TestGenerateSchemaRepairsCorruptCachedSchema pins the second half of the
// live defect: the corrupt schema written by the earlier version carried
// the completion marker, so a marker-only cache check would trust it for
// ever and the host could never recover.
func TestGenerateSchemaRepairsCorruptCachedSchema(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{InstallDir: dir}
	os.MkdirAll(filepath.Join(dir, "init"), 0o755)
	schemaPath := filepath.Join(dir, "init/001-initdb.sql")

	corrupt := "Unable to find image 'guacamole/guacamole:1.6.0' locally\n" +
		goodSQL + "\n-- Guacamole schema complete: " + GuacVersion + "\n"
	if err := os.WriteFile(schemaPath, []byte(corrupt), 0o644); err != nil {
		t.Fatal(err)
	}

	calls := 0
	good := func(context.Context, string, ...string) (string, string, error) {
		calls++
		return goodSQL, "", nil
	}
	if err := GenerateSchema(context.Background(), good, cfg); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("corrupt cached schema was trusted instead of regenerated (calls=%d)", calls)
	}
	b, _ := os.ReadFile(schemaPath)
	if strings.Contains(string(b), "Unable to find image") {
		t.Fatal("corrupt schema survived regeneration")
	}
}
