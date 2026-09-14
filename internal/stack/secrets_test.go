package stack

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func runtimeTestDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("/dev/shm", "guacdeploy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := checkMemoryBacked(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

const (
	testPassword = "pa$sword-3f9c"
	testToken    = "tok$en-7b21"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	cfg := Config{
		InstallDir:        t.TempDir(),
		RuntimeSecretsDir: filepath.Join(runtimeTestDir(t), "run", "secrets"),
		Hostname:          "guac.example.test",
		AdminGroup:        "GA",
		OperatorGroup:     "GO",
		ComposeProfiles:   "cloudflare",
	}
	writeTestSchema(t, cfg)
	return cfg
}

// TestComposeDeliversCredentialsAsFilesOnly is the regression guard the
// acceptance criterion needs: putting either credential back into a service's
// "environment:" block turns this test red. Docker stores a container's
// environment on disk, so an environment field is a persistent plaintext copy
// of the credential.
func TestComposeDeliversCredentialsAsFilesOnly(t *testing.T) {
	cfg := testConfig(t)
	cfg.SAMLMetadataURL = "https://login.example/metadata"
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(cfg.InstallDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)

	// No credential-bearing environment key, with or without a value.
	banned := regexp.MustCompile(`(?m)^\s+(POSTGRES_PASSWORD|POSTGRESQL_PASSWORD|TUNNEL_TOKEN):`)
	if m := banned.FindString(compose); m != "" {
		t.Fatalf("a credential is delivered as an environment field: %q", strings.TrimSpace(m))
	}
	// Each image's file mechanism is wired up instead.
	for _, want := range []string{
		"POSTGRES_PASSWORD_FILE: /run/secrets/postgres-password",
		"POSTGRESQL_PASSWORD_FILE: /run/secrets/postgresql-password",
		`ENABLE_FILE_ENVIRONMENT_PROPERTIES: "true"`,
		"TUNNEL_TOKEN_FILE: /run/secrets/tunnel-token",
	} {
		if !strings.Contains(compose, want) {
			t.Fatalf("compose.yaml is missing %q", want)
		}
	}
	// Each service mounts only its own credential directory.
	for _, s := range runtimeSecrets {
		want := s.dir(cfg) + ":/run/secrets:ro,z"
		if !strings.Contains(compose, want) {
			t.Fatalf("compose.yaml is missing the mount %q", want)
		}
	}
	// The health check can no longer read the password from the container
	// environment, so it must read the file.
	if !strings.Contains(compose, `PGPASSWORD=\"$$(cat /run/secrets/postgres-password)\"`) {
		t.Fatal("the postgres health check does not read the credential file")
	}
}

func TestUpWritesOwnerOnlyRuntimeFilesAndRecreatesOnColdBoot(t *testing.T) {
	cfg := testConfig(t)
	var calls [][]string
	run := func(_ context.Context, _ string, name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		return databaseReady, nil
	}
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}

	for _, s := range runtimeSecrets {
		want := s.value(testPassword, testToken)
		b, err := os.ReadFile(s.path(cfg))
		if err != nil {
			t.Fatalf("%s: %v", s.Service, err)
		}
		// Verbatim, with no trailing newline: Guacamole reads the file as
		// the property value without trimming it.
		if string(b) != want {
			t.Fatalf("%s: the runtime file does not hold the credential exactly", s.Service)
		}
		info, err := os.Stat(s.path(cfg))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: runtime file mode %04o", s.Service, info.Mode().Perm())
		}
		d, err := os.Stat(s.dir(cfg))
		if err != nil {
			t.Fatal(err)
		}
		if d.Mode().Perm() != 0o700 {
			t.Fatalf("%s: runtime directory mode %04o", s.Service, d.Mode().Perm())
		}
	}
	if info, _ := os.Stat(cfg.RuntimeSecretsDir); info.Mode().Perm() != 0o711 {
		t.Fatalf("runtime root mode %04o", info.Mode().Perm())
	}

	// Cold boot: the files were absent, so the containers Docker restarted
	// by itself are running without a credential and must be recreated.
	if !strings.Contains(strings.Join(calls[0], " "), "--force-recreate") {
		t.Fatalf("a cold start did not recreate the containers: %v", calls[0])
	}
	// A second start in the same boot changes nothing and must not restart
	// the stack for no reason.
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(calls[len(calls)-1], " "), "--force-recreate") {
		t.Fatalf("a warm start recreated the containers: %v", calls[len(calls)-1])
	}
}

// TestUpRepairsDirectoriesDockerCreated covers the cold boot as it actually
// happens. Docker restarts the containers by itself before anything has
// written the tmpfs, and it creates each missing bind-mount source as a
// world-readable directory of its own. Up has to take those directories back,
// or the credential files land in a directory every account on the host can
// list.
func TestUpRepairsDirectoriesDockerCreated(t *testing.T) {
	cfg := testConfig(t)
	for _, s := range runtimeSecrets {
		if err := os.MkdirAll(s.dir(cfg), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(cfg.RuntimeSecretsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context, string, string, ...string) (string, error) { return databaseReady, nil }
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(cfg.RuntimeSecretsDir); info.Mode().Perm() != 0o711 {
		t.Fatalf("runtime root left at mode %04o", info.Mode().Perm())
	}
	for _, s := range runtimeSecrets {
		if info, _ := os.Stat(s.dir(cfg)); info.Mode().Perm() != 0o700 {
			t.Fatalf("%s: runtime directory left at mode %04o", s.Service, info.Mode().Perm())
		}
	}
}

func TestUpWritesNoTunnelTokenWithoutATunnel(t *testing.T) {
	cfg := testConfig(t)
	run := func(context.Context, string, string, ...string) (string, error) { return databaseReady, nil }
	if err := Up(context.Background(), run, cfg, testPassword, ""); err != nil {
		t.Fatal(err)
	}
	cf := runtimeSecrets[2]
	if _, err := os.Stat(cf.path(cfg)); !os.IsNotExist(err) {
		t.Fatal("an empty tunnel token was written to the runtime directory")
	}
}

func TestRemoveRuntimeSecrets(t *testing.T) {
	cfg := testConfig(t)
	run := func(context.Context, string, string, ...string) (string, error) { return databaseReady, nil }
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRuntimeSecrets(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.RuntimeSecretsDir); !os.IsNotExist(err) {
		t.Fatal("the runtime credential directory survived removal")
	}
}

// dockerFake answers the two commands CheckDelivery runs. inspect returns
// whatever metadata the test wants Docker to be holding.
func dockerFake(inspect string) Runner {
	return func(_ context.Context, _ string, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "guacdeploy-database") {
			return databaseReady, nil
		}
		switch {
		case strings.Contains(joined, "ps --quiet"):
			return "a1b2c3d4e5f6\nf6e5d4c3b2a1\n", nil
		case strings.HasPrefix(joined, "inspect"):
			return inspect, nil
		}
		return "", nil
	}
}

const cleanInspect = `[{"Config":{"Env":["POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password","POSTGRES_USER=guacamole_user"]}}]`

func TestCheckDeliveryAcceptsFileDelivery(t *testing.T) {
	cfg := testConfig(t)
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	run := dockerFake(cleanInspect)
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	if err := CheckDelivery(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatalf("a correctly delivered stack was reported as failing: %v", err)
	}
}

func TestCheckDeliveryFindsACredentialInDockerMetadata(t *testing.T) {
	cfg := testConfig(t)
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	// What the old environment-field delivery left behind.
	leaky := `[{"Config":{"Env":["POSTGRES_PASSWORD=` + testPassword + `"]}}]`
	run := dockerFake(leaky)
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	err := CheckDelivery(context.Background(), run, cfg, testPassword, testToken)
	if err == nil {
		t.Fatal("a plaintext credential in Docker's stored metadata was not reported")
	}
	if !strings.Contains(err.Error(), "stored metadata") {
		t.Fatalf("the finding does not name the metadata: %v", err)
	}
	assertNoCredential(t, err.Error())
}

func TestCheckDeliveryFindsACredentialInTheRenderedCompose(t *testing.T) {
	cfg := testConfig(t)
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	run := dockerFake(cleanInspect)
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.InstallDir, "compose.yaml")
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(b, []byte("\n# TUNNEL_TOKEN: "+testToken+"\n")...), 0o640); err != nil {
		t.Fatal(err)
	}
	err := CheckDelivery(context.Background(), run, cfg, testPassword, testToken)
	if err == nil || !strings.Contains(err.Error(), "rendered compose.yaml") {
		t.Fatalf("a credential written into compose.yaml was not reported: %v", err)
	}
	assertNoCredential(t, err.Error())
}

func TestCheckDeliveryReportsAnUndeliveredCredential(t *testing.T) {
	cfg := testConfig(t)
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	run := dockerFake(cleanInspect)
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(runtimeSecrets[0].path(cfg)); err != nil {
		t.Fatal(err)
	}
	err := CheckDelivery(context.Background(), run, cfg, testPassword, testToken)
	if err == nil || !strings.Contains(err.Error(), "was not delivered") {
		t.Fatalf("a missing runtime credential was not reported: %v", err)
	}
	assertNoCredential(t, err.Error())
}

func TestCheckDeliveryReportsAReadableRuntimeFile(t *testing.T) {
	cfg := testConfig(t)
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	run := dockerFake(cleanInspect)
	if err := Up(context.Background(), run, cfg, testPassword, testToken); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeSecrets[0].path(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CheckDelivery(context.Background(), run, cfg, testPassword, testToken)
	if err == nil || !strings.Contains(err.Error(), "not owner-only") {
		t.Fatalf("a world-readable runtime credential was not reported: %v", err)
	}
	assertNoCredential(t, err.Error())
}

// assertNoCredential is the rule that makes this check usable in an operator
// transcript: a finding says where the credential is, never what it is.
func assertNoCredential(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, testPassword) || strings.Contains(s, testToken) {
		t.Fatal("a credential value was printed in a finding")
	}
}

func TestMountFSTypeRejectsPersistentStorage(t *testing.T) {
	const mounts = "/dev/mapper/rl-root / xfs rw,relatime 0 0\n" +
		"tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0\n" +
		"/dev/mapper/rl-var /var/lib/docker xfs rw,relatime 0 0\n"

	for _, c := range []struct{ path, want string }{
		{"/run/guacdeploy/secrets", "tmpfs"},
		{"/var/lib/docker/containers", "xfs"},
		{"/opt/guacamole", "xfs"},
		{"/run", "tmpfs"},
	} {
		got, found := mountFSType(mounts, c.path)
		if !found || got != c.want {
			t.Fatalf("%s: got %q (found=%v), want %q", c.path, got, found, c.want)
		}
	}
	// "/runner" must not match the "/run" mount point.
	if got, _ := mountFSType(mounts, "/runner/x"); got != "xfs" {
		t.Fatalf("/runner/x resolved to %q; the mount point match is not on a path boundary", got)
	}
}

func TestCheckMemoryBackedRefusesPersistentStorage(t *testing.T) {
	if _, err := os.Stat("/proc/mounts"); err != nil {
		t.Skip("no /proc/mounts on this host")
	}
	// A path under the working tree is on ordinary persistent storage.
	err := checkMemoryBacked(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "survives a reboot") {
		t.Fatalf("a persistent path was accepted for decrypted credentials: %v", err)
	}
}
