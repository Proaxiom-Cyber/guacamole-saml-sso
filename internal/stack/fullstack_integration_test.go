package stack

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
)

// This is the actual production Compose path on a fresh Linux host directory.
// Run as root so runtime credential ownership matches the deployed containers.
func TestFullStackIntegration(t *testing.T) {
	if os.Getenv("GUACDEPLOY_TEST_DOCKER") != "1" || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires GUACDEPLOY_TEST_DOCKER=1 and root on Linux")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	mem, err := os.MkdirTemp("/dev/shm", "guacdeploy-stack-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(mem) })
	cfg := Config{InstallDir: t.TempDir(), RuntimeSecretsDir: filepath.Join(mem, "secrets"), Hostname: "guac.example.test", HTTPSPort: "0", AdminGroup: "Administrators", OperatorGroup: "Operators", InitializeDatabase: true}
	project := fmt.Sprintf("guacdeploy-test-%d", time.Now().UnixNano())
	run := func(c context.Context, stdin, name string, args ...string) (string, error) {
		if name == "docker" && len(args) > 0 && args[0] == "compose" {
			args = append([]string{"compose", "--project-name", project}, args[1:]...)
		}
		return ExecRunner(c, stdin, name, args...)
	}
	if err := Render(cfg); err != nil {
		t.Fatal(err)
	}
	if err := recording.EnsureDirs(cfg.InstallDir); err != nil {
		t.Fatal(err)
	}
	if err := GenerateSchema(ctx, ExecOutRunner, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if out, err := run(cleanupCtx, "", "docker", cfg.composeArgs("down", "--volumes", "--remove-orphans")...); err != nil {
			t.Errorf("fixture cleanup: %v %s", err, out)
		}
	})
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(raw[:]) // memory and tmpfs only
	if err := Up(ctx, run, cfg, password, ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckDelivery(ctx, run, cfg, password, ""); err != nil {
		t.Fatal(err)
	}
	port, err := run(ctx, "", "docker", cfg.composeArgs("port", "nginx", "443")...)
	if err != nil {
		t.Fatal(err)
	}
	_, cfg.HTTPSPort, err = net.SplitHostPort(strings.TrimSpace(strings.Split(port, "\n")[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := (Probe{Timeout: time.Minute}).Check(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.InitializeDatabase = false
	if err := Up(ctx, run, cfg, password, ""); err != nil {
		t.Fatal("warm restart:", err)
	}
	if err := (Probe{Timeout: time.Minute}).Check(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}
