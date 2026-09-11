// Package stack renders and runs the local Guacamole containers: guacd,
// PostgreSQL, the Guacamole web application, nginx, and (in a later slice)
// cloudflared. Assets are embedded in the binary and rendered under the
// installation directory, so the tool works without a repository checkout.
// The database password reaches Compose through an in-memory stdin override
// and never lands in a rendered file.
package stack

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

//go:embed assets/compose.yaml.tmpl
var composeTmpl string

//go:embed assets/guacamole.conf.template
var nginxTemplate string

//go:embed assets/002-groups.sh
var groupsScript string

// GuacVersion is the pinned Guacamole release for this tool version.
const GuacVersion = "1.6.0"

// Config is the non-secret stack configuration. It mirrors what the tool
// records in deployment state.
type Config struct {
	InstallDir      string // default /opt/guacamole
	Hostname        string // public hostname, also the TLS server name
	AdminGroup      string
	OperatorGroup   string
	HTTPSPort       string // default 443
	SAMLMetadataURL string // empty until the Entra slice configures it
	ComposeProfiles string // e.g. "cloudflare" once the tunnel slice lands
}

func (c *Config) defaults() {
	if c.InstallDir == "" {
		c.InstallDir = "/opt/guacamole"
	}
	if c.HTTPSPort == "" {
		c.HTTPSPort = "443"
	}
}

// Runner executes a command with optional stdin, returning combined output.
type Runner func(ctx context.Context, stdin string, name string, args ...string) (string, error)

// ExecRunner is the real command seam.
func ExecRunner(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Render writes the compose file, nginx template, group initialisation, and
// non-secret .env under the installation directory, and creates a self-signed
// certificate when none exists. The origin-certificate slice replaces the
// certificate later; local checks accept the self-signed one until then.
// Render is idempotent and safe to re-run on resume.
func Render(cfg Config) error {
	cfg.defaults()
	for _, d := range []string{"", "init", "nginx/templates", "nginx/certs", "nginx/log"} {
		if err := os.MkdirAll(filepath.Join(cfg.InstallDir, d), 0o750); err != nil {
			return err
		}
	}

	var compose bytes.Buffer
	t := template.Must(template.New("compose").Parse(composeTmpl))
	if err := t.Execute(&compose, cfg); err != nil {
		return err
	}

	env := fmt.Sprintf(
		"# Non-secret configuration rendered by guacdeploy. Credentials never\n"+
			"# belong in this file; the database password arrives at start time.\n"+
			"GUAC_VERSION=%s\nGUAC_HOSTNAME=%s\nGUAC_ADMIN_GROUP=%s\nGUAC_OPERATOR_GROUP=%s\nHTTPS_PORT=%s\nSAML_IDP_METADATA_URL=%s\nCOMPOSE_PROFILES=%s\n",
		GuacVersion, cfg.Hostname, cfg.AdminGroup, cfg.OperatorGroup, cfg.HTTPSPort, cfg.SAMLMetadataURL, cfg.ComposeProfiles)

	files := map[string]struct {
		content string
		mode    os.FileMode
	}{
		"compose.yaml": {compose.String(), 0o640},
		".env":         {env, 0o600},
		"nginx/templates/guacamole.conf.template": {nginxTemplate, 0o644},
		"init/002-groups.sh":                      {groupsScript, 0o755},
	}
	for name, f := range files {
		if err := os.WriteFile(filepath.Join(cfg.InstallDir, name), []byte(f.content), f.mode); err != nil {
			return err
		}
	}

	certPath := filepath.Join(cfg.InstallDir, "nginx/certs/fullchain.pem")
	keyPath := filepath.Join(cfg.InstallDir, "nginx/certs/privkey.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := selfSignedCert(cfg.Hostname, certPath, keyPath); err != nil {
			return fmt.Errorf("create temporary self-signed certificate: %w", err)
		}
	}
	return nil
}

// selfSignedCert writes a short-lived self-signed certificate so nginx can
// terminate TLS before the real origin certificate is issued.
func selfSignedCert(hostname, certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// GenerateSchema produces init/001-initdb.sql from the pinned Guacamole
// image and validates it before publishing, so a failed generation never
// masquerades as a schema.
func GenerateSchema(ctx context.Context, run Runner, cfg Config) error {
	cfg.defaults()
	schemaPath := filepath.Join(cfg.InstallDir, "init/001-initdb.sql")
	marker := "-- Guacamole schema complete: " + GuacVersion
	if b, err := os.ReadFile(schemaPath); err == nil && strings.Contains(string(b), marker) {
		return nil
	}
	out, err := run(ctx, "", "docker", "run", "--rm", "guacamole/guacamole:"+GuacVersion,
		"/opt/guacamole/bin/initdb.sh", "--postgresql")
	if err != nil {
		return fmt.Errorf("database schema generation failed: %v\n%s", err, tail(out))
	}
	for _, want := range []string{"CREATE TABLE guacamole_entity", "CREATE TABLE guacamole_user_group"} {
		if !strings.Contains(out, want) {
			return fmt.Errorf("the generated SQL does not contain %q; refusing to publish it", want)
		}
	}
	// PostgreSQL's container user reads this public schema.
	return os.WriteFile(schemaPath, []byte(out+"\n"+marker+"\n"), 0o644)
}

// override builds the in-memory Compose override that delivers credentials.
// Dollar signs are doubled so Compose does not interpolate secret contents.
func override(password, tunnelToken string) string {
	esc := func(s string) string { return strings.ReplaceAll(s, "$", "$$") }
	o := map[string]any{"services": map[string]any{
		"postgres":    map[string]any{"environment": map[string]string{"POSTGRES_PASSWORD": esc(password)}},
		"guacamole":   map[string]any{"environment": map[string]string{"POSTGRESQL_PASSWORD": esc(password)}},
		"cloudflared": map[string]any{"environment": map[string]string{"TUNNEL_TOKEN": esc(tunnelToken)}},
	}}
	b, _ := json.Marshal(o)
	return string(b)
}

func (c Config) composeArgs(rest ...string) []string {
	return append([]string{"compose",
		"--project-directory", c.InstallDir,
		"--env-file", filepath.Join(c.InstallDir, ".env"),
		"-f", filepath.Join(c.InstallDir, "compose.yaml"),
		"-f", "-"}, rest...)
}

// Up starts the stack and waits for container health. The password travels
// only through stdin; it never appears in arguments or rendered files.
func Up(ctx context.Context, run Runner, cfg Config, password, tunnelToken string) error {
	cfg.defaults()
	out, err := run(ctx, override(password, tunnelToken), "docker",
		cfg.composeArgs("up", "--detach", "--wait", "--wait-timeout", "180")...)
	if err != nil {
		return fmt.Errorf("the services did not become healthy: %v\n%s", err, tail(out))
	}
	return nil
}

// Containers lists the stack's running container names.
func Containers(ctx context.Context, run Runner, cfg Config, password, tunnelToken string) ([]string, error) {
	cfg.defaults()
	out, err := run(ctx, override(password, tunnelToken), "docker",
		cfg.composeArgs("ps", "--format", "{{.Name}}")...)
	if err != nil {
		return nil, fmt.Errorf("docker compose ps failed: %v\n%s", err, tail(out))
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	return names, nil
}

// Probe checks the representative local connection: an HTTPS request to
// nginx on this host for the Guacamole web application. The certificate can
// be self-signed until the origin-certificate slice issues a real one, so
// verification is skipped for this local loopback probe only.
type Probe struct {
	Timeout time.Duration // total; default 120s
	Client  *http.Client  // injectable for tests
}

func (p Probe) Check(ctx context.Context, cfg Config) error {
	cfg.defaults()
	if p.Timeout == 0 {
		p.Timeout = 120 * time.Second
	}
	client := p.Client
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, "127.0.0.1:"+cfg.HTTPSPort)
				},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: cfg.Hostname},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	url := "https://" + cfg.Hostname + ":" + cfg.HTTPSPort + "/guacamole/"
	deadline := time.Now().Add(p.Timeout)
	var last string
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			switch resp.StatusCode {
			case 200, 302, 303, 307, 308:
				return nil
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("Guacamole did not respond through nginx within %s (last result: %s)", p.Timeout, last)
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if lines := strings.Split(s, "\n"); len(lines) > 12 {
		return strings.Join(lines[len(lines)-12:], "\n")
	}
	return s
}
