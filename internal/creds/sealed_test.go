package creds

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCreds stands in for systemd-creds. It records every argument of every
// call so a test can prove no secret is ever passed as one, and it performs
// a real round trip so encrypt and decrypt are actually checked against each
// other rather than against a stub.
type fakeCreds struct {
	argv     [][]string // one entry per call, including the command name
	stdin    []string
	version  string // --version output; default systemd 257
	hasTPM2  string // has-tpm2 output; default "yes"
	tpmFails bool   // has-tpm2 exits non-zero
	notFound bool   // systemd-creds is not installed
	sealErr  error  // encrypt fails with this
	openErr  error  // decrypt fails with this
	echo     bool   // a hostile command that copies stdin into stderr
	empty    bool   // decrypt succeeds but returns nothing
}

func (f *fakeCreds) run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	f.argv = append(f.argv, append([]string{name}, args...))
	f.stdin = append(f.stdin, stdin)
	echoed := ""
	if f.echo {
		echoed = "systemd-creds: failed on input " + stdin
	}
	if f.notFound {
		return "", "", errors.New(`exec: "systemd-creds": executable file not found in $PATH`)
	}
	switch {
	case name == "systemd-creds" && len(args) > 0 && args[0] == "--version":
		v := f.version
		if v == "" {
			v = "systemd 257 (257-9.el10)\n+PAM +AUDIT\n"
		}
		return v, "", nil
	case name == "systemd-creds" && len(args) > 0 && args[0] == "has-tpm2":
		h := f.hasTPM2
		if h == "" && !f.tpmFails {
			h = "yes\n+firmware\n+driver\n+system\n"
		}
		if f.tpmFails {
			return h, "", errors.New("exit status 1")
		}
		return h, "", nil
	case name == "systemd-creds" && len(args) > 0 && args[0] == "encrypt":
		if f.sealErr != nil {
			return "", echoed, f.sealErr
		}
		key, credName := flag(args, "--with-key="), flag(args, "--name=")
		return "SEALED:" + key + ":" + credName + ":" + base64.StdEncoding.EncodeToString([]byte(stdin)), "", nil
	case name == "systemd-creds" && len(args) > 0 && args[0] == "decrypt":
		if f.openErr != nil {
			return "", echoed, f.openErr
		}
		if f.empty {
			return "", "", nil
		}
		parts := strings.SplitN(stdin, ":", 4)
		if len(parts) != 4 || parts[0] != "SEALED" {
			return "", "not a systemd-creds blob", errors.New("exit status 1")
		}
		if parts[2] != flag(args, "--name=") {
			return "", "credential name mismatch", errors.New("exit status 1")
		}
		plain, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil {
			return "", "corrupt blob", errors.New("exit status 1")
		}
		return string(plain), "", nil
	}
	return "", "", nil
}

func flag(args []string, prefix string) string {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	return ""
}

func hasTPMDevice() []string   { return []string{"/dev/tpm0", "/dev/tpmrm0"} }
func hasNoTPMDevice() []string { return nil }
func reasonFor(s []Support, mode string) (Support, bool) {
	for _, x := range s {
		if x.Mode == mode {
			return x, true
		}
	}
	return Support{}, false
}

func TestDetectReportsSupportAndReasons(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name          string
		fake          *fakeCreds
		devices       func() []string
		wantTPM       bool
		wantHost      bool
		tpmReasonHas  string
		hostReasonHas string
	}{
		{name: "tpm host with vtpm", fake: &fakeCreds{}, devices: hasTPMDevice, wantTPM: true, wantHost: true},
		{name: "no tpm device", fake: &fakeCreds{}, devices: hasNoTPMDevice,
			wantHost: true, tpmReasonHas: "/dev/tpm*"},
		{name: "no tpm2 in firmware", fake: &fakeCreds{hasTPM2: "no\n-firmware\n+driver\n", tpmFails: true},
			devices: hasTPMDevice, wantHost: true, tpmReasonHas: "-firmware"},
		{name: "systemd too old", fake: &fakeCreds{version: "systemd 249 (249.11-1)\n"}, devices: hasTPMDevice,
			tpmReasonHas: "systemd 250 or newer", hostReasonHas: "systemd 250 or newer"},
		{name: "systemd-creds missing", fake: &fakeCreds{notFound: true}, devices: hasTPMDevice,
			tpmReasonHas: "systemd-creds is not available", hostReasonHas: "systemd-creds is not available"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detector{Run: c.fake.run, TPMDevices: c.devices}.Detect(ctx)
			if len(got) != len(AllModes) {
				t.Fatalf("Detect reported %d modes, want %d", len(got), len(AllModes))
			}
			tpm, _ := reasonFor(got, ModeTPM)
			host, _ := reasonFor(got, ModeHostKey)
			if tpm.Supported != c.wantTPM {
				t.Errorf("tpm supported = %v, want %v (reason %q)", tpm.Supported, c.wantTPM, tpm.Reason)
			}
			if host.Supported != c.wantHost {
				t.Errorf("host supported = %v, want %v (reason %q)", host.Supported, c.wantHost, host.Reason)
			}
			for _, p := range []struct {
				s    Support
				want string
			}{{tpm, c.tpmReasonHas}, {host, c.hostReasonHas}} {
				if p.want == "" {
					continue
				}
				if !strings.Contains(p.s.Reason, p.want) {
					t.Errorf("%s reason %q does not explain %q", p.s.Mode, p.s.Reason, p.want)
				}
			}
			// An unsupported mode must always say why, and a supported
			// one must not invent a reason.
			for _, s := range got {
				if !s.Supported && strings.TrimSpace(s.Reason) == "" {
					t.Errorf("%s is unsupported with no reason", s.Mode)
				}
				if s.Supported && s.Reason != "" {
					t.Errorf("%s is supported but carries reason %q", s.Mode, s.Reason)
				}
			}
			// The session-only and plaintext modes never depend on the
			// host's TPM or systemd version.
			for _, mode := range []string{ModePrompt, ModeEnv, ModeFile} {
				if s, _ := reasonFor(got, mode); !s.Supported {
					t.Errorf("%s must always be available, got %q", mode, s.Reason)
				}
			}
		})
	}
}

// An unavailable preferred mode is refused by name. Nothing substitutes
// plaintext for it.
func TestAvailableRefusesUnsupportedModeWithoutFallback(t *testing.T) {
	d := Detector{Run: (&fakeCreds{}).run, TPMDevices: hasNoTPMDevice}
	err := d.Available(context.Background(), ModeTPM)
	if err == nil {
		t.Fatal("Available must refuse tpm on a host with no TPM device")
	}
	if !strings.Contains(err.Error(), ModeTPM) || !strings.Contains(err.Error(), "/dev/tpm*") {
		t.Fatalf("refusal must name the mode and the reason: %v", err)
	}
	if strings.Contains(err.Error(), "using "+ModeFile) || strings.Contains(err.Error(), "falling back") {
		t.Fatalf("refusal must not offer a fallback: %v", err)
	}
	if err := d.Available(context.Background(), ModeHostKey); err != nil {
		t.Fatalf("host-key mode must remain available without a TPM: %v", err)
	}
	if err := d.Available(context.Background(), "nonsense"); err == nil {
		t.Fatal("an unknown mode must be refused")
	}
}

func TestSealRoundTripPerMode(t *testing.T) {
	const secret = "s3cr3t-postgres-password"
	for _, mode := range []string{ModeTPM, ModeHostKey} {
		t.Run(mode, func(t *testing.T) {
			f := &fakeCreds{}
			dir := filepath.Join(t.TempDir(), "credentials")
			m := &Manager{Mode: mode, Dir: dir, Run: f.run}
			s := Spec{Name: "postgres-password", Purpose: "database"}

			createdDir, err := m.Store(context.Background(), s, secret)
			if err != nil || !createdDir {
				t.Fatalf("Store: %v createdDir=%v", err, createdDir)
			}

			blob, err := os.ReadFile(filepath.Join(dir, "postgres-password.cred"))
			if err != nil {
				t.Fatalf("no sealed file: %v", err)
			}
			if strings.Contains(string(blob), secret) {
				t.Fatal("the stored file contains the plaintext credential")
			}
			if want := "--with-key=" + keyFor(mode); !strings.Contains(strings.Join(f.argv[0], " "), want) {
				t.Fatalf("encrypt did not use %s: %v", want, f.argv[0])
			}

			// Read back through a fresh Manager so the session cache
			// cannot answer instead of the decryption path.
			m2 := &Manager{Mode: mode, Dir: dir, Run: f.run}
			got, err := m2.Get(s)
			if err != nil || got != secret {
				t.Fatalf("Get = %q, %v; want the stored value", got, err)
			}
			if miss := m2.Missing([]Spec{s}); len(miss) != 0 {
				t.Fatalf("a stored credential must not be reported missing: %v", miss)
			}
		})
	}
}

func TestPathIsPerMode(t *testing.T) {
	s := Spec{Name: "postgres-password"}
	for mode, want := range map[string]string{
		ModeTPM:     "/d/postgres-password.cred",
		ModeHostKey: "/d/postgres-password.cred",
		ModeFile:    "/d/postgres-password",
		ModePrompt:  "",
		ModeEnv:     "",
	} {
		if got := (&Manager{Mode: mode, Dir: "/d"}).Path(s); got != want {
			t.Errorf("%s: Path = %q, want %q", mode, got, want)
		}
	}
}

func TestMissingReportsAnUnsealedCredential(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	m := &Manager{Mode: ModeTPM, Dir: dir, Run: (&fakeCreds{}).run}
	s := Spec{Name: "cloudflare-api-token"}
	miss := m.Missing([]Spec{s})
	if len(miss) != 1 || !strings.Contains(miss[0], "cloudflare-api-token") {
		t.Fatalf("missing = %v", miss)
	}
	if strings.Contains(miss[0], "plaintext") {
		t.Fatalf("the instruction must not push the operator to plaintext: %q", miss[0])
	}
}

// The plaintext value must never be an argument: arguments are visible in
// ps and in shell history.
func TestSecretNeverAppearsInAnArgument(t *testing.T) {
	const secret = "argv-must-never-hold-this"
	f := &fakeCreds{}
	dir := filepath.Join(t.TempDir(), "credentials")
	m := &Manager{Mode: ModeTPM, Dir: dir, Run: f.run}
	s := Spec{Name: "postgres-password"}
	if _, err := m.Store(context.Background(), s, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Manager{Mode: ModeTPM, Dir: dir, Run: f.run}).Get(s); err != nil {
		t.Fatal(err)
	}
	if len(f.argv) != 2 {
		t.Fatalf("want one encrypt and one decrypt call, got %v", f.argv)
	}
	for i, call := range f.argv {
		for _, a := range call {
			if strings.Contains(a, secret) {
				t.Fatalf("call %d passed the credential as an argument: %v", i, call)
			}
		}
	}
	// ...and it must have travelled through stdin instead, or the test
	// above proves nothing.
	if f.stdin[0] != secret {
		t.Fatalf("the credential did not reach the command through stdin: %q", f.stdin[0])
	}
}

func TestFailedSealLeaksNothingAndStoresNothing(t *testing.T) {
	const secret = "never-print-me"
	f := &fakeCreds{sealErr: errors.New("exit status 1"), echo: true}
	dir := filepath.Join(t.TempDir(), "credentials")
	m := &Manager{Mode: ModeTPM, Dir: dir, Run: f.run}
	s := Spec{Name: "postgres-password"}

	_, err := m.Store(context.Background(), s, secret)
	if err == nil {
		t.Fatal("a failed seal must be an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error carries the credential: %v", err)
	}
	if !strings.Contains(err.Error(), "postgres-password") {
		t.Fatalf("the error must name the credential: %v", err)
	}
	// Nothing at all is written: no sealed file, and above all no
	// plaintext one.
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) > 0 {
		t.Fatalf("a failed seal left files behind: %v", entries)
	}
	// The same failure with a plaintext value must not become file mode.
	if m.Mode != ModeTPM {
		t.Fatalf("the mode changed to %q after a failure", m.Mode)
	}
}

func TestDecryptFailureIsReportedNotEmpty(t *testing.T) {
	const secret = "postgres-password-value"
	seed := &fakeCreds{}
	dir := filepath.Join(t.TempDir(), "credentials")
	s := Spec{Name: "postgres-password"}
	if _, err := (&Manager{Mode: ModeTPM, Dir: dir, Run: seed.run}).Store(context.Background(), s, secret); err != nil {
		t.Fatal(err)
	}

	t.Run("decrypt fails", func(t *testing.T) {
		f := &fakeCreds{openErr: errors.New("exit status 1"), echo: true}
		v, err := (&Manager{Mode: ModeTPM, Dir: dir, Run: f.run}).Get(s)
		if err == nil {
			t.Fatal("a failed decrypt must be an error, not an empty credential")
		}
		if v != "" {
			t.Fatalf("a failed decrypt returned a value: %q", v)
		}
		for _, want := range []string{"postgres-password", "re-supply"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error must mention %q: %v", want, err)
			}
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error carries the credential: %v", err)
		}
	})

	t.Run("decrypt returns nothing", func(t *testing.T) {
		f := &fakeCreds{empty: true}
		v, err := (&Manager{Mode: ModeTPM, Dir: dir, Run: f.run}).Get(s)
		if err == nil || v != "" {
			t.Fatalf("an empty decrypt must fail, got %q, %v", v, err)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Fatalf("the error must say the value was empty: %v", err)
		}
	})

	t.Run("no credential stored", func(t *testing.T) {
		f := &fakeCreds{}
		empty := filepath.Join(t.TempDir(), "credentials")
		v, err := (&Manager{Mode: ModeTPM, Dir: empty, Run: f.run}).Get(s)
		if err == nil || v != "" {
			t.Fatalf("a missing credential must fail, got %q, %v", v, err)
		}
	})

	t.Run("blob sealed under another name", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "credentials")
		f := &fakeCreds{}
		m := &Manager{Mode: ModeTPM, Dir: other, Run: f.run}
		if _, err := m.Store(context.Background(), Spec{Name: "cloudflare-api-token"}, "token"); err != nil {
			t.Fatal(err)
		}
		// Rename the blob so it claims to be the database password.
		if err := os.Rename(filepath.Join(other, "cloudflare-api-token.cred"),
			filepath.Join(other, "postgres-password.cred")); err != nil {
			t.Fatal(err)
		}
		if v, err := (&Manager{Mode: ModeTPM, Dir: other, Run: f.run}).Get(s); err == nil {
			t.Fatalf("a blob sealed under another name must not decrypt, got %q", v)
		}
	})
}

func TestSealedFilesAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	m := &Manager{Mode: ModeHostKey, Dir: dir, Run: (&fakeCreds{}).run}
	if _, err := m.Store(context.Background(), Spec{Name: "postgres-password"}, "v"); err != nil {
		t.Fatal(err)
	}
	d, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode().Perm() != 0o700 {
		t.Fatalf("credential directory mode %v, want 0700", d.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(dir, "postgres-password.cred"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("sealed file mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestStoreRefusesNonPersistentModesAndEmptyValues(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	for _, mode := range []string{ModePrompt, ModeEnv, ""} {
		m := &Manager{Mode: mode, Dir: dir, Run: (&fakeCreds{}).run}
		if _, err := m.Store(context.Background(), Spec{Name: "x"}, "v"); err == nil {
			t.Fatalf("mode %q stores nothing and must refuse", mode)
		}
	}
	m := &Manager{Mode: ModeTPM, Dir: dir, Run: (&fakeCreds{}).run}
	if _, err := m.Store(context.Background(), Spec{Name: "x"}, ""); err == nil {
		t.Fatal("an empty credential must never be stored")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("a refused store must not create the credential directory")
	}
}

// Store in file mode is the existing plaintext path, unchanged.
func TestStoreInFileModeStaysPlaintextFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	m := &Manager{Mode: ModeFile, Dir: dir}
	s := Spec{Name: "postgres-password"}
	if _, err := m.Store(context.Background(), s, "value-x"); err != nil {
		t.Fatal(err)
	}
	if v, err := (&Manager{Mode: ModeFile, Dir: dir}).Get(s); err != nil || v != "value-x" {
		t.Fatalf("got %q, %v", v, err)
	}
}

func TestDescribeCoversEveryMode(t *testing.T) {
	for _, mode := range AllModes {
		e := Describe(mode)
		if e.Mode != mode {
			t.Fatalf("Describe(%q).Mode = %q", mode, e.Mode)
		}
		fields := map[string]string{
			"Short": e.Short, "Protection": e.Protection,
			"UnattendedReboot": e.UnattendedReboot, "ReplacementHost": e.ReplacementHost,
			"Backup": e.Backup,
		}
		for name, field := range fields {
			if strings.TrimSpace(field) == "" {
				t.Errorf("%s: %s is empty", mode, name)
			}
		}
		d := Detail(mode)
		for _, want := range []string{"Protection:", "Unattended reboot recovery:", "Replacement host:", "Backup implication:"} {
			if !strings.Contains(d, want) {
				t.Errorf("%s: Detail is missing %q", mode, want)
			}
		}
		if Explain(mode) != e.Short {
			t.Errorf("%s: Explain must be the short line", mode)
		}
	}
	if Explain("nonsense") != "unknown mode" || Detail("nonsense") != "unknown mode" {
		t.Error("an unknown mode must say so")
	}
}

func TestExplanationsAreHonestAboutTheirLimits(t *testing.T) {
	// Prompt mode cannot recover unattended, and must say so.
	if p := Describe(ModePrompt).UnattendedReboot; !strings.HasPrefix(p, "No.") {
		t.Errorf("prompt mode must state plainly that it cannot recover unattended: %q", p)
	}
	if p := Describe(ModeEnv).UnattendedReboot; strings.HasPrefix(p, "Yes.") {
		t.Errorf("env mode does not recover on its own: %q", p)
	}
	// A virtual TPM is protected by the hypervisor, and sealed credentials
	// do not move to a replacement host. Overselling either is the failure
	// this test exists to prevent.
	tpm := Describe(ModeTPM)
	for _, want := range []string{"hypervisor", "virtual"} {
		if !strings.Contains(strings.ToLower(tpm.Protection), want) {
			t.Errorf("the TPM protection level must mention %q: %q", want, tpm.Protection)
		}
	}
	if !strings.HasPrefix(tpm.ReplacementHost, "No.") || !strings.Contains(tpm.ReplacementHost, "Re-supply") {
		t.Errorf("TPM replacement-host behaviour must be stated plainly: %q", tpm.ReplacementHost)
	}
	if !strings.Contains(Describe(ModeHostKey).ReplacementHost, "credential.secret") {
		t.Errorf("host-key mode must say what would have to move: %q", Describe(ModeHostKey).ReplacementHost)
	}
	// Plaintext must never be described as anything but plaintext.
	f := Describe(ModeFile)
	if !strings.Contains(f.Protection, "Plaintext") || !strings.Contains(f.Backup, "clear") {
		t.Errorf("plaintext mode must not be oversold: %+v", f)
	}
	for _, mode := range []string{ModeTPM, ModeHostKey} {
		if !strings.Contains(Describe(mode).UnattendedReboot, "no provisioning binary") {
			t.Errorf("%s must state that recovery needs no provisioning binary", mode)
		}
	}
}

// No explanation, reason or error may contain a credential value. This is a
// blanket check over everything this package renders for a human.
func TestRenderedTextNeverContainsACredential(t *testing.T) {
	const secret = "text-must-never-contain-this"
	f := &fakeCreds{echo: true, sealErr: errors.New("boom")}
	dir := filepath.Join(t.TempDir(), "credentials")
	m := &Manager{Mode: ModeTPM, Dir: dir, Run: f.run}
	_, storeErr := m.Store(context.Background(), Spec{Name: "postgres-password"}, secret)

	texts := []string{fmt.Sprint(storeErr)}
	for _, mode := range AllModes {
		texts = append(texts, Detail(mode), Explain(mode))
	}
	d := Detector{Run: f.run, TPMDevices: hasNoTPMDevice}
	for _, s := range d.Detect(context.Background()) {
		texts = append(texts, s.Reason)
	}
	for _, txt := range texts {
		if strings.Contains(txt, secret) {
			t.Fatalf("rendered text contains a credential: %q", txt)
		}
	}
}
