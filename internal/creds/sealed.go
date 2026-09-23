package creds

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Encrypted persistent modes. systemd-creds does the cryptography: it is
// already on every supported host, it is the mechanism systemd itself uses
// for unit credentials, and it needs no key material of our own.
const (
	// ModeTPM seals with the host key and the TPM together
	// (--with-key=host+tpm2). Preferred where a TPM exists.
	ModeTPM = "tpm"
	// ModeHostKey seals with the host key only (--with-key=host), for hosts
	// with no usable TPM.
	ModeHostKey = "host"
)

// AllModes is every credential mode, in the order to offer them. The
// preferred persistent mode comes first and plaintext comes last: plaintext
// is an approved exception, never the obvious default and never a silent
// fallback.
var AllModes = []string{ModeTPM, ModeHostKey, ModeEnv, ModePrompt, ModeFile}

// Persistent reports whether a mode keeps the credential across a reboot
// without a person and without anything injecting it.
func Persistent(mode string) bool {
	switch mode {
	case ModeTPM, ModeHostKey, ModeFile:
		return true
	}
	return false
}

// minSystemd is the first systemd release with `systemd-creds encrypt`.
const minSystemd = 250

// Runner executes a command with optional stdin, returning stdout and stderr
// separately. Same shape as schedule.Runner and backup.Runner, so one fake
// serves all three. Credential values travel through stdin only.
type Runner func(ctx context.Context, stdin, name string, args ...string) (stdout, stderr string, err error)

// ExecRunner is the real command seam.
func ExecRunner(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errs strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	return out.String(), errs.String(), err
}

// Support reports whether one mode can be used on this host.
type Support struct {
	Mode      string
	Supported bool
	Reason    string // why not, when unsupported; empty when supported
}

// Detector answers what this host actually supports. Both seams are
// injectable so tests never need a TPM or systemd.
type Detector struct {
	Run Runner
	// TPMDevices lists TPM character devices. Default globs /dev/tpm*.
	TPMDevices func() []string
}

func (d Detector) run() Runner {
	if d.Run != nil {
		return d.Run
	}
	return ExecRunner
}

func (d Detector) devices() []string {
	if d.TPMDevices != nil {
		return d.TPMDevices()
	}
	m, _ := filepath.Glob("/dev/tpm*")
	return m
}

// Detect reports every mode with the reason an unsupported one is
// unavailable. It runs two short commands at most.
func (d Detector) Detect(ctx context.Context) []Support {
	sysErr := d.systemdCreds(ctx)
	tpmErr := sysErr
	if tpmErr == nil {
		tpmErr = d.tpm2(ctx)
	}
	return []Support{
		support(ModeTPM, tpmErr),
		support(ModeHostKey, sysErr),
		{Mode: ModeEnv, Supported: true},
		{Mode: ModePrompt, Supported: true},
		{Mode: ModeFile, Supported: true},
	}
}

// Available returns nil when mode can be used here, and otherwise an error
// naming the reason. Callers must surface that error and let the operator
// choose another mode explicitly. Nothing in this package ever answers an
// unavailable mode by substituting a weaker one.
func (d Detector) Available(ctx context.Context, mode string) error {
	for _, s := range d.Detect(ctx) {
		if s.Mode != mode {
			continue
		}
		if s.Supported {
			return nil
		}
		return fmt.Errorf("credential mode %q is not available on this host: %s", mode, s.Reason)
	}
	return fmt.Errorf("unknown credential mode %q", mode)
}

func support(mode string, err error) Support {
	if err != nil {
		return Support{Mode: mode, Reason: err.Error()}
	}
	return Support{Mode: mode, Supported: true}
}

var systemdVersion = regexp.MustCompile(`systemd (\d+)`)

// systemdCreds checks that systemd-creds exists and is new enough to
// encrypt. Both encrypted modes need it.
func (d Detector) systemdCreds(ctx context.Context) error {
	stdout, stderr, err := d.run()(ctx, "", "systemd-creds", "--version")
	if err != nil {
		return fmt.Errorf("systemd-creds is not available on this host (%v: %s)",
			err, oneLine(stderr))
	}
	m := systemdVersion.FindStringSubmatch(stdout)
	if m == nil {
		return nil // it answered; an unrecognised version string is not a refusal
	}
	// Err on the side of reporting a problem: a parse that succeeds and
	// reads too low is a real refusal to encrypt.
	if v, convErr := strconv.Atoi(m[1]); convErr == nil && v < minSystemd {
		return fmt.Errorf("systemd-creds needs systemd %d or newer to encrypt credentials, this host has systemd %d",
			minSystemd, v)
	}
	return nil
}

// tpm2 checks for a TPM this host can actually seal against.
func (d Detector) tpm2(ctx context.Context) error {
	if len(d.devices()) == 0 {
		return errors.New("no TPM device is present (/dev/tpm* does not exist); a virtual machine needs a vTPM added to its configuration")
	}
	stdout, stderr, err := d.run()(ctx, "", "systemd-creds", "has-tpm2")
	answer := oneLine(stdout)
	if err != nil || answer != "yes" {
		detail := strings.TrimSpace(stdout)
		if detail == "" {
			detail = strings.TrimSpace(stderr)
		}
		return fmt.Errorf("the TPM is not usable for sealing; `systemd-creds has-tpm2` reports: %s",
			strings.Join(strings.Fields(detail), " "))
	}
	return nil
}

func oneLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// keyFor maps a mode to the systemd-creds key specification.
//
// ModeTPM uses host+tpm2 rather than tpm2 alone. Both are bound to this
// machine, so neither survives a move to a replacement host; host+tpm2 also
// requires the root-only host secret, so reading the TPM is not enough on
// its own. It is systemd's own default for this reason.
func keyFor(mode string) string {
	switch mode {
	case ModeTPM:
		return "host+tpm2"
	case ModeHostKey:
		return "host"
	}
	return ""
}

func (m *Manager) runner() Runner {
	if m.Run != nil {
		return m.Run
	}
	return ExecRunner
}

// sealPath is where one sealed credential lives. The blob is ciphertext,
// but it is still owner-only: it names the credential and its key policy.
func (m *Manager) sealPath(s Spec) string { return filepath.Join(m.Dir, s.Name+".cred") }

// Path is where the selected mode keeps this credential on disk, and an
// empty string for the modes that keep nothing. Callers use it to test
// whether a credential is already stored, which differs by mode: plaintext
// modes store <name> and encrypted modes store <name>.cred.
func (m *Manager) Path(s Spec) string {
	switch m.Mode {
	case ModeFile:
		return m.path(s)
	case ModeTPM, ModeHostKey:
		return m.sealPath(s)
	}
	return ""
}

// Store writes one credential value for a persistent mode: sealed with
// systemd-creds for the encrypted modes, and an owner-only plaintext file
// for the approved plaintext exception. Returns whether this call created
// the credential directory, so the caller can record what it created.
//
// A failed seal writes nothing. There is no plaintext fallback.
func (m *Manager) Store(ctx context.Context, s Spec, value string) (createdDir bool, err error) {
	switch m.Mode {
	case ModeFile:
		return m.StoreFile(s, value)
	case ModeTPM, ModeHostKey:
	default:
		return false, fmt.Errorf("credential mode %q stores nothing on disk", m.Mode)
	}
	if value == "" {
		return false, fmt.Errorf("refusing to store an empty value for credential %s", s.Name)
	}
	// Seal before touching the filesystem: a failure here must leave no
	// file at all, least of all a plaintext one.
	blob, err := m.seal(ctx, s, value)
	if err != nil {
		return false, err
	}
	if createdDir, err = m.ensureDir(); err != nil {
		return false, err
	}
	// Refresh tokens rotate. Replace the encrypted blob atomically so a
	// interrupted write does not truncate the last usable credential.
	f, err := os.CreateTemp(m.Dir, ".sealed-*")
	if err != nil {
		return createdDir, err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(blob); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return createdDir, err
	}
	if closeErr != nil {
		return createdDir, closeErr
	}
	if err = os.Rename(f.Name(), m.sealPath(s)); err != nil {
		return createdDir, err
	}
	dir, err := os.Open(m.Dir)
	if err != nil {
		return createdDir, err
	}
	defer dir.Close()
	return createdDir, dir.Sync()
}

// seal encrypts one value. The value goes in through stdin and never
// appears in an argument: arguments are visible in ps and in shell history.
func (m *Manager) seal(ctx context.Context, s Spec, value string) (string, error) {
	key := keyFor(m.Mode)
	stdout, stderr, err := m.runner()(ctx, value, "systemd-creds", "encrypt",
		"--name="+s.Name, "--with-key="+key, "-", "-")
	if err != nil {
		return "", fmt.Errorf("encrypting credential %s with key %s failed: %v\n%s",
			s.Name, key, err, redact(strings.TrimSpace(stderr), value))
	}
	if strings.TrimSpace(stdout) == "" {
		return "", fmt.Errorf("encrypting credential %s produced no output; refusing to store nothing", s.Name)
	}
	return stdout, nil
}

// unseal decrypts one credential. An unreadable or undecryptable credential
// is an error: an empty password reaching the stack would look like a
// working deployment until the database refused it.
func (m *Manager) unseal(ctx context.Context, s Spec) (string, error) {
	blob, err := os.ReadFile(m.sealPath(s))
	if err != nil {
		return "", fmt.Errorf("credential %s is not available: %v", s.Name, err)
	}
	stdout, stderr, err := m.runner()(ctx, string(blob), "systemd-creds", "decrypt",
		"--name="+s.Name, "-", "-")
	if err != nil {
		return "", fmt.Errorf("decrypting credential %s from %s failed: %v\n%s\n"+
			"The %s mode binds a credential to this host. A replacement host, a reset or removed TPM, "+
			"or a rebuilt /var/lib/systemd/credential.secret cannot decrypt it: re-supply the credential.",
			s.Name, m.sealPath(s), err, strings.TrimSpace(stderr), m.Mode)
	}
	if stdout == "" {
		return "", fmt.Errorf("decrypting credential %s from %s produced an empty value; refusing to continue",
			s.Name, m.sealPath(s))
	}
	return stdout, nil
}

// ensureDir creates the owner-only credential directory, reporting whether
// this call created it.
func (m *Manager) ensureDir() (bool, error) {
	if _, err := os.Stat(m.Dir); err == nil {
		return false, nil
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return false, err
	}
	return true, nil
}

// redact removes a known secret from text that is about to be shown. The
// commands we run do not echo their stdin, but a future one that did would
// otherwise put the credential in an error message.
func redact(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "[redacted]")
}

// unsealTimeout bounds a decrypt. A TPM that stops answering must fail the
// boot unit with a message, not hang it forever.
const unsealTimeout = 30 * time.Second

// Explanation is what the specification requires the tool to state about a
// mode before the operator selects it.
type Explanation struct {
	Mode string
	// Short is the one-line menu description.
	Short string
	// Protection is the honest protection level, including what it does
	// not protect against.
	Protection string
	// UnattendedReboot says whether the deployment recovers by itself.
	UnattendedReboot string
	// ReplacementHost says what happens when the deployment moves.
	ReplacementHost string
	// Backup says what a backup of the state directory does and does not
	// contain.
	Backup string
}

// Describe returns the full explanation for a mode. Mode is empty when the
// mode is unknown.
func Describe(mode string) Explanation {
	switch mode {
	case ModeTPM:
		return Explanation{Mode: mode,
			Short: "Encrypted with systemd-creds using the host key and the TPM together. Survives reboot without a person; does not survive a move to another host.",
			Protection: "systemd-creds seals the value with --with-key=host+tpm2, so both the TPM and the root-only host secret " +
				"(/var/lib/systemd/credential.secret) are needed to open it. A copy of the disk image, a backup, or the state " +
				"directory on its own is useless. It does not protect against root on this host. On a virtual machine the TPM " +
				"is virtual: the hypervisor holds its secrets, so an administrator of the hypervisor, or anyone who takes the " +
				"hypervisor's storage, can read them. This mode protects a stolen VM disk, not the platform that runs the VM.",
			UnattendedReboot: "Yes. The installed boot unit decrypts the credential and starts the stack with no person present " +
				"and with no provisioning binary on the host.",
			ReplacementHost: "No. A replacement VM has a different TPM and a different host key, so the sealed file cannot be " +
				"decrypted there, even from a restored backup. Re-supply every credential on the replacement host.",
			Backup: "A backup of the state directory copies the sealed file but not the key that opens it, so the backup leaks " +
				"nothing and recovers nothing. Keep an independent record of any credential you cannot recreate: the Cloudflare " +
				"API token, and the database password if you intend to restore a database backup onto a replacement host.",
		}
	case ModeHostKey:
		return Explanation{Mode: mode,
			Short: "Encrypted with systemd-creds using the host key only, for hosts with no usable TPM. Survives reboot without a person.",
			Protection: "systemd-creds seals the value with --with-key=host, against the root-only host secret at " +
				"/var/lib/systemd/credential.secret. A copy of the state directory on its own is useless, which a plaintext " +
				"file is not. It does not protect against root on this host, and anyone who takes both the state directory " +
				"and the host secret can decrypt it. There is no hardware binding: the secret is an ordinary file on the " +
				"same disk, so a full disk image contains both halves.",
			UnattendedReboot: "Yes. The installed boot unit decrypts the credential and starts the stack with no person present " +
				"and with no provisioning binary on the host.",
			ReplacementHost: "No, unless you copy /var/lib/systemd/credential.secret to the replacement host as well, which " +
				"moves the protection with it. Otherwise re-supply every credential on the replacement host.",
			Backup: "A backup of the state directory copies the sealed file, not the host secret. Treat it as unrecoverable " +
				"elsewhere unless you deliberately keep the host secret too, and keep an independent record of any credential " +
				"you cannot recreate.",
		}
	case ModeFile:
		return Explanation{Mode: mode,
			Short: "Owner-only plaintext files. An approved exception for this project, never a silent fallback. Survives reboot; a copy of the directory is a copy of the credentials.",
			Protection: "Plaintext, protected only by file permissions: mode 0600 files in a 0700 directory. Anyone who can " +
				"read the file reads the credential, including any process running as the owner and anyone with root. It is " +
				"an approved exception for this project and must always be an explicit choice.",
			UnattendedReboot: "Yes. The installed boot unit reads the file and starts the stack with no person present and with " +
				"no provisioning binary on the host.",
			ReplacementHost: "Yes. Restoring the credential directory to a replacement host restores working credentials, which " +
				"is the same reason a copy of that directory is as sensitive as the credentials themselves.",
			Backup: "Any backup, snapshot or disk image that includes the credential directory contains the credentials in the " +
				"clear. Protect those copies to the same standard as the host.",
		}
	case ModePrompt:
		return Explanation{Mode: mode,
			Short: "Hidden interactive prompts. Nothing is stored. Cannot recover after a reboot on its own.",
			Protection: "Nothing is written to disk. The value exists in process memory for one run and is never placed in " +
				"logs, state, or command arguments.",
			UnattendedReboot: "No. Prompt mode cannot provide unattended reboot recovery by itself: after a reboot a person must " +
				"run the command and type the value again. Choose an encrypted mode if the deployment must come back on its own.",
			ReplacementHost: "The operator supplies the values again, exactly as on any other host. Nothing is lost that was " +
				"not already being supplied by hand.",
			Backup: "Nothing to back up and nothing recoverable from a backup. A restored deployment waits for a person.",
		}
	case ModeEnv:
		return Explanation{Mode: mode,
			Short: "Values read from GUACDEPLOY_CRED_* environment variables at each invocation. This tool stores nothing and installs nothing that can supply them at boot.",
			Protection: "This tool stores nothing; the protection is whatever supplies the variables. A process environment " +
				"is readable by root, and putting the values in a unit file or a shell profile creates a plaintext copy this " +
				"tool does not manage and cannot protect.",
			UnattendedReboot: "Only if whatever supplies the variables also supplies them at boot. This tool installs no boot " +
				"unit for this mode, because the only way it could inject the values would be to write them to disk in " +
				"plaintext, which would be a silent downgrade.",
			ReplacementHost: "Whatever supplies the variables supplies them on the replacement host too. Nothing here has to move.",
			Backup:          "Nothing stored by this tool, so nothing in its backups. The supplying system keeps its own copies.",
		}
	}
	return Explanation{}
}

// Explain is the one-line description for a selection menu.
func Explain(mode string) string {
	if e := Describe(mode); e.Mode != "" {
		return e.Short
	}
	return "unknown mode"
}

// Detail renders the full explanation the specification requires the tool
// to show for the selected mode.
func Detail(mode string) string {
	e := Describe(mode)
	if e.Mode == "" {
		return "unknown mode"
	}
	return strings.Join([]string{
		"Protection: " + e.Protection,
		"Unattended reboot recovery: " + e.UnattendedReboot,
		"Replacement host: " + e.ReplacementHost,
		"Backup implication: " + e.Backup,
	}, "\n")
}
