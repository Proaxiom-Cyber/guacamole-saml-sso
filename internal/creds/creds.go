// Package creds selects and supplies deployment credentials.
//
// Persistent modes: systemd-creds sealed against the TPM and the host key
// (tpm), sealed against the host key alone (host), and explicitly approved
// owner-only plaintext files (file). Session-only modes: hidden prompts
// (prompt) and process environment input (env).
//
// Values live in process memory. They never enter deployment state, logs, or
// command arguments: a command argument is visible in ps and in shell
// history, so every value passed to systemd-creds or to Compose travels
// through stdin.
//
// An unavailable mode is reported, never replaced. Nothing here answers "no
// TPM on this host" by quietly writing plaintext instead. See sealed.go for
// detection and encryption, and boot.go for reboot recovery.
package creds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Modes. Plaintext is an approved exception for this project and is never a
// silent fallback: selecting it requires explicit confirmation.
const (
	ModePrompt = "prompt"
	ModeEnv    = "env"
	ModeFile   = "file"
)

// Modes is the pre-encryption mode set, kept while the session still offers
// only these three.
//
// Spec describes one credential the deployment needs. The registry grows as
// integration slices land.
type Spec struct {
	Name    string // kebab-case identifier, also the file name in file mode
	Purpose string
	// Generate marks a machine credential the tool can create itself. In
	// file mode a missing value is generated and stored instead of asked
	// for. In env and prompt modes the administrator supplies it, because
	// those modes give the tool nowhere durable to keep a generated value.
	Generate bool
}

// EnvVar is where env mode reads a spec from.
func (s Spec) EnvVar() string {
	return "GUACDEPLOY_CRED_" + strings.ToUpper(strings.ReplaceAll(s.Name, "-", "_"))
}

// Required is the V1 registry of deployment credentials.
var Required = []Spec{
	{Name: "cloudflare-api-token", Purpose: "Cloudflare Tunnel, DNS and Access configuration"},
	{Name: "postgres-password", Purpose: "local PostgreSQL database used by Guacamole", Generate: true},
}

// NewSecret returns a generated 256-bit hex secret for Generate specs.
func NewSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is not recoverable
	}
	return hex.EncodeToString(b[:])
}

// Manager resolves credential values for one selected mode.
type Manager struct {
	Mode string
	Dir  string // file mode: owner-only directory of one file per credential

	// ReadSecret reads one hidden line; injectable for tests. Set by the
	// UI layer in real runs.
	ReadSecret func(prompt string) (string, error)

	// Run executes systemd-creds for the encrypted modes; injectable for
	// tests. Defaults to ExecRunner.
	Run Runner

	values map[string]string // session cache; never serialised
}

// Remember keeps an accepted value for this process only. It does not write
// to the environment, the state file, or a credential file.
func (m *Manager) Remember(s Spec, value string) {
	if m.values == nil {
		m.values = map[string]string{}
	}
	m.values[s.Name] = value
}

// ErrUnattendedPrompt means prompt mode was asked for a value without a
// terminal. Prompt mode cannot support unattended operation.
var ErrUnattendedPrompt = errors.New("prompt-mode credentials require an interactive terminal")

// Missing reports which specs have no value available right now, with an
// instruction for supplying each. Prompt mode reports nothing as missing:
// values are collected at use time from the operator.
func (m *Manager) Missing(specs []Spec) []string {
	var out []string
	for _, s := range specs {
		switch m.Mode {
		case ModeEnv:
			if os.Getenv(s.EnvVar()) == "" {
				out = append(out, fmt.Sprintf("%s: set environment variable %s", s.Name, s.EnvVar()))
			}
		case ModeFile:
			if _, err := os.Stat(m.path(s)); err != nil && !s.Generate {
				out = append(out, fmt.Sprintf("%s: place the value in %s (owner-only permissions)", s.Name, m.path(s)))
			}
		case ModeTPM, ModeHostKey:
			if _, err := os.Stat(m.sealPath(s)); err != nil && !s.Generate {
				out = append(out, fmt.Sprintf("%s: no sealed credential at %s; run setup again to supply it", s.Name, m.sealPath(s)))
			}
		}
	}
	return out
}

func (m *Manager) path(s Spec) string { return filepath.Join(m.Dir, s.Name) }

// Get returns the credential value for in-memory use only. Callers must
// never log, persist, or place the value in command arguments.
func (m *Manager) Get(s Spec) (string, error) {
	if v, ok := m.values[s.Name]; ok {
		return v, nil
	}
	var v string
	switch m.Mode {
	case ModeEnv:
		v = os.Getenv(s.EnvVar())
		if v == "" {
			return "", fmt.Errorf("credential %s is not set: export %s", s.Name, s.EnvVar())
		}
	case ModeFile:
		b, err := os.ReadFile(m.path(s))
		if err != nil {
			return "", fmt.Errorf("credential %s is not available: %v", s.Name, err)
		}
		v = strings.TrimSpace(string(b))
	case ModeTPM, ModeHostKey:
		// Get has no context of its own: it is called from paths that
		// predate this slice. The timeout is here so a TPM that stops
		// answering fails the boot unit with a message instead of
		// hanging it forever.
		ctx, cancel := context.WithTimeout(context.Background(), unsealTimeout)
		defer cancel()
		var err error
		if v, err = m.unseal(ctx, s); err != nil {
			return "", err
		}
	case ModePrompt:
		if m.ReadSecret == nil {
			return "", ErrUnattendedPrompt
		}
		var err error
		v, err = m.ReadSecret(fmt.Sprintf("Enter %s (%s)", s.Name, s.Purpose))
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("no credential mode selected")
	}
	if m.values == nil {
		m.values = map[string]string{}
	}
	m.values[s.Name] = v
	return v, nil
}

// StoreFile writes one credential value as an owner-only file, creating the
// owner-only directory if needed. Returns whether this call created the
// directory, so the caller can record ownership of what it created.
func (m *Manager) StoreFile(s Spec, value string) (createdDir bool, err error) {
	if m.Mode != ModeFile {
		return false, errors.New("StoreFile is only valid in file mode")
	}
	if createdDir, err = m.ensureDir(); err != nil {
		return false, err
	}
	if err := os.WriteFile(m.path(s), []byte(value+"\n"), 0o600); err != nil {
		return createdDir, err
	}
	return createdDir, nil
}
