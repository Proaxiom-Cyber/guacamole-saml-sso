// Package creds selects and supplies deployment credentials. Values live in
// process memory for the session only; the durable modes are hidden prompts,
// environment input, and explicitly approved owner-only plaintext files.
// Values never enter deployment state, logs, or command arguments.
// Encrypted persistence across service restarts is a separate slice.
package creds

import (
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

var Modes = []string{ModePrompt, ModeEnv, ModeFile}

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

	values map[string]string // session cache; never serialised
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
	if _, err := os.Stat(m.Dir); os.IsNotExist(err) {
		if err := os.MkdirAll(m.Dir, 0o700); err != nil {
			return false, err
		}
		createdDir = true
	}
	if err := os.WriteFile(m.path(s), []byte(value+"\n"), 0o600); err != nil {
		return createdDir, err
	}
	return createdDir, nil
}

// Explain describes a mode and its unattended-operation requirements.
func Explain(mode string) string {
	switch mode {
	case ModePrompt:
		return "Hidden interactive prompts. Nothing is stored on disk. Unattended operation is not possible in this mode."
	case ModeEnv:
		return "Values are read from GUACDEPLOY_CRED_* environment variables supplied to each invocation. Unattended operation works when the caller injects the variables; nothing is stored on disk."
	case ModeFile:
		return "Owner-only plaintext files under the credential directory. An approved exception for this project, never a silent fallback. Unattended operation works; protect the directory and prefer encrypted storage once available."
	}
	return "unknown mode"
}
