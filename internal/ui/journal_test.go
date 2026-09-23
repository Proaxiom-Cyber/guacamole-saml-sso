package ui

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalKeepsUsefulEventsButExcludesSecretsAndChallenges(t *testing.T) {
	u := &UI{Out: &bytes.Buffer{}, In: bufio.NewReader(strings.NewReader("")), Interactive: true, Secret: func(string) (string, error) { return "fixture-password", nil }}
	if err := u.StartLog(t.TempDir(), "setup"); err != nil {
		t.Fatal(err)
	}
	u.SecretReader()("Hidden passphrase")
	u.PhaseStart("entra-signin")
	u.Transient("Code: DEVICE-FIXTURE")
	u.Say("Certificate registered. client_secret=unknown-fixture")
	u.Say("Reflected credential: fixture-password")
	u.Say("\x1b[31mstatus\x1b[0m\r\nsecond line")
	u.FinishLog(errors.New("connection timed out"))
	u.FinishLog(nil)
	b, err := os.ReadFile(u.LogPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"fixture-password", "unknown-fixture", "DEVICE-FIXTURE", "\x1b", "\r"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("log contains excluded content: %s", forbidden)
		}
	}
	for _, required := range []string{"START    | entra-signin", "Certificate registered", "ERROR    | entra-signin             | connection timed out", "[redacted]"} {
		if !strings.Contains(string(b), required) {
			t.Fatalf("missing event %s", required)
		}
	}
	info, _ := os.Stat(u.LogPath())
	if info.Mode().Perm() != 0600 {
		t.Fatal("log is not owner-only")
	}
	if strings.Count(u.Out.(*bytes.Buffer).String(), "Session log:") != 1 {
		t.Fatal("closing the log printed duplicate summaries")
	}
}
func TestJournalRefusesSharedOrLinkedDirectories(t *testing.T) {
	for _, link := range []bool{true, false} {
		t.Run(map[bool]string{true: "link", false: "shared"}[link], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "logs")
			if link {
				os.Symlink(t.TempDir(), path)
			} else {
				os.Mkdir(path, 0755)
			}
			u := &UI{Out: &bytes.Buffer{}}
			if err := u.StartLog(dir, "setup"); err == nil {
				t.Fatal("accepted unsafe log directory")
			}
		})
	}
}
