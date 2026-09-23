package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/host"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func TestRecoveryRetriesOnlyWhenChosen(t *testing.T) {
	for _, tc := range []struct {
		input string
		calls int
	}{{"r\n", 2}, {"q\n", 1}, {"v\nb\nq\n", 1}} {
		var output bytes.Buffer
		u := &ui.UI{Interactive: true, In: bufio.NewReader(strings.NewReader(tc.input)), Out: &output}
		calls := 0
		err := runWithRecovery(context.Background(), u, "setup", func() error {
			calls++
			if calls == 1 {
				return errors.New("temporary failure")
			}
			return nil
		})
		if calls != tc.calls {
			t.Fatalf("calls=%d want %d", calls, tc.calls)
		}
		if tc.calls == 2 && err != nil {
			t.Fatal(err)
		}
	}
}
func TestRebootExplainsNextCommandBeforeExit(t *testing.T) {
	var output bytes.Buffer
	u := &ui.UI{Interactive: true, In: bufio.NewReader(strings.NewReader("q\n")), Out: &output}
	err := runWithRecovery(context.Background(), u, "setup", func() error { return host.ErrRebootRequired })
	if !errors.Is(err, host.ErrRebootRequired) {
		t.Fatal(err)
	}
	for _, want := range []string{"Reboot required", "sudo reboot", "sudo /usr/local/bin/guacdeploy setup"} {
		if !strings.Contains(output.String(), want) {
			t.Fatal("missing " + want)
		}
	}
}
func TestUnattendedFailureDoesNotPromptOrRetry(t *testing.T) {
	var output bytes.Buffer
	u := &ui.UI{Out: &output}
	calls := 0
	err := runWithRecovery(context.Background(), u, "setup", func() error { calls++; return errors.New("failure") })
	if err == nil || calls != 1 || output.Len() != 0 {
		t.Fatal("unexpected unattended interaction")
	}
}

func TestIdentifierDomainErrorIsNotReportedAsDuplicate(t *testing.T) {
	title, help := recoveryGuidance(errors.New("graph POST /applications failed: Values of identifierUris property must use a verified domain (HostNameNotOnVerifiedDomain)"))
	if title != "Entra rejected the application identifier" || strings.Contains(help, "already exists") {
		t.Fatalf("misleading guidance: %s: %s", title, help)
	}
	title, _ = recoveryGuidance(errors.New("Another object with the same value for property identifierUris already exists"))
	if title != "Entra application already exists" {
		t.Fatalf("duplicate not recognized: %s", title)
	}
	title, _ = recoveryGuidance(errors.New("identifierUris: permission denied"))
	if title == "Entra application already exists" {
		t.Fatal("unrelated identifier error reported as duplicate")
	}
}
