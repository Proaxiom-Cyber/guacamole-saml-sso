package main

import (
	"bufio"
	"bytes"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
	"strings"
	"testing"
)

func TestMainMenuSelectsLifecycleWithoutRunningIt(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"s\n", "setup"}, {"t\n", "teardown"}, {"q\n", ""}, {"v\nb\nt\n", "teardown"}} {
		var out bytes.Buffer
		u := &ui.UI{Interactive: true, In: bufio.NewReader(strings.NewReader(tc.input)), Out: &out}
		got, err := mainMenu(u, t.TempDir())
		if err != nil || got != tc.want {
			t.Fatalf("got %q, %v; want %q", got, err, tc.want)
		}
	}
}
