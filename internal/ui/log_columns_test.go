package ui

import (
	"github.com/mattn/go-runewidth"
	"strings"
	"testing"
)

func TestLogWrapKeepsTimeInItsOwnColumn(t *testing.T) {
	lines := wrapped([]string{"12:34:56 | A long event that needs several continuation lines for a narrow terminal."}, 32)
	if !strings.HasPrefix(lines[0], "12:34:56 | ") {
		t.Fatal(lines)
	}
	if lines[len(lines)-1] != "" {
		t.Fatal("missing space between entries")
	}
	for _, line := range lines[1 : len(lines)-1] {
		if !strings.HasPrefix(line, "         | ") {
			t.Fatalf("misaligned continuation: %q", line)
		}
	}
	for _, line := range lines {
		if runewidth.StringWidth(line) > 32 {
			t.Fatal("log exceeds width")
		}
	}
}
