package stack

import (
	"strings"
	"testing"
)

func TestStartupOutputStreamsPartialLinesAndBoundsDiagnostics(t *testing.T) {
	var lines []string
	w := eventWriter{emit: func(s string) { lines = append(lines, s) }}
	w.Write([]byte("Container app Crea"))
	w.Write([]byte("ting\rContainer app Healthy\n"))
	w.flush()
	if len(lines) != 2 || lines[0] != "Container app Creating" || lines[1] != "Container app Healthy" {
		t.Fatalf("bad startup events: %v", lines)
	}
	w.Write([]byte(strings.Repeat("x", 2<<20)))
	w.flush()
	if w.output.Len() > 1<<20 || len(lines[2]) > 8192 {
		t.Fatal("output was not bounded")
	}
}
