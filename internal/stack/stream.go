package stack

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// StreamingRunner streams only Compose startup output. Database query output and
// credential commands keep their existing private capture path.
func StreamingRunner(emit func(string)) Runner {
	return func(ctx context.Context, stdin, name string, args ...string) (string, error) {
		startup := false
		for _, arg := range args {
			if arg == "up" {
				startup = true
				break
			}
		}
		if name != "docker" || !startup {
			return ExecRunner(ctx, stdin, name, args...)
		}
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(stdin)
		sink := &eventWriter{emit: emit}
		cmd.Stdout = sink
		cmd.Stderr = sink
		err := cmd.Run()
		sink.flush()
		return sink.output.String(), err
	}
}

type eventWriter struct {
	mu      sync.Mutex
	pending string
	output  strings.Builder
	emit    func(string)
}

func (w *eventWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Keep diagnostics bounded, independently of the on-screen history.
	if w.output.Len() < 1<<20 {
		_, _ = io.WriteString(&w.output, string(p[:min(len(p), (1<<20)-w.output.Len())]))
	}
	for i, c := range p {
		if c == '\n' || c == '\r' {
			if w.pending != "" {
				w.emit(w.pending)
				w.pending = ""
			}
		} else if len(w.pending) < 8192 {
			w.pending += string(p[i : i+1])
		}
	}
	return len(p), nil
}
func (w *eventWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending != "" {
		w.emit(w.pending)
		w.pending = ""
	}
}

// StartupLogs collects a bounded snapshot, including logs on failed startup.
func StartupLogs(ctx context.Context, run Runner, cfg Config, emit func(string)) {
	out, err := run(ctx, "", "docker", cfg.composeArgs("logs", "--no-color", "--tail", "80")...)
	if err != nil {
		emit("Startup logs unavailable; inspect Docker after resolving the startup error.")
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			emit(line)
		}
	}
}

// FollowStartupLogs polls bounded snapshots while startup is in progress.
// Cancellation joins the reader before the caller changes phases or closes logs.
func FollowStartupLogs(ctx context.Context, cfg Config, emit func(string)) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	since := time.Now().UTC().Format(time.RFC3339Nano)
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		seen := map[string]bool{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			out, err := ExecRunner(ctx, "", "docker", cfg.composeArgs("logs", "--no-color", "--timestamps", "--since", since, "--tail", "80")...)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(out, "\n") {
				if line != "" && !seen[line] {
					emit(line)
					seen[line] = true
				}
			}
			if len(seen) > 1000 {
				since = time.Now().UTC().Format(time.RFC3339Nano)
				seen = map[string]bool{}
			}
		}
	}()
	return func() { cancel(); <-done }
}
