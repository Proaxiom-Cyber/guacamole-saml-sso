package ui

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestWideLayoutUsesTerminalAndShowsLogTail(t *testing.T) {
	u, _, _ := newTestUI("")
	w := u.wiz
	w.cols = 200
	w.rows = 48
	u.PhaseStart("stack-up")
	for i := 0; i < 40; i++ {
		u.Say("Earlier event %d", i)
	}
	u.Say("Most recent event")
	frame := strings.Join(w.frame(nil), "\n")
	if w.width() != 199 || !strings.Contains(frame, "LIVE LOG") || !strings.Contains(frame, "Most recent event") {
		t.Fatal("wide live log missing")
	}
	w.viewKey(keyPageUp)
	frame = strings.Join(w.frame(nil), "\n")
	if !strings.Contains(frame, "LOG PAUSED") || strings.Contains(strings.Split(frame, "LOG PAUSED")[len(strings.Split(frame, "LOG PAUSED"))-1], "Most recent event") {
		t.Fatal("history did not scroll")
	}
	for i := 0; i < 20; i++ {
		w.viewKey(keyPageDown)
	}
	if !strings.Contains(strings.Join(w.frame(nil), "\n"), "LIVE LOG") {
		t.Fatal("live follow did not resume")
	}
}
func TestCopyChallengeUsesCompleteURLWithoutLogging(t *testing.T) {
	u, out, _ := newTestUI("")
	w := u.wiz
	target := "https://example.com/" + strings.Repeat("segment", 60)
	w.challenge = target
	if !w.viewKey(25) {
		t.Fatal("copy key not handled")
	}
	if !strings.Contains(out.String(), "\x1b]52;c;"+base64.StdEncoding.EncodeToString([]byte(target))+"\x07") {
		t.Fatal("complete clipboard request missing")
	}
	if len(w.log) != 0 {
		t.Fatal("challenge leaked into history")
	}
	w.challenge = ""
	out.Reset()
	w.viewKey(25)
	if out.Len() != 0 {
		t.Fatal("expired link copied")
	}
}
func TestDockerStatusKeepsLatestPerContainer(t *testing.T) {
	w := newWizard(nil, nil, 40, 140, false)
	w.trackDocker("[docker] Container app Creating")
	w.trackDocker("[docker] Container app Healthy")
	w.trackDocker("[docker] app | unrelated application output")
	if len(w.dockerOrder) != 1 || !strings.Contains(strings.Join(w.dockerLines(), "\n"), "Healthy") {
		t.Fatal("resource status lost")
	}
}
