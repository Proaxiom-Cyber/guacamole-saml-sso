package ui

import (
	"strings"
	"testing"
)

func TestReviewPhaseFollowsBackWithoutChangingCompletion(t *testing.T) {
	u, _, _ := newTestUI("")
	u.wiz.cols, u.wiz.rows = 140, 45
	u.PhaseList([]string{"host-preflight", "credential-mode", "credential-check"})
	u.PhaseDone("host-preflight")
	u.PhaseDone("credential-mode")
	u.PhaseStart("credential-check")
	backToCheck := u.ReviewPhase("credential-mode")
	frame := strings.Join(u.wiz.snapshot(), "\n")
	if !strings.Contains(frame, "> 02 Protect credentials") {
		t.Fatalf("wrong selected task:\n%s", frame)
	}
	backToMode := u.ReviewPhase("host-preflight")
	frame = strings.Join(u.wiz.snapshot(), "\n")
	if !strings.Contains(frame, "> 01 Check this host") {
		t.Fatalf("wrong previous task:\n%s", frame)
	}
	if u.wiz.state["host-preflight"] != phaseDone || u.wiz.state["credential-mode"] != phaseDone || u.wiz.active != "credential-check" {
		t.Fatal("review changed execution state")
	}
	backToMode()
	if u.wiz.viewedPhase != "credential-mode" {
		t.Fatal("forward did not return to protection")
	}
	backToCheck()
	if u.wiz.viewedPhase != "" {
		t.Fatal("review focus remained after returning")
	}
}
