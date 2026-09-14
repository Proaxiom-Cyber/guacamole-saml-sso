package ui

import (
	"strings"
	"testing"

	"github.com/mattn/go-runewidth"
)

func TestBrandMotionStopsForQuestionsAndReducedMotion(t *testing.T) {
	u, _, _ := newTestUI("")
	w := u.wiz
	w.cols, w.rows = 120, 36
	w.setPhase("host-preflight", phaseRunning)
	for _, reduced := range []string{"", "1"} {
		t.Setenv("GUACDEPLOY_REDUCED_MOTION", reduced)
		for _, busy := range []bool{false, true} {
			w.tick = 0
			a := strings.Join(w.brandHeader(119, "0 / 3 steps complete", busy), "\n")
			w.tick = 4
			b := strings.Join(w.brandHeader(119, "0 / 3 steps complete", busy), "\n")
			if (a != b) != (busy && reduced == "") {
				t.Fatalf("unexpected animation: busy=%v reduced=%q", busy, reduced)
			}
		}
	}
}

func TestBrandFitsAndPreservesPlainText(t *testing.T) {
	u, _, _ := newTestUI("")
	w := u.wiz
	w.colour = true
	for _, size := range [][2]int{{120, 36}, {80, 24}, {48, 16}} {
		w.cols, w.rows = size[0], size[1]
		for _, ascii := range []string{"", "1"} {
			t.Setenv("GUACDEPLOY_ASCII", ascii)
			frame := w.frame(nil)
			if len(frame) >= w.rows {
				t.Fatal("brand pushed frame beyond the terminal")
			}
			for _, line := range frame {
				if runewidth.StringWidth(line) >= w.cols {
					t.Fatal("brand exceeded terminal width")
				}
				if stripANSI(w.paint(line)) != line {
					t.Fatal("colour changed readable content")
				}
				if ascii != "" {
					for _, r := range line {
						if r > 127 {
							t.Fatalf("non-ASCII rune: %q", r)
						}
					}
				}
			}
		}
	}
}

func TestTaskProgressResetsForNextPhaseAndRejectsUnknownTotals(t *testing.T) {
	u, _, _ := newTestUI("")
	u.PhaseStart("host-preflight")
	u.TaskProgress("Network checks", 2, 3)
	if !strings.Contains(u.wiz.task.line(70), "2 / 3") {
		t.Fatal("measured progress absent")
	}
	u.TaskProgress("Unknown", 1, 0)
	if u.wiz.task.label != "Network checks" {
		t.Fatal("unknown total produced a progress bar")
	}
	u.PhaseStart("stack-up")
	if u.wiz.task.total != 0 {
		t.Fatal("previous phase progress leaked into next phase")
	}
}
