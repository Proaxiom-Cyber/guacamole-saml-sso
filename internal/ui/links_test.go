package ui

import (
	"strings"
	"testing"
)

func TestTransientLinkIsClickableAndExpires(t *testing.T) {
	w := &Wizard{challenge: "Open https://example.com/start/fixture\nApprove access."}
	got := w.linkify(signInLinkLabel)
	if !strings.Contains(got, "\x1b]8;;https://example.com/start/fixture\x1b\\") {
		t.Fatal("missing hyperlink")
	}
	w.challenge = ""
	if w.linkify(signInLinkLabel) != signInLinkLabel {
		t.Fatal("expired link retained")
	}
}
func TestChallengeLinkRejectsUnsafeSchemes(t *testing.T) {
	for _, s := range []string{"file:///etc/passwd", "javascript:alert(1)", "https://example.com/\x1b]bad"} {
		if challengeURL(s) != "" {
			t.Fatal("unsafe link")
		}
	}
}

func TestLongChallengeURLIsNotDisplayedAsWrappedText(t *testing.T) {
	u, _, _ := newTestUI("")
	w := u.wiz
	w.cols, w.rows = 100, 36
	target := "https://example.com/start/" + strings.Repeat("abcdef", 40)
	w.challenge = "Open this address:\n" + target + "\nApprove access."
	frame := strings.Join(w.frame(nil), "\n")
	if strings.Contains(frame, "https://example.com/start/") {
		t.Fatal("raw URL can still be truncated by terminal selection")
	}
	if !strings.Contains(frame, signInLinkLabel) {
		t.Fatal("missing short link label")
	}
	if !strings.Contains(w.linkify(signInLinkLabel), target) {
		t.Fatal("hyperlink lost part of its target")
	}
}

func TestSignInLinkHasVisibleAffordanceAndColour(t *testing.T) {
	w := &Wizard{challenge: "Open https://example.com/start/fixture", colour: true}
	got := w.linkify(signInLinkLabel)
	if !strings.Contains(got, "\x1b[1;4;96m[ OPEN SIGN-IN PAGE ]") {
		t.Fatal("link lacks bold underline and distinct colour")
	}
	w.colour = false
	got = w.linkify(signInLinkLabel)
	if strings.Contains(got, "\x1b[1;") || !strings.Contains(got, "[ OPEN SIGN-IN PAGE ]") {
		t.Fatal("plain mode must retain a visible link label without colour")
	}
}

func TestCompactSignInLinkRetainsCompleteTarget(t *testing.T) {
	u, _, _ := newTestUI("")
	w := u.wiz
	w.cols, w.rows = 48, 30
	target := "https://example.com/start/" + strings.Repeat("a", 200)
	w.challenge = "Open this address:\n" + target
	frame := strings.Join(w.frame(nil), "\n")
	if !strings.Contains(frame, signInLinkLabel) {
		t.Fatal("compact view wrapped the clickable label")
	}
	if !strings.Contains(w.linkify(frame), target) {
		t.Fatal("compact hyperlink lost its full target")
	}
	if !strings.Contains(frame, "Ctrl-Y") {
		t.Fatal("missing copy action")
	}
}

func TestCopyKeyOnlyActsDuringBrowserWait(t *testing.T) {
	u, out, _ := newTestUI("")
	w := u.wiz
	w.challenge = "Open https://example.com/start/fixture"
	if !w.viewKey('c') || !strings.Contains(out.String(), "\x1b]52;c;") {
		t.Fatal("C did not request clipboard copy")
	}
	out.Reset()
	w.waiting = true
	if w.viewKey('c') || out.Len() != 0 {
		t.Fatal("copy shortcut consumed a normal prompt key")
	}
	w.waiting = false
	w.challenge = ""
	if w.viewKey('c') {
		t.Fatal("copy shortcut active without a sign-in link")
	}
}
