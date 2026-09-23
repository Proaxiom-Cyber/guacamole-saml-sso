package ui

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

const signInLinkLabel = "[ OPEN SIGN-IN PAGE ]"

func challengeURL(challenge string) string {
	for _, field := range strings.Fields(challenge) {
		parsed, err := url.Parse(field)
		if err == nil && parsed.Scheme == "https" && parsed.Host != "" && !strings.ContainsAny(field, "\x1b\x07") {
			return field
		}
	}
	return ""
}

// OSC 8 delegates opening to the operator's terminal, including over SSH.
// The link remains transient: it is never copied into history or the log.
func (w *Wizard) linkify(line string) string {
	target := challengeURL(w.challenge)
	if target == "" || !strings.Contains(line, signInLinkLabel) {
		return line
	}
	label := signInLinkLabel
	if w.colour {
		label = "\x1b[1;4;96m" + label + "\x1b[0m"
	}
	return strings.Replace(line, signInLinkLabel, "\x1b]8;;"+target+"\x1b\\"+label+"\x1b]8;;\x1b\\", 1)
}

// OSC 52 asks the local terminal to copy, even when the application runs over SSH.
// Terminals may refuse it; never claim clipboard confirmation we cannot receive.
func (w *Wizard) copyLinkLocked(target string) {
	fmt.Fprintf(w.out, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(target)))
	w.copyNotice = "Copy requested. If nothing copies, press L to select the plain-text address."
}

// Write the URL as one uninterrupted logical line. The terminal handles visual
// wrapping, so selection can copy the complete address without pane borders or
// inserted newlines. Do not send the challenge to event history or a log.
func (w *Wizard) renderPlainLinkLocked() bool {
	target := challengeURL(w.challenge)
	if target == "" {
		return false
	}
	identity := fmt.Sprintf("%dx%d:%s", w.cols, w.rows, w.challenge)
	if identity == w.plainLinkFrame {
		return true
	}
	fmt.Fprint(w.out, homeAndClear)
	fmt.Fprint(w.out, "SIGN-IN LINK — SELECT AND COPY\r\n\r\nSelect the address below, then paste it into your browser.\r\nIn PuTTY, selecting text normally copies it.\r\nB or Enter returns to setup. Sign-in continues while this view is open.\r\n\r\n")
	fmt.Fprint(w.out, target)
	fmt.Fprint(w.out, "\r\n\r\n")
	// Keep Microsoft's device code and provider instructions available too.
	instructions := strings.Replace(w.challenge, target, "(address shown above)", 1)
	fmt.Fprint(w.out, strings.ReplaceAll(instructions, "\n", "\r\n"))
	w.plainLinkFrame = identity
	return true
}
