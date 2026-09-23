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
	w.copyNotice = "Copy requested. If blocked, use the link menu to copy its address."
}
