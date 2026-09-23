package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-runewidth"
)

type phaseDescription struct{ Title, Purpose, Group string }

var phaseDescriptions = map[string]phaseDescription{
	"teardown-review":       {"Review removal plan", "Check ownership and choose which resources to remove.", "Teardown"},
	"teardown-remove":       {"Remove deployment resources", "Remove approved resources and save each result for recovery.", "Teardown"},
	"teardown-result":       {"Review teardown results", "Check what was removed, preserved, or needs another attempt.", "Teardown"},
	"initialise-deployment": {"Create deployment record", "Save progress on this host so interrupted work can resume.", "Prepare"},
	"host-preflight":        {"Check this host", "Check Rocky Linux, privileges and required network access.", "Prepare"},
	"credential-mode":       {"Protect credentials", "Choose how the host stores and supplies service credentials.", "Prepare"},
	"credential-check":      {"Check credentials", "Validate credentials before creating external resources.", "Prepare"},
	"configure-review":      {"Configure and review", "Collect answers, use Back to edit, then approve deployment.", "Configure"},
	"host-dependencies":     {"Prepare the host", "Install approved dependencies and check Docker Compose.", "Prepare"},
	"stack-configure":       {"Name your deployment", "Set the public hostname and the two access groups.", "Configure"},
	"cloudflare-select":     {"Connect Cloudflare", "Select the account and existing DNS zone for this deployment.", "Configure"},
	"cloudflare-tunnel":     {"Create the tunnel", "Create an owned tunnel with verified origin encryption.", "Configure"},
	"stack-render":          {"Prepare service files", "Write the configuration for Guacamole and its services.", "Services"},
	"stack-schema":          {"Prepare the database", "Create and validate the Guacamole database schema.", "Services"},
	"origin-certificate":    {"Secure the origin", "Issue the certificate and configure automatic renewal.", "Services"},
	"stack-up":              {"Start the services", "Start the containers and wait for their health checks.", "Services"},
	"boot-recovery":         {"Prepare reboot recovery", "Configure service startup after a host restart.", "Protect"},
	"backup-schedule":       {"Protect your data", "Choose backup protection, destination and retention.", "Protect"},
	"recording-schedule":    {"Manage recordings", "Set a storage budget and retention for completed recordings.", "Protect"},
	"stack-health":          {"Check the deployment", "Verify Guacamole through the local web server.", "Protect"},
	"entra-signin":          {"Connect Microsoft Entra", "Authorize setup, then configure Guacamole sign-in and access groups.", "Identity"},
	"cloudflare-dns":        {"Publish the hostname", "Create the DNS record for this deployment.", "Publish"},
	"cloudflare-access":     {"Protect public access", "Configure the Cloudflare Access policy and verify its rules.", "Publish"},
	"cloudflare-connect":    {"Bring the deployment online", "Connect the tunnel after the access checks pass.", "Publish"},
	"azure-destination":     {"Set up external backups", "Configure optional Azure storage for backups and recordings.", "Publish"},
}

func phaseInfo(name string) phaseDescription {
	if p, ok := phaseDescriptions[name]; ok {
		return p
	}
	if name == "" {
		return phaseDescription{"Welcome to Guacamole", "Set up a deployment, or continue saved work on this host.", "Setup"}
	}
	return phaseDescription{strings.ReplaceAll(name, "-", " "), "The installer records completed work as it runs.", "Setup"}
}
func (w *Wizard) width() int         { return max(1, w.cols-1) }
func fit(s string, width int) string { return runewidth.Truncate(s, max(0, width), "…") }
func pad(s string, width int) string {
	s = fit(s, width)
	return s + strings.Repeat(" ", max(0, width-runewidth.StringWidth(s)))
}
func elapsed(t time.Time) string {
	d := int(time.Since(t).Seconds())
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%02d:%02d", d/60, d%60)
}
func (w *Wizard) progress() string {
	count := map[string]int{}
	for _, n := range w.names {
		s := w.state[n]
		if s == "" {
			s = phaseWaiting
		}
		count[s]++
	}
	return fmt.Sprintf("Phases (%d): %d done, %d running, %d failed, %d already complete, %d to do", len(w.names), count[phaseDone], count[phaseRunning], count[phaseFailed], count[phaseSkipped], count[phaseWaiting])
}
func wrapped(blocks []string, width int) []string {
	var result []string
	for _, block := range blocks {
		for _, line := range strings.Split(cleanText(block), "\n") {
			if len(line) >= 11 && line[2] == ':' && line[5] == ':' && line[8:11] == " | " && width > 16 {
				parts := wrapLine(line[11:], width-11)
				for i, part := range parts {
					prefix := "         | "
					if i == 0 {
						prefix = line[:11]
					}
					result = append(result, prefix+part)
				}
				result = append(result, "")
			} else {
				result = append(result, wrapLine(line, width)...)
			}
		}
	}
	return result
}

// frame composes terminal-native panels from the available cell dimensions.
// The action pane owns the height. History and navigation never push it away.
func (w *Wizard) frame(prompt []string) []string {
	width := w.width()
	if w.cols < 48 || w.rows < 16 {
		if w.finalScreen {
			status := "Session finished."
			if len(w.summary) > 0 {
				status = w.summary[0]
			}
			return []string{fit(status, width), fit("Resize to read details.", width), fit("F: Exit to shell", width)}
		}
		return []string{fit("Resize to 48 x 16 to continue. Ctrl-C cancels.", width)}
	}
	active := w.active
	if w.viewedPhase != "" {
		active = w.viewedPhase
	}
	if active == "" && len(w.names) > 0 {
		active = w.names[0]
	}
	p := phaseInfo(active)
	if w.finalScreen {
		p = phaseDescription{"Session summary", "Review the outcome before returning to the shell.", "Summary"}
	}
	completed, index := 0, 0
	for i, n := range w.names {
		if w.state[n] == phaseDone || w.state[n] == phaseSkipped {
			completed++
		}
		if n == active {
			index = i
		}
	}
	total := len(w.names)
	barWidth := min(28, max(8, width/4))
	fill := 0
	if total > 0 {
		fill = barWidth * completed / total
	}
	solid, empty := "█", "░"
	if os.Getenv("GUACDEPLOY_ASCII") != "" {
		solid, empty = "=", "-"
	}
	bar := strings.Repeat(solid, fill) + strings.Repeat(empty, barWidth-fill)
	progress := fmt.Sprintf("%s  %d / %d steps complete", bar, completed, total)
	out := w.brandHeader(width, progress, w.state[active] == phaseRunning && len(prompt) == 0 && !w.details)
	sidebar := w.cols >= 104 && w.rows >= 26 && !w.details && !w.progressView
	sideWidth := 0
	if sidebar {
		sideWidth = 29
	}
	contentWidth := width - sideWidth - 4
	bodyHeight := w.rows - len(out) - 4
	var controls []string
	if !w.details && !w.progressView {
		for i, l := range prompt {
			if strings.HasPrefix(l, "> ") || strings.HasPrefix(l, "  [") {
				controls = wrapped(prompt[i:], contentWidth)
				prompt = prompt[:i]
				break
			}
		}
	}
	choiceWidth, helpWidth := contentWidth, 0
	var optionHelp []string
	if len(controls) > 0 && w.selectionHelp != "" && contentWidth >= 76 {
		choiceWidth = contentWidth / 2
		helpWidth = contentWidth - choiceWidth - 3
		controls = wrapped(controls, choiceWidth)
		optionHelp = wrapped([]string{"ABOUT THIS OPTION", "", w.selectionHelp}, helpWidth)
		for len(controls) < len(optionHelp) {
			controls = append(controls, "")
		}
	}
	// Actions stay visible while long instructions scroll independently.
	controlMax := max(3, bodyHeight/2)
	if len(controls) > 0 && strings.HasPrefix(controls[0], "> ") && !strings.HasPrefix(controls[0], "> [") {
		controlMax = max(3, bodyHeight-2)
	}
	if len(controls) > controlMax {
		focus := 0
		for i, l := range controls {
			if strings.HasPrefix(l, "> ") {
				focus = i
			}
		}
		controls = windowLines(controls, focus, controlMax)
	}
	if len(controls) > 0 {
		bodyHeight -= len(controls) + 1
	}
	paneHeight := 0
	if !w.details && !w.progressView && w.challenge == "" && bodyHeight >= 16 {
		paneHeight = max(6, bodyHeight/2)
		bodyHeight -= paneHeight
	}
	w.logPaneActive = paneHeight > 0
	var body []string
	if w.progressView {
		body = append(body, "Deployment progress", w.progress(), "")
		for i, n := range w.names {
			status := w.state[n]
			if status == "" {
				status = phaseWaiting
			}
			body = append(body, fmt.Sprintf("%02d  %s  %s", i+1, status, phaseInfo(n).Title))
		}
	} else if w.details {
		body = append(body, "Session history", w.progress(), "")
		if w.selectionHelp != "" {
			body = append(body, "ABOUT THIS OPTION", w.selectionHelp, "")
		}
		for _, n := range w.names {
			status := w.state[n]
			if status == "" {
				status = phaseWaiting
			}
			body = append(body, status+"  "+phaseInfo(n).Title+"  ("+n+")")
		}
		body = append(body, "", "Guidance", "")
		body = append(body, w.notes...)
		body = append(body, "", "Timestamped events", "")
		if len(w.log) == 0 {
			body = append(body, "No events yet.")
		} else {
			body = append(body, w.log...)
		}
		if w.logPath != "" {
			body = append(body, "", "Session log: "+w.logPath)
		}
	} else {
		activity := "READY"
		if w.state[active] == phaseRunning {
			spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"}[w.tick%8]
			if os.Getenv("GUACDEPLOY_ASCII") != "" {
				spinner = []string{"|", "/", "-", "\\"}[w.tick%4]
			}
			activity = "IN PROGRESS " + spinner + "  " + elapsed(w.phaseStarted)
			if w.rows >= 30 && width >= 79 {
				activity = "IN PROGRESS  " + elapsed(w.phaseStarted)
			}
		}
		if len(prompt) > 0 || len(controls) > 0 {
			activity = "YOUR TURN"
		}
		if w.challenge != "" {
			activity = "WAITING FOR BROWSER SIGN-IN"
		}
		if w.state[active] == phaseFailed {
			activity = "NEEDS ATTENTION"
		}
		if w.finalScreen {
			activity = "REVIEW AND FINISH"
		}
		if total > 0 && !w.finalScreen {
			body = append(body, fmt.Sprintf("%02d  %s", index+1, p.Title))
		} else {
			body = append(body, p.Title)
		}
		if len(prompt) == 0 && len(controls) == 0 {
			body = append(body, p.Purpose)
		}
		body = append(body, "", activity, "")
		if w.task.total > 0 && len(prompt) == 0 && len(controls) == 0 {
			body = append(body, w.task.line(contentWidth), "")
		}
		if len(w.dockerOrder) > 0 && len(prompt) == 0 {
			body = append(body, w.dockerLines()...)
		}
		if w.challenge != "" {
			challenge := w.challenge
			if target := challengeURL(challenge); target != "" {
				// A hard-wrapped URL looks selectable but terminal URL detection
				// may open only its first line. Show a short OSC 8 label instead.
				challenge = strings.Replace(challenge, target, signInLinkLabel, 1)
			}
			if challengeURL(w.challenge) != "" {
				body = append(body, "CONTINUE IN YOUR BROWSER", "", "[ C  COPY SIGN-IN LINK ]", "Press C, then paste into your browser.", "[ L  SHOW LINK AS PLAIN TEXT ]", "PuTTY: press L, then select the address to copy.", "Setup continues after you complete sign-in.", w.copyNotice, "", "Or use the clickable link below:")
			}
			body = append(body, challenge, "Ctrl-Y also copies the complete link.", "")
		}
		if len(prompt) > 0 || len(controls) > 0 {
			body = append(body, prompt...)
		} else if len(w.log) > 0 {
			body = append(body, "Latest status", "")
			n := 1
			if w.state[active] == phaseFailed {
				n = 8
			}
			body = append(body, w.log[max(0, len(w.log)-n):]...)
		} else {
			body = append(body, "Preparing the next step...")
		}
		// Keep the last status visible while answering, without replaying the log.
		if len(prompt) > 0 && len(w.log) > 0 {
			body = append(body, "", "Latest: "+w.log[len(w.log)-1])
		}
		// On short screens the question takes priority over repeated phase
		// headings. The field and its validation remain pinned below it.
		if bodyHeight <= 5 && len(prompt) > 0 {
			body = prompt
		}
	}
	body = wrapped(body, contentWidth)
	// Focus follows the chosen option when it would otherwise be out of view.
	focus := -1
	for i, l := range body {
		if strings.HasPrefix(l, "> ") {
			focus = i
		}
	}
	if !w.details && !w.progressView && w.selectionHelp != "" && contentWidth < 76 {
		body = append(body, "", "ABOUT THIS OPTION", w.selectionHelp)
		body = wrapped(body, contentWidth)
	}
	start := min(w.scroll, max(0, len(body)-bodyHeight))
	if w.scroll == 0 && focus >= bodyHeight {
		start = focus - bodyHeight + 2
	}
	start = min(start, max(0, len(body)-bodyHeight))
	w.scroll = start
	end := min(len(body), start+bodyHeight)
	visible := body[start:end]
	if paneHeight > 0 {
		for len(visible) < bodyHeight {
			visible = append(visible, "")
		}
		history := wrapped(w.log, contentWidth)
		capacity := paneHeight - 2
		w.logScroll = min(w.logScroll, max(0, len(history)-capacity))
		endLog := max(0, len(history)-w.logScroll)
		startLog := max(0, endLog-capacity)
		label := "LIVE LOG  ·  PgUp/PgDn history"
		if w.logScroll > 0 {
			label = "LOG PAUSED  ·  PgDn to return to live output"
		}
		visible = append(visible, strings.Repeat("─", contentWidth), label)
		visible = append(visible, history[startLog:endLog]...)
		bodyHeight += paneHeight
	}
	var nav []string
	if sidebar {
		nav = append(nav, "DEPLOYMENT", "")
		groups := []string{}
		seen := map[string]bool{}
		for _, n := range w.names {
			g := phaseInfo(n).Group
			if !seen[g] {
				groups = append(groups, g)
				seen[g] = true
			}
		}
		for _, g := range groups {
			marker := "  "
			if g == p.Group {
				marker = "> "
			}
			nav = append(nav, marker+g)
			if g != p.Group {
				continue
			}
			for i, n := range w.names {
				if phaseInfo(n).Group != g {
					continue
				}
				status := "·"
				switch w.state[n] {
				case phaseDone, phaseSkipped:
					status = "✓"
				case phaseRunning:
					status = ">"
					if w.viewedPhase != "" && n != active {
						status = "·"
					}
				case phaseFailed:
					status = "!"
				}
				if w.viewedPhase != "" && n == active {
					status = ">"
				}
				if os.Getenv("GUACDEPLOY_ASCII") != "" {
					if status == "✓" {
						status = "+"
					}
					if status == "·" {
						status = "."
					}
				}
				nav = append(nav, fmt.Sprintf("  %s %02d %s", status, i+1, phaseInfo(n).Title))
			}
		}
		nav = append(nav, "", "Completed work", "is saved on this host.")
	}
	for i := 0; i < bodyHeight; i++ {
		l := ""
		if i < len(visible) {
			l = visible[i]
		}
		prefix := "  "
		if sidebar {
			n := ""
			if i < len(nav) {
				n = nav[i]
			}
			prefix = "  " + pad(n, sideWidth-3) + "│ "
		}
		out = append(out, fit(prefix+l, width))
	}
	hint := "Tab  Details   PgUp/PgDn  Scroll   Ctrl-C  Cancel"
	if w.cols < 104 || w.rows < 26 {
		hint = "Tab  Deployment progress   PgUp/PgDn  Scroll   Ctrl-C  Cancel"
	}
	if w.progressView {
		hint = "Tab  Details   PgUp/PgDn  Scroll   Ctrl-C  Cancel"
	}
	if w.finalScreen {
		hint = "Tab  Details   PgUp/PgDn  Scroll   F  Finish and return to the shell"
	}
	if w.details {
		hint = "Tab  Back to task   PgUp/PgDn  Scroll   Ctrl-C  Cancel"
	}
	if len(body) > bodyHeight {
		hint = fmt.Sprintf("%d–%d / %d  ", start+1, end, len(body)) + hint
	}
	if len(controls) > 0 {
		prefix := "  "
		border := "  "
		if sidebar {
			prefix = "  " + strings.Repeat(" ", sideWidth-3) + "│ "
			border = "  " + strings.Repeat(" ", sideWidth-3) + "├─"
		}
		if helpWidth > 0 {
			out = append(out, border+strings.Repeat("─", choiceWidth)+"─┬─"+strings.Repeat("─", helpWidth))
			help := optionHelp
			for i, control := range controls {
				right := ""
				if i < len(help) {
					right = help[i]
				}
				out = append(out, fit(prefix+pad(control, choiceWidth)+" │ "+right, width))
			}
		} else {
			out = append(out, fit(border+strings.Repeat("─", contentWidth), width))
			for _, control := range controls {
				out = append(out, fit(prefix+control, width))
			}
		}
	}

	bottom := []rune("  " + strings.Repeat("─", width-4))
	if sidebar && sideWidth-1 < len(bottom) {
		bottom[sideWidth-1] = '┴'
	}
	if len(controls) > 0 && helpWidth > 0 {
		junction := 2 + choiceWidth + 1
		if sidebar {
			junction += sideWidth - 1
		}
		if junction < len(bottom) {
			bottom[junction] = '┴'
		}
	}
	out = append(out, fit(string(bottom), width), fit("  "+hint, width))
	if os.Getenv("GUACDEPLOY_ASCII") != "" {
		for i, l := range out {
			out[i] = strings.NewReplacer("█", "=", "░", "-", "─", "-", "━", "=", "│", "|", "├", "+", "┬", "+", "┴", "+", "·", ".", "–", "-", "…", "~").Replace(l)
		}
	}
	return out
}

func (w *Wizard) paint(line string) string {
	if !w.colour {
		return line
	}
	if painted, ok := w.paintBrand(line); ok {
		return painted
	}
	if left, right, ok := strings.Cut(line, "│"); ok {
		return w.paint(left) + "│" + w.paint(right)
	}
	reset := "\x1b[0m"
	if strings.Contains(line, " | ") {
		switch eventLevel(line) {
		case "ERROR":
			return "\x1b[31m" + line + reset
		case "WARN":
			return "\x1b[33m" + line + reset
		case "SUCCESS":
			return "\x1b[32m" + line + reset
		}
	}
	// Default terminal colours keep body text legible on light and dark themes.
	if strings.Contains(line, "[ERROR]") || strings.Contains(line, "NEEDS ATTENTION") || strings.Contains(line, phaseFailed) {
		return "\x1b[1;31m" + line + reset
	}
	if strings.Contains(line, "[ C  COPY SIGN-IN LINK ]") || strings.Contains(line, "YOUR TURN") || strings.Contains(line, "WAITING FOR BROWSER SIGN-IN") {
		prefix := line[:len(line)-len(strings.TrimLeft(line, " "))]
		return prefix + brandInk(0, true) + "\x1b[1;97m" + strings.TrimLeft(line, " ") + reset
	}
	if strings.Contains(line, "> [") {
		prefix := line[:len(line)-len(strings.TrimLeft(line, " "))]
		return prefix + brandInk(0, true) + "\x1b[1;97m" + strings.TrimLeft(line, " ") + reset
	}
	if strings.HasPrefix(strings.TrimSpace(line), "IN PROGRESS") {
		prefix := line[:len(line)-len(strings.TrimLeft(line, " "))]
		return prefix + brandInk(0, true) + "\x1b[1;97m" + strings.TrimLeft(line, " ") + reset
	}
	if strings.HasPrefix(strings.TrimSpace(line), "> ") {
		return "\x1b[1;36m" + line + reset
	}
	if strings.Contains(line, "steps complete") {
		return "\x1b[36m" + line + reset
	}
	if strings.Contains(line, "[SUCCESS]") || strings.Contains(line, "✓") || strings.Contains(line, phaseDone) {
		return "\x1b[32m" + line + reset
	}
	if strings.Contains(line, "Ctrl-C") {
		return "\x1b[1m" + line + reset
	}
	if strings.Contains(line, "[WARN]") {
		return "\x1b[33m" + line + reset
	}
	if strings.Contains(line, "[docker]") {
		return "\x1b[36m" + line + reset
	}
	return line
}
