package ui

import (
	"fmt"
	"os"
	"strings"
)

type taskProgress struct {
	label            string
	completed, total int
}

// TaskProgress reports a count from the operation itself. Unknown totals must
// use the activity indicator instead. Count completed checks, not elapsed time.
func (u *UI) TaskProgress(label string, completed, total int) {
	if total <= 0 || completed < 0 || completed > total {
		return
	}
	label = u.safe(label)
	u.record("PROGRESS", fmt.Sprintf("%s: %d/%d", label, completed, total))
	if w := u.wizard(); w != nil {
		w.mu.Lock()
		w.task = taskProgress{label, completed, total}
		w.mu.Unlock()
		w.redraw()
		return
	}
	u.Say("%s: %d/%d", label, completed, total)
}

func (p taskProgress) line(width int) string {
	if p.total <= 0 {
		return ""
	}
	n := min(24, max(4, width/3))
	fill := n * p.completed / p.total
	solid, empty := "━", "─"
	if os.Getenv("GUACDEPLOY_ASCII") != "" {
		solid, empty = "=", "-"
	}
	return fmt.Sprintf("%s\n%s  %d / %d", p.label, strings.Repeat(solid, fill)+strings.Repeat(empty, n-fill), p.completed, p.total)
}
