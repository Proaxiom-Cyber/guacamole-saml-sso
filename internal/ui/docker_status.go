package ui

import "strings"

// Compose emits resource lifecycle events without needing control of the terminal.
func (w *Wizard) trackDocker(line string) {
	if !strings.HasPrefix(line, "[docker]") {
		return
	}
	fields := strings.Fields(strings.TrimPrefix(line, "[docker]"))
	if len(fields) < 3 || fields[0] != "Container" {
		return
	}
	if w.dockerStatus == nil {
		w.dockerStatus = map[string]string{}
	}
	name := fields[1]
	if _, ok := w.dockerStatus[name]; !ok {
		if len(w.dockerOrder) >= 12 {
			return
		}
		w.dockerOrder = append(w.dockerOrder, name)
	}
	w.dockerStatus[name] = strings.Join(fields[2:], " ")
}
func (w *Wizard) dockerLines() []string {
	lines := []string{"CONTAINERS"}
	for _, name := range w.dockerOrder {
		status := w.dockerStatus[name]
		marker := "…"
		lower := strings.ToLower(status)
		if strings.Contains(lower, "error") || strings.Contains(lower, "unhealthy") {
			marker = "!"
		} else if strings.Contains(lower, "healthy") || strings.Contains(lower, "running") || strings.Contains(lower, "started") {
			marker = "✓"
		}
		lines = append(lines, marker+" "+name+"  "+status)
	}
	return lines
}
func eventLevel(s string) string {
	lower := strings.ToLower(s)
	for _, word := range []string{"failed", "error", "unhealthy", "fatal"} {
		if strings.Contains(lower, word) {
			return "ERROR"
		}
	}
	for _, word := range []string{"warning", "warn:", "[warn]"} {
		if strings.Contains(lower, word) {
			return "WARN"
		}
	}
	for _, word := range []string{"healthy", "complete", "[success]"} {
		if strings.Contains(lower, word) {
			return "SUCCESS"
		}
	}
	return "INFO"
}
