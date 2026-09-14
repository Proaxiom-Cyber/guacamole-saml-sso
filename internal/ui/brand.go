package ui

import (
	"fmt"
	"os"
	"strings"
)

// Terminal adaptation of branding/logos/proaxiom-submark.png. Keep the stagger
// and final dot; terminal cells replace curves without needing image protocols.
var brandBars = []string{
	"      ━━━━━━━━━━━━",
	"          ━━━━━━━━━━",
	"    ━━━━━━━━━━━━",
	"  ━━━━━━━",
	"━━━━━━━  ●",
}

// These are the shared Proaxiom palette, not inferred terminal theme colours.
var brandRGB = [][3]int{{8, 64, 84}, {78, 142, 153}, {41, 161, 185}, {117, 201, 185}, {242, 104, 103}}
var brand256 = []int{23, 66, 37, 115, 203}

func brandInk(row int, background bool) string {
	mode := "38"
	if background {
		mode = "48"
	}
	if strings.Contains(os.Getenv("COLORTERM"), "truecolor") || strings.Contains(os.Getenv("COLORTERM"), "24bit") {
		c := brandRGB[row]
		return fmt.Sprintf("\x1b[%s;2;%d;%d;%dm", mode, c[0], c[1], c[2])
	}
	return fmt.Sprintf("\x1b[%s;5;%dm", mode, brand256[row])
}

func (w *Wizard) brandHeader(width int, progress string, busy bool) []string {
	mode := "GUIDED SETUP"
	if w.details {
		mode = "SESSION DETAILS"
	}
	if w.rows < 30 || width < 79 {
		return []string{pad(" PROAXIOM / GUACAMOLE", width), "", fit("  "+progress, width), ""}
	}
	text := []string{"P R O A X I O M", "GUACAMOLE DEPLOYER", mode + "   /   " + elapsed(w.started) + " elapsed", "", progress}
	lines := make([]string, 0, 7)
	for i, bar := range brandBars {
		// A moving bright segment communicates activity; it is never a percentage.
		if busy && os.Getenv("GUACDEPLOY_REDUCED_MOTION") == "" && w.tick%10/2 == i {
			bar = strings.ReplaceAll(bar, "━", "═")
		}
		if os.Getenv("GUACDEPLOY_ASCII") != "" {
			bar = strings.NewReplacer("━", "-", "═", "=", "●", "o").Replace(bar)
		}
		lines = append(lines, fit("  "+pad(bar, 24)+text[i], width))
	}
	return append(lines, "", "")
}

func (w *Wizard) paintBrand(line string) (string, bool) {
	if strings.HasPrefix(line, " PROAXIOM / GUACAMOLE") {
		return brandInk(0, true) + "\x1b[1;97m" + line + "\x1b[0m", true
	}
	for i, bar := range brandBars {
		prefix := "  " + pad(bar, 24)
		variants := []string{prefix, strings.ReplaceAll(prefix, "━", "═")}
		if os.Getenv("GUACDEPLOY_ASCII") != "" {
			for j := range variants {
				variants[j] = strings.NewReplacer("━", "-", "═", "=", "●", "o").Replace(variants[j])
			}
		}
		for _, v := range variants {
			if strings.HasPrefix(line, v) {
				// A white card keeps the navy mark visible on both terminal themes.
				return "\x1b[48;5;255m" + brandInk(i, false) + v[:len(v)-2] + "\x1b[0m  \x1b[1m" + strings.TrimPrefix(line, v) + "\x1b[0m", true
			}
		}
	}
	return line, false
}
