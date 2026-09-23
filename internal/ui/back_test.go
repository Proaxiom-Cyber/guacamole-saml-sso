package ui

import (
	"errors"
	"testing"
)

func TestBackLineReturnsToConfigurationWithoutClosingWizard(t *testing.T) {
	u, _, restores := newTestUI("\x02")
	if _, err := u.BackLine("Hostname", "guacamole"); !errors.Is(err, ErrBack) {
		t.Fatal(err)
	}
	if *restores != 0 {
		t.Fatal("Back closed the terminal")
	}
}
