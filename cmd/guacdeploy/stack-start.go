package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// stackStartCmd brings the stack up after a reboot.
//
// It exists because credentials now reach the containers as files on
// memory-backed storage, which is empty after a cold boot. Docker would
// restart the containers on its own — they carry restart: always — but
// their secret files would be gone, so postgres would refuse to start and
// the tunnel connector would have no token. This repopulates the files and
// starts the stack, and the boot unit installed with the credential store
// calls it.
//
// It never prompts: a boot unit has no terminal. A credential mode that
// cannot supply a value unattended is reported rather than waited on.
func stackStartCmd(ctx context.Context, stateDir string, u *ui.UI) error {
	err := session.StartStack(ctx, stateDir, u)
	if errors.Is(err, ui.ErrInputRequired) {
		return fmt.Errorf("%w: this deployment's credential mode needs a person, so the stack cannot start unattended", err)
	}
	return err
}
