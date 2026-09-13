//go:build !linux

package ui

// keepSignalKeys does nothing away from Linux, which is the supported target.
// The wizard then keeps the full raw mode golang.org/x/term sets: Ctrl-C still
// cancels at a prompt, where the wizard reads it as a key, but not while a
// phase is running. Terminal settings are still restored on every exit path.
func keepSignalKeys(int) bool { return false }
