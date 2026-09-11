package ui

import (
	"syscall"
	"unsafe"
)

// keepSignalKeys re-enables the terminal's signal characters after raw mode
// turned them off, and disables the two that would strand the screen. It
// reports whether the terminal accepted the change.
//
// Raw mode normally makes Ctrl-C an ordinary key. That is enough while a
// prompt is reading the keyboard, but a phase can run for minutes with
// nothing reading it, and during that time Ctrl-C would do nothing at all
// while the footer still offers it. Leaving ISIG on means the kernel raises
// SIGINT whenever it is pressed, so the existing handler cancels the session
// from anywhere, running phase included.
//
// Ctrl-Z and Ctrl-\ are switched off rather than left on. Suspending or
// quitting through them would leave the terminal in raw mode and on the
// alternate screen with nothing left running to put it back.
func keepSignalKeys(fd int) bool {
	var tio syscall.Termios
	if err := ioctlTermios(fd, syscall.TCGETS, &tio); err != nil {
		return false
	}
	tio.Lflag |= syscall.ISIG
	tio.Cc[syscall.VSUSP] = 0
	tio.Cc[syscall.VQUIT] = 0
	return ioctlTermios(fd, syscall.TCSETS, &tio) == nil
}

func ioctlTermios(fd int, req uintptr, tio *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(tio))); errno != 0 {
		return errno
	}
	return nil
}
