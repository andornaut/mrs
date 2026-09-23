package prompt

import "golang.org/x/sys/unix"

// disableEcho switches echo off on fd, for a password prompt resumed after a
// stop: the shell that ran while mrs was stopped put its own terminal settings
// back, and term.ReadPassword, still reading, does not know to switch echo off
// again.
func disableEcho(fd int) error {
	t, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return err
	}
	t.Lflag &^= unix.ECHO
	return unix.IoctlSetTermios(fd, ioctlSetTermios, t)
}
