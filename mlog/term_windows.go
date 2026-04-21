//go:build windows

package mlog

import "golang.org/x/sys/windows"

func isTerminal(fd uintptr) bool {
	var mode uint32
	err := windows.GetConsoleMode(windows.Handle(fd), &mode)
	return err == nil
}
