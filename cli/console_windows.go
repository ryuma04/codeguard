//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

// enableConsole switches the Windows console to UTF-8 output and turns on ANSI colour
// processing. Returns false when f is not a console that accepts it.
func enableConsole(f *os.File) bool {
	kernel32.NewProc("SetConsoleOutputCP").Call(65001)
	var mode uint32
	h := f.Fd()
	if r, _, _ := kernel32.NewProc("GetConsoleMode").Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false
	}
	r, _, _ := kernel32.NewProc("SetConsoleMode").Call(h, uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
	return r != 0
}
