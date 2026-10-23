//go:build !windows

package main

import "os"

func enableConsole(*os.File) bool { return true }
