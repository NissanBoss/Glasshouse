//go:build !windows

package main

import "os"

func elevated() bool { return os.Geteuid() == 0 }
