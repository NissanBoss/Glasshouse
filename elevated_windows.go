//go:build windows

package main

import "golang.org/x/sys/windows"

// elevated says whether we are running with administrator rights. It
// matters because plenty of the keys worth reading are readable only from
// an elevated process, and a report full of gaps deserves to say why.
func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
