//go:build !windows && !linux && !darwin

package main

// Linux and macOS expose most of this too, but through different places:
// /sys/class/dmi for the board, /sys/firmware/efi for Secure Boot,
// /etc/machine-id for the install identifier. Until those are written the
// program still builds and runs everywhere, and says so plainly rather
// than reporting an empty machine as a clean one.

func platformChecks() []Check {
	return []Check{
		{ID: "unsupported-platform", Group: "platform", Run: func() []Finding {
			return []Finding{{ID: "unsupported-platform.notyet", Fix: Clear,
				Reach: Local, How: Measured}}
		}},
	}
}

func fontDirs() []string           { return nil }
func firefoxProfileDirs() []string { return nil }

func chromiumBrowsers() []chromiumBrowser { return nil }
