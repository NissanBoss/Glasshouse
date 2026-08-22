//go:build darwin

package main

// What we look at on macOS.
//
// Unlike Linux, macOS keeps the hardware identifiers in the IORegistry
// rather than in files, and there is no way to read it from Go without
// either cgo or asking one of Apple's own tools. This file asks the tools.
//
// That is a deliberate trade and worth naming: running another program is
// more surface than reading a file. It is kept as narrow as possible. Only
// the commands in allowedTools may be run, they are all stock Apple
// binaries, they are all read-only, and none of them is ever handed
// anything that came from outside this file.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// allowedTools is the whole list. A test checks that nothing else is ever
// launched, so growing this list has to be a decision somebody makes on
// purpose.
var allowedTools = map[string]bool{
	"/usr/sbin/ioreg":  true,
	"/usr/bin/csrutil": true,
}

func platformChecks() []Check {
	return []Check{
		{ID: "management-engine", Group: "firmware", Run: checkManagementEngine},
		{ID: "firmware-vendor", Group: "firmware", Run: checkFirmwareVendor},
		{ID: "boot-guard", Group: "firmware", Run: checkBootGuard},
		{ID: "sip", Group: "firmware", Run: checkSIP},

		{ID: "system-uuid", Group: "identity", Run: checkSystemUUID},
		{ID: "board-serial", Group: "identity", Run: checkBoardSerial},
		{ID: "computer-name", Group: "identity", Run: checkHostname},

		{ID: "crash-reporting", Group: "telemetry", Run: checkDiagnosticSubmission},

		{ID: "dns-servers", Group: "network", Run: checkResolvConf},
	}
}

// runTool launches one of the allowed commands and returns what it printed.
// Anything not on the list is refused rather than run, so a typo cannot
// turn into an arbitrary execution.
func runTool(path string, args ...string) (string, error) {
	if !allowedTools[path] {
		return "", &os.PathError{Op: "run", Path: path, Err: os.ErrPermission}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).Output()
	return string(out), err
}

// parseIoreg pulls one value out of what ioreg prints. The lines look like
//
//	"IOPlatformUUID" = "3F1B0A2C-..."
//
// and the quotes are part of the format, not of the value.
func parseIoreg(output, key string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`+key+`"`) {
			continue
		}
		_, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"`)
	}
	return ""
}

func platformValue(key string) (string, error) {
	out, err := runTool("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", err
	}
	return parseIoreg(out, key), nil
}

// Firmware

func checkManagementEngine() []Finding {
	// Apple Silicon has no Intel chipset and therefore no Management
	// Engine. It has a Secure Enclave instead, which is a different thing:
	// it holds keys rather than managing the machine, and it has no network
	// stack of its own.
	if runtime.GOARCH == "arm64" {
		return []Finding{{ID: "management-engine.applesilicon", Fix: Sealed, Reach: Local,
			How: Measured, Source: "the architecture this binary was built for",
			Detail: "Apple Silicon"}}
	}
	return []Finding{{ID: "management-engine.intel", Fix: Sealed, Reach: Remote,
		How: Inferred, Source: "the architecture this binary was built for",
		Detail: "Intel Mac",
		Why:    "deduced from the architecture, not read from the engine itself"}}
}

func checkFirmwareVendor() []Finding {
	const where = "IORegistry, IOPlatformExpertDevice"
	model, err := platformValue("model")
	if err != nil {
		return []Finding{unreadable("firmware-vendor.closed", where, err.Error())}
	}
	return []Finding{{ID: "firmware-vendor.closed", Fix: Sealed, Reach: Remote,
		How: Measured, Source: where, Detail: strings.TrimSpace("Apple " + model)}}
}

func checkBootGuard() []Finding {
	return []Finding{{ID: "boot-guard.apple", Fix: Sealed, Reach: Local,
		How: Measured, Source: "Apple platform"}}
}

// checkSIP reads System Integrity Protection, which is the closest thing
// macOS has to the question Secure Boot answers elsewhere.
func checkSIP() []Finding {
	const where = "csrutil status"
	out, err := runTool("/usr/bin/csrutil", "status")
	if err != nil {
		return []Finding{unreadable("sip.unknown", where, err.Error())}
	}
	if strings.Contains(strings.ToLower(out), "enabled") &&
		!strings.Contains(strings.ToLower(out), "disabled") {
		return []Finding{{ID: "sip.on", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "sip.off", Fix: Settable, Reach: Local,
		How: Measured, Source: where}}
}

// Identity

func checkSystemUUID() []Finding {
	const where = "IORegistry, IOPlatformUUID"
	v, err := platformValue("IOPlatformUUID")
	if err != nil {
		return []Finding{unreadable("system-uuid.present", where, err.Error())}
	}
	if v == "" || placeholderSerial(v) {
		return []Finding{{ID: "system-uuid.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "system-uuid.present", Fix: Sealed, Reach: Installed,
		How: Measured, Source: where, Value: v, Sensitive: true}}
}

func checkBoardSerial() []Finding {
	const where = "IORegistry, IOPlatformSerialNumber"
	v, err := platformValue("IOPlatformSerialNumber")
	if err != nil {
		return []Finding{unreadable("board-serial.present", where, err.Error())}
	}
	if v == "" || placeholderSerial(v) {
		return []Finding{{ID: "board-serial.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "board-serial.present", Fix: Sealed, Reach: Installed,
		How: Measured, Source: where, Value: v, Sensitive: true}}
}

func checkHostname() []Finding {
	v, err := os.Hostname()
	if err != nil || v == "" {
		return []Finding{unreadable("computer-name.present", "the hostname system call",
			"the system call gave nothing back")}
	}
	return []Finding{{ID: "computer-name.present", Fix: Settable, Reach: Network,
		How: Measured, Source: "the hostname system call", Value: v, Sensitive: true}}
}

// Telemetry

// checkDiagnosticSubmission looks at whether crash and usage reports go to
// Apple. The preference lives in a binary plist, so rather than parse one
// we look for the marker the setting leaves behind.
func checkDiagnosticSubmission() []Finding {
	where := at("Library/Application Support/CrashReporter/SubmitDiagInfo.domains")
	if _, err := os.Stat(where); err == nil {
		return []Finding{{ID: "crash-reporting.on", Fix: Settable, Reach: Network,
			How: Inferred, Source: where,
			Why: "the submission list is present, which is what the setting leaves behind"}}
	}
	return []Finding{{ID: "crash-reporting.absent", Fix: Clear, Reach: Local,
		How: Measured, Source: where}}
}

// Where the browser-facing things live on macOS.

func fontDirs() []string {
	dirs := []string{"/System/Library/Fonts", "/Library/Fonts"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Library", "Fonts"))
	}
	return dirs
}

func firefoxProfileDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")}
}

func chromiumBrowsers() []chromiumBrowser {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	s := filepath.Join(home, "Library", "Application Support")
	return []chromiumBrowser{
		{"Chrome", filepath.Join(s, "Google", "Chrome")},
		{"Edge", filepath.Join(s, "Microsoft Edge")},
		{"Brave", filepath.Join(s, "BraveSoftware", "Brave-Browser")},
	}
}
