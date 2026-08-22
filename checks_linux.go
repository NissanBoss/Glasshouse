//go:build linux

package main

// What we look at on Linux.
//
// Almost all of it is plain files under /sys and /etc, which makes this the
// easiest platform to be honest about: the checks read a path, and the
// tests point that path at a fake machine instead of the real one. Nothing
// here is verified only by having run it once on somebody's laptop.

import (
	"os"
	"path/filepath"
	"strings"
)

const dmi = "sys/class/dmi/id"

func platformChecks() []Check {
	return []Check{
		{ID: "management-engine", Group: "firmware", Run: checkManagementEngine},
		{ID: "firmware-vendor", Group: "firmware", Run: checkFirmwareVendor},
		{ID: "boot-guard", Group: "firmware", Run: checkBootGuard},
		{ID: "secure-boot", Group: "firmware", Run: checkSecureBoot},
		{ID: "tpm", Group: "firmware", Run: checkTPM},

		{ID: "system-uuid", Group: "identity", Run: checkSystemUUID},
		{ID: "board-serial", Group: "identity", Run: checkBoardSerial},
		{ID: "machine-id", Group: "identity", Run: checkMachineID},
		{ID: "computer-name", Group: "identity", Run: checkHostname},

		{ID: "popularity-contest", Group: "telemetry", Run: checkPopularityContest},
		{ID: "crash-reporting", Group: "telemetry", Run: checkApport},

		{ID: "dns-servers", Group: "network", Run: checkResolvConf},
	}
}

// Firmware

// cpuVendor pulls the vendor and model out of /proc/cpuinfo. On ARM boards
// there is no vendor_id line at all, which is an answer in itself.
func cpuVendor() (vendor, model string, err error) {
	b, err := os.ReadFile(at("proc/cpuinfo"))
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "vendor_id":
			if vendor == "" {
				vendor = value
			}
		case "model name":
			if model == "" {
				model = value
			}
		}
	}
	return vendor, model, nil
}

func checkManagementEngine() []Finding {
	where := at("proc/cpuinfo")
	vendor, model, err := cpuVendor()
	if err != nil {
		return []Finding{unreadable("management-engine.unknown", where, err.Error())}
	}

	f := Finding{Fix: Sealed, Reach: Remote, How: Inferred, Source: where, Detail: model,
		Why: "deduced from the CPU vendor, not read from the engine itself"}

	switch vendor {
	case "GenuineIntel":
		f.ID = "management-engine.intel"
		// /dev/mei0 is the kernel's interface to the engine. Its presence
		// turns the inference into something actually observed.
		if _, err := os.Stat(at("dev/mei0")); err == nil {
			f.Detail += " (mei device present)"
			f.How = Measured
			f.Why = ""
			f.Source = at("dev/mei0")
		}
	case "AuthenticAMD":
		f.ID = "management-engine.amd"
	default:
		f.ID = "management-engine.unknown"
		f.Detail = vendor
		if vendor == "" {
			f.Detail = "no x86 vendor line, so probably not an x86 machine"
		}
	}
	return []Finding{f}
}

func checkFirmwareVendor() []Finding {
	where := at(dmi, "bios_vendor")
	vendor, err := readTrimmed(where)
	if err != nil {
		if deniedErr(err) {
			return []Finding{unreadable("firmware-vendor.closed", where, err.Error())}
		}
		return []Finding{unreadable("firmware-vendor.closed", where,
			"no DMI tables, which usually means a board without SMBIOS")}
	}
	version, _ := readTrimmed(at(dmi, "bios_version"))
	date, _ := readTrimmed(at(dmi, "bios_date"))

	detail := strings.TrimSpace(vendor + " " + version)
	if date != "" {
		detail += ", " + date
	}
	return []Finding{{ID: "firmware-vendor.closed", Fix: Costly, Reach: Remote,
		How: Measured, Source: where, Detail: detail}}
}

func checkBootGuard() []Finding {
	where := at("proc/cpuinfo")
	vendor, model, err := cpuVendor()
	if err != nil {
		return []Finding{unreadable("boot-guard.unknown", where, err.Error())}
	}
	if vendor != "GenuineIntel" {
		return []Finding{{ID: "boot-guard.notintel", Fix: Costly, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "boot-guard.likely", Fix: Sealed, Reach: Local,
		How: Inferred, Source: where, Detail: model,
		Why: "based on the CPU generation; reading the fuses needs ring 0"}}
}

// The Secure Boot variable is five bytes: four of EFI attributes and then
// the flag itself.
const secureBootVar = "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

func checkSecureBoot() []Finding {
	if _, err := os.Stat(at("sys/firmware/efi")); err != nil {
		return []Finding{{ID: "secure-boot.unknown", Fix: Settable, Reach: Local,
			How: Measured, Source: at("sys/firmware/efi")}}
	}
	where := at(secureBootVar)
	b, err := os.ReadFile(where)
	if err != nil {
		if deniedErr(err) {
			return []Finding{unreadable("secure-boot.unknown", where, err.Error())}
		}
		return []Finding{{ID: "secure-boot.off", Fix: Settable, Reach: Local,
			How: Measured, Source: where}}
	}
	if len(b) >= 5 && b[4] == 1 {
		return []Finding{{ID: "secure-boot.on", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "secure-boot.off", Fix: Settable, Reach: Local,
		How: Measured, Source: where}}
}

func checkTPM() []Finding {
	where := at("sys/class/tpm/tpm0")
	if _, err := os.Stat(where); err != nil {
		return []Finding{{ID: "tpm.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: at("sys/class/tpm")}}
	}
	return []Finding{{ID: "tpm.present", Fix: Sealed, Reach: Network,
		How: Measured, Source: where}}
}

// Identity

// checkSystemUUID reads the DMI product UUID, which the kernel deliberately
// keeps root-only because it is a permanent machine identifier. Running
// unprivileged therefore reports a gap, which is the correct answer: the
// identifier is still there, we just were not allowed to look at it.
func checkSystemUUID() []Finding {
	where := at(dmi, "product_uuid")
	v, err := readTrimmed(where)
	switch {
	case deniedErr(err):
		return []Finding{unreadable("system-uuid.present", where,
			"root only, because it is a permanent machine identifier")}
	case err != nil:
		return []Finding{{ID: "system-uuid.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	case v == "" || placeholderSerial(v):
		return []Finding{{ID: "system-uuid.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "system-uuid.present", Fix: Sealed, Reach: Installed,
		How: Measured, Source: where, Value: v, Sensitive: true}}
}

func checkBoardSerial() []Finding {
	where := at(dmi, "board_serial")
	var serials []string
	denied := false
	for _, name := range []string{"board_serial", "product_serial"} {
		v, err := readTrimmed(at(dmi, name))
		if deniedErr(err) {
			denied = true
			continue
		}
		if err != nil || v == "" || placeholderSerial(v) {
			continue
		}
		serials = append(serials, v)
	}
	if len(serials) == 0 {
		if denied {
			return []Finding{unreadable("board-serial.present", where,
				"root only, because these are permanent machine identifiers")}
		}
		return []Finding{{ID: "board-serial.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "board-serial.present", Fix: Sealed, Reach: Installed,
		How: Measured, Source: where,
		Value: strings.Join(serials, " / "), Sensitive: true}}
}

// checkMachineID reads the identifier systemd writes at install time. It is
// the direct counterpart of the Windows MachineGuid and, unlike the DMI
// values, any user can read it.
func checkMachineID() []Finding {
	where := at("etc/machine-id")
	v, err := readTrimmed(where)
	if err != nil || v == "" {
		where = at("var/lib/dbus/machine-id")
		if v, err = readTrimmed(where); err != nil || v == "" {
			return []Finding{{ID: "machine-id.absent", Fix: Clear, Reach: Local,
				How: Measured, Source: at("etc/machine-id")}}
		}
	}
	return []Finding{{ID: "machine-id.present", Fix: Settable, Reach: Installed,
		How: Measured, Source: where, Value: v, Sensitive: true}}
}

func checkHostname() []Finding {
	where := at("etc/hostname")
	v, err := readTrimmed(where)
	if err != nil || v == "" {
		if v, err = os.Hostname(); err != nil || v == "" {
			return []Finding{unreadable("computer-name.present", where,
				"no hostname file and the system call gave nothing")}
		}
		where = "the hostname system call"
	}
	return []Finding{{ID: "computer-name.present", Fix: Settable, Reach: Network,
		How: Measured, Source: where, Value: v, Sensitive: true}}
}

// Telemetry
//
// There is far less of it here than on Windows, and what exists is opt-in
// and packaged rather than built into the kernel. That difference is worth
// seeing in the report rather than being told about.

func checkPopularityContest() []Finding {
	where := at("etc/popularity-contest.conf")
	b, err := os.ReadFile(where)
	if err != nil {
		return []Finding{{ID: "popularity-contest.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	if strings.Contains(string(b), `PARTICIPATE="no"`) {
		return []Finding{{ID: "popularity-contest.off", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "popularity-contest.on", Fix: Settable, Reach: Network,
		How: Measured, Source: where}}
}

func checkApport() []Finding {
	where := at("etc/default/apport")
	b, err := os.ReadFile(where)
	if err != nil {
		return []Finding{{ID: "crash-reporting.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	if strings.Contains(strings.ReplaceAll(string(b), " ", ""), "enabled=0") {
		return []Finding{{ID: "crash-reporting.off", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "crash-reporting.on", Fix: Settable, Reach: Network,
		How: Measured, Source: where}}
}

// Network

// Where the browser-facing things live on Linux. The system directories go
// through the configurable root so tests can supply their own; the ones
// under a home directory do not, since there is only ever one of those.

func fontDirs() []string {
	dirs := []string{at("usr/share/fonts"), at("usr/local/share/fonts")}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, ".local", "share", "fonts"),
			filepath.Join(home, ".fonts"))
	}
	return dirs
}

func firefoxProfileDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".mozilla", "firefox"),
		// Snap and Flatpak put the profile somewhere else entirely, and a
		// tool that only knows the classic path reports a machine with
		// Firefox on it as having none.
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
		filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
	}
}
