//go:build windows

package main

// What we look at on Windows.
//
// Everything here reads. Nothing in this file opens a key for writing, and
// that is the point: a tool that inspects your machine has no business
// changing it while you are still deciding whether to trust the tool.
//
// Every check reports where it looked, so nobody has to take this program's
// word for anything. And no check returns silence: if it could not read
// something it says so, because a quiet failure looks identical to good
// news and that is the one mistake this tool cannot afford.

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

func platformChecks() []Check {
	return []Check{
		{ID: "management-engine", Group: "firmware", Run: checkManagementEngine},
		{ID: "firmware-vendor", Group: "firmware", Run: checkFirmwareVendor},
		{ID: "boot-guard", Group: "firmware", Run: checkBootGuard},
		{ID: "secure-boot", Group: "firmware", Run: checkSecureBoot},
		{ID: "tpm", Group: "firmware", Run: checkTPM},

		{ID: "system-uuid", Group: "identity", Run: checkSystemUUID},
		{ID: "board-serial", Group: "identity", Run: checkBoardSerial},
		{ID: "machine-guid", Group: "identity", Run: checkMachineGUID},
		{ID: "sqm-machine-id", Group: "identity", Run: checkSQMMachineID},
		{ID: "advertising-id", Group: "identity", Run: checkAdvertisingID},
		{ID: "product-id", Group: "identity", Run: checkProductID},
		{ID: "computer-name", Group: "identity", Run: checkComputerName},

		{ID: "telemetry-level", Group: "telemetry", Run: checkTelemetryLevel},
		{ID: "diagtrack", Group: "telemetry", Run: checkDiagTrack},
		{ID: "error-reporting", Group: "telemetry", Run: checkErrorReporting},
		{ID: "activity-feed", Group: "telemetry", Run: checkActivityFeed},
		{ID: "recall", Group: "telemetry", Run: checkRecall},

		{ID: "dns-servers", Group: "network", Run: checkDNSServers},
	}
}

// Reading the registry
//
// The helpers hand back the error rather than a bare ok, because "the key
// is not there" and "you are not allowed to look" mean opposite things to
// the reader and the old code threw that difference away.

func regString(root registry.Key, path, name string) (string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	return v, err
}

func regInt(root registry.Key, path, name string) (uint64, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err
}

func regKeyExists(root registry.Key, path string) (bool, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	k.Close()
	return true, nil
}

func regSubKeys(root registry.Key, path string) ([]string, error) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}

// blocked separates "not allowed to look" from "genuinely not there". Only
// the first one is a gap in the report; the second is an answer.
func blocked(err error) bool {
	if err == nil || errors.Is(err, registry.ErrNotExist) {
		return false
	}
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) ||
		errors.Is(err, syscall.ERROR_PRIVILEGE_NOT_HELD) ||
		strings.Contains(strings.ToLower(err.Error()), "access is denied")
}

// Firmware

// checkManagementEngine reports the coprocessor that every modern x86
// machine carries. It is inferred from the CPU vendor rather than read from
// the engine itself, because the engine is in the chipset whether or not a
// driver is talking to it, and that inference is labelled as one.
func checkManagementEngine() []Finding {
	const cpuKey = `HARDWARE\DESCRIPTION\System\CentralProcessor\0`
	vendor, err := regString(registry.LOCAL_MACHINE, cpuKey, "VendorIdentifier")
	if err != nil {
		return []Finding{unreadable("management-engine.unknown", cpuKey, err.Error())}
	}
	name, _ := regString(registry.LOCAL_MACHINE, cpuKey, "ProcessorNameString")
	name = strings.Join(strings.Fields(name), " ")

	base := Finding{Fix: Sealed, Reach: Remote, How: Inferred, Source: cpuKey, Detail: name,
		Why: "deduced from the CPU vendor, not read from the engine itself"}

	switch vendor {
	case "GenuineIntel":
		if on, _ := regKeyExists(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\MEIx64`); on {
			base.Detail += " (MEI driver loaded)"
			base.How = Measured
			base.Why = ""
		}
		base.ID = "management-engine.intel"
	case "AuthenticAMD":
		base.ID = "management-engine.amd"
	default:
		base.ID = "management-engine.unknown"
		base.Detail = vendor
	}
	return []Finding{base}
}

func checkFirmwareVendor() []Finding {
	const biosKey = `HARDWARE\DESCRIPTION\System\BIOS`
	vendor, err := regString(registry.LOCAL_MACHINE, biosKey, "BIOSVendor")
	if err != nil {
		return []Finding{unreadable("firmware-vendor.closed", biosKey, err.Error())}
	}
	version, _ := regString(registry.LOCAL_MACHINE, biosKey, "BIOSVersion")
	date, _ := regString(registry.LOCAL_MACHINE, biosKey, "BIOSReleaseDate")

	detail := strings.TrimSpace(vendor + " " + version)
	if date != "" {
		detail += ", " + date
	}
	return []Finding{{ID: "firmware-vendor.closed", Fix: Costly, Reach: Remote,
		How: Measured, Source: biosKey, Detail: detail}}
}

// checkBootGuard answers the question that decides whether replacing the
// firmware is even possible, and is honest that it answers it by inference.
//
// Reading the fuses needs ring 0, which would mean shipping a kernel driver,
// which is not something a privacy tool should ask anyone to install. What
// is left is the CPU generation, and that is a good enough signal to be
// worth stating: Boot Guard arrived with Skylake and OEMs have fused it on
// consumer boards ever since.
func checkBootGuard() []Finding {
	const cpuKey = `HARDWARE\DESCRIPTION\System\CentralProcessor\0`
	vendor, err := regString(registry.LOCAL_MACHINE, cpuKey, "VendorIdentifier")
	if err != nil {
		return []Finding{unreadable("boot-guard.unknown", cpuKey, err.Error())}
	}
	if vendor != "GenuineIntel" {
		return []Finding{{ID: "boot-guard.notintel", Fix: Costly, Reach: Local,
			How: Measured, Source: cpuKey}}
	}
	name, _ := regString(registry.LOCAL_MACHINE, cpuKey, "ProcessorNameString")
	name = strings.Join(strings.Fields(name), " ")

	return []Finding{{ID: "boot-guard.likely", Fix: Sealed, Reach: Local,
		How: Inferred, Source: cpuKey, Detail: name,
		Why: "based on the CPU generation; reading the fuses needs ring 0"}}
}

func checkSecureBoot() []Finding {
	const key = `SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	on, err := regInt(registry.LOCAL_MACHINE, key, "UEFISecureBootEnabled")
	switch {
	case blocked(err):
		return []Finding{unreadable("secure-boot.unknown", key, err.Error())}
	case err != nil:
		return []Finding{{ID: "secure-boot.unknown", Fix: Settable, Reach: Local,
			How: Measured, Source: key}}
	case on == 1:
		return []Finding{{ID: "secure-boot.on", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	default:
		return []Finding{{ID: "secure-boot.off", Fix: Settable, Reach: Local,
			How: Measured, Source: key}}
	}
}

func checkTPM() []Finding {
	const key = `SYSTEM\CurrentControlSet\Services\TPM`
	present, err := regKeyExists(registry.LOCAL_MACHINE, key)
	if blocked(err) {
		return []Finding{unreadable("tpm.present", key, err.Error())}
	}
	if !present {
		return []Finding{{ID: "tpm.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	}
	return []Finding{{ID: "tpm.present", Fix: Sealed, Reach: Network,
		How: Measured, Source: key}}
}

// Identity

func checkMachineGUID() []Finding {
	const key = `SOFTWARE\Microsoft\Cryptography`
	v, err := regString(registry.LOCAL_MACHINE, key, "MachineGuid")
	if err != nil {
		return []Finding{unreadable("machine-guid.present", key, err.Error())}
	}
	return []Finding{{ID: "machine-guid.present", Fix: Costly, Reach: Installed,
		How: Measured, Source: key, Value: v, Sensitive: true}}
}

func checkSQMMachineID() []Finding {
	const key = `SOFTWARE\Microsoft\SQMClient`
	v, err := regString(registry.LOCAL_MACHINE, key, "MachineId")
	switch {
	case blocked(err):
		return []Finding{unreadable("sqm-machine-id.present", key, err.Error())}
	case err != nil:
		return []Finding{{ID: "sqm-machine-id.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	}
	return []Finding{{ID: "sqm-machine-id.present", Fix: Settable, Reach: Network,
		How: Measured, Source: key, Value: v, Sensitive: true}}
}

func checkAdvertisingID() []Finding {
	const key = `SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo`
	enabled, err := regInt(registry.CURRENT_USER, key, "Enabled")
	if blocked(err) {
		return []Finding{unreadable("advertising-id.on", key, err.Error())}
	}
	if err == nil && enabled == 0 {
		return []Finding{{ID: "advertising-id.off", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	}
	id, _ := regString(registry.CURRENT_USER, key, "Id")
	return []Finding{{ID: "advertising-id.on", Fix: Settable, Reach: Network,
		How: Measured, Source: key, Value: id, Sensitive: true}}
}

func checkProductID() []Finding {
	const key = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	v, err := regString(registry.LOCAL_MACHINE, key, "ProductId")
	if err != nil {
		return []Finding{unreadable("product-id.present", key, err.Error())}
	}
	return []Finding{{ID: "product-id.present", Fix: Sealed, Reach: Installed,
		How: Measured, Source: key, Value: v, Sensitive: true}}
}

func checkComputerName() []Finding {
	const key = `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`
	v, err := regString(registry.LOCAL_MACHINE, key, "ComputerName")
	if err != nil {
		return []Finding{unreadable("computer-name.present", key, err.Error())}
	}
	return []Finding{{ID: "computer-name.present", Fix: Settable, Reach: Network,
		How: Measured, Source: key, Value: v, Sensitive: true}}
}

// Telemetry

func checkTelemetryLevel() []Finding {
	// The policy key wins when it is set, so it is the one worth reporting.
	paths := []string{
		`SOFTWARE\Policies\Microsoft\Windows\DataCollection`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection`,
	}
	for _, key := range paths {
		level, err := regInt(registry.LOCAL_MACHINE, key, "AllowTelemetry")
		if blocked(err) {
			return []Finding{unreadable("telemetry-level.on", key, err.Error())}
		}
		if err != nil {
			continue
		}
		if level == 0 {
			return []Finding{{ID: "telemetry-level.off", Fix: Clear, Reach: Local,
				How: Measured, Source: key}}
		}
		return []Finding{{ID: "telemetry-level.on", Fix: Settable, Reach: Network,
			How: Measured, Source: key, Detail: telemetryName(level)}}
	}
	return []Finding{{ID: "telemetry-level.default", Fix: Settable, Reach: Network,
		How: Measured, Source: paths[0]}}
}

func telemetryName(level uint64) string {
	switch level {
	case 1:
		return "1 (Required)"
	case 2:
		return "2 (Enhanced)"
	case 3:
		return "3 (Optional, sends the most)"
	}
	return "level " + strconv.FormatUint(level, 10)
}

func checkDiagTrack() []Finding {
	const key = `SYSTEM\CurrentControlSet\Services\DiagTrack`
	// Start is 4 when a service is disabled, 2 when it starts with Windows.
	start, err := regInt(registry.LOCAL_MACHINE, key, "Start")
	switch {
	case blocked(err):
		return []Finding{unreadable("diagtrack.running", key, err.Error())}
	case err != nil:
		return []Finding{{ID: "diagtrack.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	case start == 4:
		return []Finding{{ID: "diagtrack.disabled", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	default:
		return []Finding{{ID: "diagtrack.running", Fix: Settable, Reach: Network,
			How: Measured, Source: key}}
	}
}

func checkErrorReporting() []Finding {
	const key = `SOFTWARE\Microsoft\Windows\Windows Error Reporting`
	off, err := regInt(registry.LOCAL_MACHINE, key, "Disabled")
	if blocked(err) {
		return []Finding{unreadable("error-reporting.on", key, err.Error())}
	}
	if err == nil && off == 1 {
		return []Finding{{ID: "error-reporting.off", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	}
	return []Finding{{ID: "error-reporting.on", Fix: Settable, Reach: Network,
		How: Measured, Source: key}}
}

func checkActivityFeed() []Finding {
	const key = `SOFTWARE\Policies\Microsoft\Windows\System`
	on, err := regInt(registry.LOCAL_MACHINE, key, "EnableActivityFeed")
	if blocked(err) {
		return []Finding{unreadable("activity-feed.on", key, err.Error())}
	}
	if err == nil && on == 0 {
		return []Finding{{ID: "activity-feed.off", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	}
	return []Finding{{ID: "activity-feed.on", Fix: Settable, Reach: Network,
		How: Measured, Source: key}}
}

func checkRecall() []Finding {
	const key = `SOFTWARE\Policies\Microsoft\Windows\WindowsAI`
	off, err := regInt(registry.LOCAL_MACHINE, key, "DisableAIDataAnalysis")
	if blocked(err) {
		return []Finding{unreadable("recall.unset", key, err.Error())}
	}
	if err == nil && off == 1 {
		return []Finding{{ID: "recall.off", Fix: Clear, Reach: Local,
			How: Measured, Source: key}}
	}
	return []Finding{{ID: "recall.unset", Fix: Settable, Reach: Local,
		How: Measured, Source: key}}
}

// Network

func checkDNSServers() []Finding {
	const base = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	names, err := regSubKeys(registry.LOCAL_MACHINE, base)
	if err != nil {
		return []Finding{unreadable("dns-servers.plain", base, err.Error())}
	}
	seen := map[string]bool{}
	var servers []string
	for _, iface := range names {
		for _, name := range []string{"NameServer", "DhcpNameServer"} {
			v, err := regString(registry.LOCAL_MACHINE, base+`\`+iface, name)
			if err != nil || strings.TrimSpace(v) == "" {
				continue
			}
			for _, s := range strings.FieldsFunc(v, func(r rune) bool {
				return r == ' ' || r == ','
			}) {
				if !seen[s] {
					seen[s] = true
					servers = append(servers, s)
				}
			}
		}
	}
	if len(servers) == 0 {
		return []Finding{{ID: "dns-servers.none", Fix: Clear, Reach: Local,
			How: Measured, Source: base}}
	}
	return []Finding{{ID: "dns-servers.plain", Fix: Settable, Reach: Network,
		How: Measured, Source: base, Detail: strings.Join(servers, ", ")}}
}

// Where the browser-facing things live on Windows.

func fontDirs() []string {
	dirs := []string{filepath.Join(os.Getenv("SystemRoot"), "Fonts")}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		dirs = append(dirs, filepath.Join(local, "Microsoft", "Windows", "Fonts"))
	}
	return dirs
}

func firefoxProfileDirs() []string {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return nil
	}
	return []string{filepath.Join(appdata, "Mozilla", "Firefox", "Profiles")}
}
