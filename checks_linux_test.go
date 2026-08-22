//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeMachine builds a directory that looks enough like /sys and /etc for
// the checks to read it. Testing a hardware reader against real hardware
// only ever tests the one machine you happen to own; this tests the ones
// you do not.
func fakeMachine(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := root
	root = dir
	t.Cleanup(func() { root = old })
	return dir
}

// only pulls the single finding a check returned, failing if there is not
// exactly one, since every check in this file reports exactly one thing.
func only(t *testing.T, found []Finding) Finding {
	t.Helper()
	if len(found) != 1 {
		t.Fatalf("expected one finding, got %d", len(found))
	}
	return found[0]
}

func TestLinuxReadsAnIntelMachine(t *testing.T) {
	fakeMachine(t, map[string]string{
		"proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\n" +
			"model name\t: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz\n",
		"sys/class/dmi/id/bios_vendor":    "LENOVO\n",
		"sys/class/dmi/id/bios_version":   "N1WET50W\n",
		"sys/class/dmi/id/bios_date":      "04/22/2024\n",
		"sys/class/dmi/id/product_uuid":   "3f1b0a2c-1111-2222-3333-444455556666\n",
		"sys/class/dmi/id/board_serial":   "PF1ABCDE\n",
		"sys/class/dmi/id/product_serial": "PF1ABCDE\n",
		"etc/machine-id":                  "9c1d0f2e8a7b4c6d8e0f1a2b3c4d5e6f\n",
		"etc/hostname":                    "thinkpad\n",
	})

	if f := only(t, checkManagementEngine()); f.ID != "management-engine.intel" {
		t.Errorf("an Intel machine came back as %q", f.ID)
	} else if f.How != Inferred {
		t.Errorf("with no mei device the engine should be inferred, got %s", certaintyKey(f.How))
	}

	if f := only(t, checkBootGuard()); f.ID != "boot-guard.likely" || f.How != Inferred {
		t.Errorf("Boot Guard came back as %q / %s", f.ID, certaintyKey(f.How))
	}

	f := only(t, checkFirmwareVendor())
	if f.Detail != "LENOVO N1WET50W, 04/22/2024" {
		t.Errorf("firmware detail came back as %q", f.Detail)
	}

	f = only(t, checkSystemUUID())
	if f.ID != "system-uuid.present" || f.Value != "3f1b0a2c-1111-2222-3333-444455556666" {
		t.Errorf("system UUID came back as %q / %q", f.ID, f.Value)
	}
	if !f.Sensitive {
		t.Error("the system UUID is not marked sensitive, so it would print in full")
	}

	if f := only(t, checkMachineID()); f.ID != "machine-id.present" ||
		f.Value != "9c1d0f2e8a7b4c6d8e0f1a2b3c4d5e6f" {
		t.Errorf("machine-id came back as %q / %q", f.ID, f.Value)
	}
	if f := only(t, checkHostname()); f.Value != "thinkpad" {
		t.Errorf("hostname came back as %q", f.Value)
	}
}

// A board the manufacturer never filled in must not be reported as
// carrying an identifier: doing so invents a fingerprint that is shared
// with every other unit off the same line.
func TestLinuxIgnoresPlaceholderSerials(t *testing.T) {
	fakeMachine(t, map[string]string{
		"sys/class/dmi/id/product_uuid":   "00000000-0000-0000-0000-000000000000\n",
		"sys/class/dmi/id/board_serial":   "To Be Filled By O.E.M.\n",
		"sys/class/dmi/id/product_serial": "Default string\n",
	})
	if f := only(t, checkSystemUUID()); f.ID != "system-uuid.absent" {
		t.Errorf("an all-zero UUID was reported as %q", f.ID)
	}
	if f := only(t, checkBoardSerial()); f.ID != "board-serial.absent" {
		t.Errorf("placeholder serials were reported as %q, value %q", f.ID, f.Value)
	}
}

// The DMI identifiers are root-only on purpose. Reading them unprivileged
// has to come back as a gap, never as "this machine has none".
func TestLinuxUnreadableIsNotTheSameAsAbsent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, so nothing is unreadable")
	}
	dir := fakeMachine(t, map[string]string{
		"sys/class/dmi/id/product_uuid": "3f1b0a2c-1111-2222-3333-444455556666\n",
	})
	locked := filepath.Join(dir, "sys/class/dmi/id/product_uuid")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skip("cannot take away read permission here")
	}

	f := only(t, checkSystemUUID())
	if f.How != Unreadable {
		t.Fatalf("a locked identifier came back as %s / %q, which reads as good news",
			certaintyKey(f.How), f.ID)
	}
	if f.Why == "" {
		t.Error("the gap does not say why it could not be read")
	}
	if f.Value != "" {
		t.Error("a finding we could not read still carried a value")
	}
}

func TestLinuxSecureBoot(t *testing.T) {
	// The variable is four bytes of EFI attributes then the flag.
	on := string([]byte{6, 0, 0, 0, 1})
	off := string([]byte{6, 0, 0, 0, 0})

	fakeMachine(t, map[string]string{secureBootVar: on, "sys/firmware/efi/x": ""})
	if f := only(t, checkSecureBoot()); f.ID != "secure-boot.on" {
		t.Errorf("Secure Boot on came back as %q", f.ID)
	}

	fakeMachine(t, map[string]string{secureBootVar: off, "sys/firmware/efi/x": ""})
	if f := only(t, checkSecureBoot()); f.ID != "secure-boot.off" {
		t.Errorf("Secure Boot off came back as %q", f.ID)
	}

	// No EFI at all means the machine booted in legacy mode, where the
	// question does not apply rather than being answered no.
	fakeMachine(t, map[string]string{"etc/hostname": "x"})
	if f := only(t, checkSecureBoot()); f.ID != "secure-boot.unknown" {
		t.Errorf("a legacy BIOS machine came back as %q", f.ID)
	}
}

func TestLinuxResolvConf(t *testing.T) {
	fakeMachine(t, map[string]string{
		"etc/resolv.conf": "# generated\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch lan\n",
	})
	f := only(t, checkResolvConf())
	if f.ID != "dns-servers.plain" || f.Detail != "1.1.1.1, 8.8.8.8" {
		t.Errorf("resolvers came back as %q / %q", f.ID, f.Detail)
	}

	// A loopback resolver means something local answers, and this file has
	// stopped saying who really sees the lookups.
	fakeMachine(t, map[string]string{"etc/resolv.conf": "nameserver 127.0.0.53\n"})
	if f := only(t, checkResolvConf()); f.ID != "dns-servers.stub" {
		t.Errorf("a stub resolver came back as %q", f.ID)
	}

	fakeMachine(t, map[string]string{"etc/resolv.conf": "# nothing here\n"})
	if f := only(t, checkResolvConf()); f.ID != "dns-servers.none" {
		t.Errorf("an empty resolv.conf came back as %q", f.ID)
	}
}

func TestLinuxDistributionTelemetry(t *testing.T) {
	fakeMachine(t, map[string]string{
		"etc/popularity-contest.conf": "PARTICIPATE=\"yes\"\nMAILTO=\"survey@example\"\n",
		"etc/default/apport":          "enabled=1\n",
	})
	if f := only(t, checkPopularityContest()); f.ID != "popularity-contest.on" {
		t.Errorf("an opted-in survey came back as %q", f.ID)
	}
	if f := only(t, checkApport()); f.ID != "crash-reporting.on" {
		t.Errorf("enabled crash reporting came back as %q", f.ID)
	}

	fakeMachine(t, map[string]string{
		"etc/popularity-contest.conf": "PARTICIPATE=\"no\"\n",
		"etc/default/apport":          "enabled=0\n",
	})
	if f := only(t, checkPopularityContest()); f.ID != "popularity-contest.off" {
		t.Errorf("an opted-out survey came back as %q", f.ID)
	}
	if f := only(t, checkApport()); f.ID != "crash-reporting.off" {
		t.Errorf("disabled crash reporting came back as %q", f.ID)
	}

	// Neither package installed is the common case and must not be an error.
	fakeMachine(t, map[string]string{"etc/hostname": "x"})
	if f := only(t, checkPopularityContest()); f.ID != "popularity-contest.absent" {
		t.Errorf("a machine without the survey came back as %q", f.ID)
	}
}

// An ARM board has no x86 vendor line at all, and the report should say so
// rather than pretending it found an Intel chipset.
func TestLinuxNonX86(t *testing.T) {
	fakeMachine(t, map[string]string{
		"proc/cpuinfo": "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\n",
	})
	if f := only(t, checkManagementEngine()); f.ID != "management-engine.unknown" {
		t.Errorf("an ARM board came back as %q", f.ID)
	}
	if f := only(t, checkBootGuard()); f.ID != "boot-guard.notintel" {
		t.Errorf("Boot Guard on ARM came back as %q", f.ID)
	}
}
