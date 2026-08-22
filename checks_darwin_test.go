//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestParseIoreg(t *testing.T) {
	// Trimmed down, but the shape is what ioreg actually prints: quoted
	// key, an equals sign, and a value that is quoted only when it is text.
	const output = `+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000247, registered>
    {
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
      "IOPlatformUUID" = "3F1B0A2C-1111-2222-3333-444455556666"
      "IOPlatformSerialNumber" = "C02ABCDEFGHI"
      "model" = <"Mac14,9">
      "target-type" = <"J316s">
    }`

	for _, c := range []struct{ key, want string }{
		{"IOPlatformUUID", "3F1B0A2C-1111-2222-3333-444455556666"},
		{"IOPlatformSerialNumber", "C02ABCDEFGHI"},
		{"nothing-like-this", ""},
	} {
		if got := parseIoreg(output, c.key); got != c.want {
			t.Errorf("%s came back as %q, wanted %q", c.key, got, c.want)
		}
	}
}

// runTool must refuse anything not on the allowlist, and refuse it without
// running it. A typo in a path should not become an arbitrary execution.
func TestRunToolRefusesAnythingElse(t *testing.T) {
	for _, path := range []string{"/bin/sh", "ioreg", "/usr/bin/../../bin/sh", ""} {
		if _, err := runTool(path); err == nil {
			t.Errorf("runTool agreed to run %q", path)
		}
	}
}

// The one that closes the real gap.
//
// Every other test here passes whether or not ioreg actually answered: a
// check that could not read something returns a well formed gap, and a well
// formed gap is a valid result. So green on macOS never proved the Mac was
// read, only that nothing crashed.
//
// This asserts the checks came back Measured. On any Mac, including the
// virtual ones the CI runs on, ioreg and csrutil are present, so a gap here
// means something is genuinely broken and the build should say so.
func TestMacReallyReadsTheMachine(t *testing.T) {
	cases := []struct {
		what string
		run  func() []Finding
	}{
		{"system UUID", checkSystemUUID},
		{"board serial", checkBoardSerial},
		{"SIP", checkSIP},
		{"firmware vendor", checkFirmwareVendor},
	}
	for _, c := range cases {
		found := c.run()
		if len(found) != 1 {
			t.Errorf("%s returned %d findings", c.what, len(found))
			continue
		}
		f := found[0]
		if f.How == Unreadable {
			t.Errorf("%s came back as a gap (%s), so the Mac was not actually read",
				c.what, f.Why)
			continue
		}
		t.Logf("%s: %s (%s)", c.what, f.ID, certaintyKey(f.How))
	}

	// And the UUID specifically has to be a real one, not a placeholder, or
	// the parsing is finding the line and taking the wrong half of it.
	f := checkSystemUUID()[0]
	if f.ID == "system-uuid.present" && !strings.Contains(f.Value, "-") {
		t.Errorf("the UUID came back as %q, which is not the shape of one", f.Value)
	}
}
