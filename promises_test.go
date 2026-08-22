package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The README makes three promises. Promises in a README rot; promises with
// a test behind them do not.

// Nothing in here may open a registry key for writing. Somebody adding a
// "just fix it for me" feature later should have to delete this test on
// purpose rather than slip past it.
func TestNeverWrites(t *testing.T) {
	banned := []string{
		"SET_VALUE", "CreateKey", "SetStringValue", "SetDWordValue",
		"SetQWordValue", "SetBinaryValue", "DeleteKey", "DeleteValue",
		"ALL_ACCESS", "os.WriteFile", "os.Create",
	}
	scanSource(t, banned, "this tool must not write anything")
}

// No network code at all. Not "we promise not to call home": no way to.
func TestNeverOpensTheNetwork(t *testing.T) {
	banned := []string{`"net"`, `"net/http"`, `"net/url"`, "net.Dial", "http.Get", "http.Post"}
	scanSource(t, banned, "this tool must have no way to reach the network")
}

func scanSource(t *testing.T, banned []string, why string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range banned {
			if bytes.Contains(src, []byte(bad)) {
				t.Errorf("%s contains %q: %s", name, bad, why)
			}
		}
	}
}

// An identifier must not reach the screen unless it was asked for. A report
// people paste into a bug thread should not carry the fingerprints of the
// machine it came from.
func TestIdentifiersAreMaskedUnlessAsked(t *testing.T) {
	secret := "4b8e03a6-dead-beef-0000-000000000000"
	f := Finding{ID: "machine-guid.present", Value: secret, Sensitive: true}

	masked := f.Shown(false)
	if strings.Contains(masked, secret) {
		t.Fatal("the raw value leaked into the masked form")
	}
	if !strings.HasPrefix(masked, "hidden:") {
		t.Errorf("masked value looks like %q, which does not read as masked", masked)
	}
	if f.Shown(true) != secret {
		t.Error("--reveal did not give back the real value")
	}

	// The same input has to mask to the same digest, or nobody can tell
	// whether a change they made actually took effect.
	if f.Shown(false) != masked {
		t.Error("masking is not stable across calls")
	}
	other := Finding{Value: "something else", Sensitive: true}
	if other.Shown(false) == masked {
		t.Error("two different values masked to the same digest")
	}
}

// The rendered report must not contain a sensitive value either, since that
// is the thing that actually reaches the screen.
func TestReportDoesNotLeak(t *testing.T) {
	cat, err := loadCatalog("en")
	if err != nil {
		t.Fatal(err)
	}
	secret := "SUPER-SECRET-SERIAL-12345"
	results := []Result{{
		Check:   Check{ID: "board-serial", Group: "identity"},
		Finding: Finding{ID: "board-serial.present", Value: secret, Sensitive: true},
	}}

	var out bytes.Buffer
	render(&out, cat, results, false, true)
	if strings.Contains(out.String(), secret) {
		t.Error("the printed report contained the raw serial")
	}

	var asJSON bytes.Buffer
	if err := renderJSON(&asJSON, cat, results, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(asJSON.String(), secret) {
		t.Error("the JSON output contained the raw serial")
	}
}

// Silence is not a result. A check that finds nothing to say must still say
// something, because an empty report reads as a clean machine.
func TestNoCheckStaysSilent(t *testing.T) {
	for _, c := range platformChecks() {
		found := c.Run()
		if len(found) == 0 {
			t.Errorf("check %q returned nothing, which would read as good news", c.ID)
			continue
		}
		for _, f := range found {
			if f.ID == "" {
				t.Errorf("check %q returned a finding with no ID", c.ID)
			}
			if f.How != Unreadable && f.Source == "" {
				t.Errorf("finding %q does not say where it looked", f.ID)
			}
			if f.How != Measured && f.Why == "" {
				t.Errorf("finding %q is %s but does not say why",
					f.ID, certaintyKey(f.How))
			}
		}
	}
}

// A gap has to survive into the summary as a gap. If an unreadable finding
// were counted as a verdict, the tool would be lying in exactly the way it
// was written to avoid.
func TestGapsAreReportedAsGaps(t *testing.T) {
	cat, err := loadCatalog("en")
	if err != nil {
		t.Fatal(err)
	}
	results := []Result{{
		Check:   Check{ID: "telemetry-level", Group: "telemetry"},
		Finding: unreadable("telemetry-level.on", `HKLM\SOFTWARE\...`, "Access is denied."),
	}}

	var out bytes.Buffer
	render(&out, cat, results, false, false)
	text := out.String()

	for _, want := range []string{
		cat.ui("fix.short.unknown"),
		cat.ui("summary.gaps"),
		"Access is denied.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report never mentions %q", want)
		}
	}
	// And it must not be counted among the things we actually established.
	if strings.Contains(text, cat.ui("fix.settable")+" ") {
		t.Error("an unreadable finding was counted as a settable one")
	}
}
