package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Preferences file, trimmed to the parts that matter and keeping the
// nesting, because the nesting is where this goes wrong.
const prefsWorst = `{
  "profile": { "cookie_controls_mode": 0, "name": "Person 1" },
  "privacy_sandbox": { "m1": { "topics_enabled": true, "ad_measurement_enabled": true } },
  "search": { "suggest_enabled": true },
  "dns_over_https": { "mode": "off" }
}`

const prefsBest = `{
  "profile": { "cookie_controls_mode": 2 },
  "privacy_sandbox": { "m1": { "topics_enabled": false, "ad_measurement_enabled": false } },
  "search": { "suggest_enabled": false },
  "dns_over_https": { "mode": "secure" }
}`

func TestReadChromiumSettings(t *testing.T) {
	worst, err := readSettings([]byte(prefsWorst))
	if err != nil {
		t.Fatal(err)
	}
	if !worst.Topics || !worst.AdMeasurement || !worst.Suggest {
		t.Errorf("the permissive profile read as %+v", worst)
	}
	if worst.ThirdParty || worst.EncryptedDNS {
		t.Errorf("the permissive profile claimed protections it does not have: %+v", worst)
	}

	best, err := readSettings([]byte(prefsBest))
	if err != nil {
		t.Fatal(err)
	}
	if best.Topics || best.AdMeasurement || best.Suggest {
		t.Errorf("the locked-down profile read as %+v", best)
	}
	if !best.ThirdParty || !best.EncryptedDNS {
		t.Errorf("the locked-down profile lost its protections: %+v", best)
	}
}

// Chromium's Preferences has no promised schema and gains and loses keys
// between versions. A missing key has to read as off rather than crash or
// be guessed at, since guessing here means telling somebody they are
// protected when nobody has checked.
func TestChromiumSettingsSurviveAMissingSchema(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"profile": {}}`,
		`{"privacy_sandbox": null}`,
		`{"privacy_sandbox": {"m1": "not an object"}}`,
		`{"profile": {"cookie_controls_mode": "two"}}`,
		`{"dns_over_https": {"mode": 3}}`,
	} {
		s, err := readSettings([]byte(raw))
		if err != nil {
			t.Errorf("%s failed to parse: %v", raw, err)
			continue
		}
		if s.Topics || s.AdMeasurement || s.ThirdParty || s.EncryptedDNS || s.Suggest {
			t.Errorf("%s produced %+v, but nothing there was actually set", raw, s)
		}
	}

	if _, err := readSettings([]byte("this is not json")); err == nil {
		t.Error("rubbish parsed without complaint")
	}
}

// People have more than one profile, and a report about the first one is a
// report about a browser they may barely use.
func TestChromiumFindsEveryProfile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Default", "Profile 1", "Profile 2"} {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "Preferences"),
			[]byte(prefsBest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Directories that are not profiles, and a profile with no Preferences
	// yet, must both be ignored rather than counted.
	os.MkdirAll(filepath.Join(dir, "ShaderCache"), 0o755)
	os.MkdirAll(filepath.Join(dir, "Profile 9"), 0o755)

	found := chromiumProfiles(dir)
	if len(found) != 3 {
		t.Errorf("found %d profiles, expected 3: %v", len(found), found)
	}
	for _, p := range found {
		if !strings.HasSuffix(p, "Preferences") {
			t.Errorf("%q is not a Preferences file", p)
		}
	}

	if got := chromiumProfiles(filepath.Join(dir, "nothing here")); got != nil {
		t.Errorf("a missing directory returned %v", got)
	}
}
