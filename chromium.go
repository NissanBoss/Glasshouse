package main

// Chrome, Edge and the rest of the Chromium family.
//
// They get a check separate from Firefox because they answer a different
// question. Firefox has a switch that makes you look like everybody else.
// Chromium has no such thing, and no plan for one, so its privacy settings
// are all about cookies and ads rather than about being unique.
//
// The interesting one is the Privacy Sandbox: Topics works out what you are
// interested in from the sites you visit and hands that to advertisers, and
// it does it inside the browser rather than through a tracker somebody else
// wrote. Turning off third-party cookies does not touch it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// chromiumBrowser is one installed browser and where its profile lives.
type chromiumBrowser struct {
	Name string
	Dir  string // the User Data directory
}

// settings are the preferences worth reporting, pulled out of the profile.
type settings struct {
	Topics        bool
	AdMeasurement bool
	ThirdParty    bool // third-party cookies blocked
	EncryptedDNS  bool
	Suggest       bool // what you type goes to the search engine as you type
}

// readSettings digs the handful of values we care about out of a Chromium
// Preferences file, which is one large JSON object with no schema promised.
// Anything missing is left false rather than guessed at.
func readSettings(raw []byte) (settings, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return settings{}, err
	}
	var s settings
	s.Topics = boolAt(doc, "privacy_sandbox", "m1", "topics_enabled")
	s.AdMeasurement = boolAt(doc, "privacy_sandbox", "m1", "ad_measurement_enabled")
	s.Suggest = boolAt(doc, "search", "suggest_enabled")

	// cookie_controls_mode is 2 when third-party cookies are blocked
	// everywhere, 1 for incognito only, 0 for not at all.
	if n, ok := numberAt(doc, "profile", "cookie_controls_mode"); ok && n == 2 {
		s.ThirdParty = true
	}
	// dns_over_https.mode is "secure" or "automatic" when it is on at all.
	if mode, ok := stringAt(doc, "dns_over_https", "mode"); ok &&
		(mode == "secure" || mode == "automatic") {
		s.EncryptedDNS = true
	}
	return s, nil
}

func dig(doc map[string]any, path ...string) (any, bool) {
	var current any = doc
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = m[key]; !ok {
			return nil, false
		}
	}
	return current, true
}

func boolAt(doc map[string]any, path ...string) bool {
	v, ok := dig(doc, path...)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func numberAt(doc map[string]any, path ...string) (float64, bool) {
	v, ok := dig(doc, path...)
	if !ok {
		return 0, false
	}
	n, ok := v.(float64)
	return n, ok
}

func stringAt(doc map[string]any, path ...string) (string, bool) {
	v, ok := dig(doc, path...)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// chromiumProfiles finds every profile inside a User Data directory. People
// have more than one, and a report about the first one is a report about a
// browser the person may barely use.
func chromiumProfiles(userData string) []string {
	entries, err := os.ReadDir(userData)
	if err != nil {
		return nil
	}
	var found []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name != "Default" && !strings.HasPrefix(name, "Profile ") {
			continue
		}
		prefs := filepath.Join(userData, name, "Preferences")
		if _, err := os.Stat(prefs); err == nil {
			found = append(found, prefs)
		}
	}
	return found
}

func checkChromium() []Finding {
	browsers := chromiumBrowsers()
	var looked []string
	seen := false
	// Worst case across every profile: someone with Topics on in one of
	// them has Topics on, whichever window they happen to open.
	worst := settings{ThirdParty: true, EncryptedDNS: true}

	for _, b := range browsers {
		for _, prefs := range chromiumProfiles(b.Dir) {
			raw, err := os.ReadFile(prefs)
			if err != nil {
				continue
			}
			s, err := readSettings(raw)
			if err != nil {
				continue
			}
			seen = true
			looked = appendOnce(looked, b.Name)
			worst.Topics = worst.Topics || s.Topics
			worst.AdMeasurement = worst.AdMeasurement || s.AdMeasurement
			worst.Suggest = worst.Suggest || s.Suggest
			worst.ThirdParty = worst.ThirdParty && s.ThirdParty
			worst.EncryptedDNS = worst.EncryptedDNS && s.EncryptedDNS
		}
	}

	where := "the Chromium profile directories"
	if len(browsers) > 0 {
		var dirs []string
		for _, b := range browsers {
			dirs = append(dirs, b.Dir)
		}
		where = strings.Join(dirs, ", ")
	}
	if !seen {
		return []Finding{{ID: "chromium.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}

	detail := strings.Join(looked, ", ")
	if notes := describeSettings(worst); notes != "" {
		detail += ": " + notes
	}
	id, fix := "chromium.topics-off", Settable
	if worst.Topics || worst.AdMeasurement {
		id = "chromium.topics-on"
	}
	return []Finding{{ID: id, Fix: fix, Reach: Network, How: Measured,
		Source: where, Detail: detail}}
}

func describeSettings(s settings) string {
	var notes []string
	if s.Topics {
		notes = append(notes, "ad topics on")
	}
	if s.AdMeasurement {
		notes = append(notes, "ad measurement on")
	}
	if !s.ThirdParty {
		notes = append(notes, "third-party cookies allowed")
	}
	if s.EncryptedDNS {
		notes = append(notes, "encrypted DNS on")
	}
	if s.Suggest {
		notes = append(notes, "search suggestions on")
	}
	return strings.Join(notes, ", ")
}
