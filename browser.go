package main

// The browser, which is where the tracking people actually meet happens.
//
// Everything above this file is about being recognised as a machine. This
// is about being recognised as a person, by every site you visit, without
// any of them storing a cookie.
//
// A local tool cannot run the fingerprinting scripts against you, so it
// does not pretend to. What it can do is look at the two things that decide
// how you come out of them: how unusual the machine looks from a browser's
// point of view, and whether the browser is set up to lie about it.

import (
	"os"
	"path/filepath"
	"strings"
)

func browserChecks() []Check {
	return []Check{
		{ID: "installed-fonts", Group: "browser", Run: checkFonts},
		{ID: "firefox", Group: "browser", Run: checkFirefox},
	}
}

// Fonts
//
// The list of fonts you have installed is one of the strongest signals in
// browser fingerprinting, and one almost nobody thinks about. A browser can
// test for them one by one, and a set nobody else has is as good as a name.

// fontExtensions are the files worth counting. Counting everything in the
// directory would fold in caches and licence files and inflate the number.
var fontExtensions = map[string]bool{
	".ttf": true, ".otf": true, ".ttc": true, ".woff": true,
	".woff2": true, ".pfb": true, ".pfm": true,
}

func countFonts(dirs []string) (int, []string) {
	seen := map[string]bool{}
	var looked []string
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		looked = append(looked, dir)
		// Walk rather than list: Linux buries fonts several levels deep.
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if fontExtensions[strings.ToLower(filepath.Ext(path))] {
				seen[strings.ToLower(d.Name())] = true
			}
			return nil
		})
	}
	return len(seen), looked
}

func checkFonts() []Finding {
	count, looked := countFonts(fontDirs())
	if len(looked) == 0 {
		return []Finding{unreadable("installed-fonts.many", strings.Join(fontDirs(), ", "),
			"none of the usual font directories could be read")}
	}
	where := strings.Join(looked, ", ")

	// The thresholds are rough on purpose and the text says so. What
	// matters is not the exact number but which side of "stock" you are on.
	id := "installed-fonts.stock"
	fix := Clear
	if count > 400 {
		id, fix = "installed-fonts.many", Costly
	}
	return []Finding{{ID: id, Fix: fix, Reach: Network, How: Measured,
		Source: where, Detail: plural(count, "font", "fonts")}}
}

func plural(n int, one, many string) string {
	word := many
	if n == 1 {
		word = one
	}
	return itoa(n) + " " + word
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// Firefox
//
// Firefox gets a check of its own because it is the only mainstream browser
// with a real anti-fingerprinting switch. The Chromium family has settings
// about cookies and ads, but nothing that makes you look like everybody
// else, which is the only thing that actually works.

// readPrefs pulls the user_pref lines out of a prefs.js. The file is
// JavaScript, but the interesting part is one call per line:
//
//	user_pref("privacy.resistFingerprinting", true);
func readPrefs(content string) map[string]string {
	prefs := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "user_pref(")
		if !ok {
			continue
		}
		rest = strings.TrimSuffix(strings.TrimSuffix(rest, ";"), ")")
		name, value, ok := strings.Cut(rest, ",")
		if !ok {
			continue
		}
		name = strings.Trim(strings.TrimSpace(name), `"`)
		value = strings.Trim(strings.TrimSpace(value), `"`)
		prefs[name] = value
	}
	return prefs
}

// profilePrefs reads every Firefox profile it can find and folds them into
// one answer. Someone with a hardened profile and a default one is not
// hardened: they are whichever one they happen to open.
func profilePrefs(dirs []string) (found bool, hardened bool, notes []string) {
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name(), "prefs.js"))
			if err != nil {
				continue
			}
			found = true
			prefs := readPrefs(string(raw))
			if prefs["privacy.resistFingerprinting"] == "true" {
				hardened = true
			}
			if prefs["network.trr.mode"] == "2" || prefs["network.trr.mode"] == "3" {
				notes = appendOnce(notes, "encrypted DNS on")
			}
			if prefs["toolkit.telemetry.enabled"] == "false" {
				notes = appendOnce(notes, "telemetry off")
			}
			if prefs["privacy.trackingprotection.enabled"] == "true" {
				notes = appendOnce(notes, "tracking protection on")
			}
		}
	}
	return found, hardened, notes
}

func appendOnce(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func checkFirefox() []Finding {
	dirs := firefoxProfileDirs()
	found, hardened, notes := profilePrefs(dirs)
	where := strings.Join(dirs, ", ")

	if !found {
		return []Finding{{ID: "firefox.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	id, fix := "firefox.resist-off", Settable
	if hardened {
		id, fix = "firefox.resist-on", Clear
	}
	return []Finding{{ID: id, Fix: fix, Reach: Network, How: Measured,
		Source: where, Detail: strings.Join(notes, ", ")}}
}
