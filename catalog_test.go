package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// findingID matches the shape of a catalogue key: two dotted lowercase
// parts, like "recall.unset". Check IDs have no dot, so they do not match.
var findingID = regexp.MustCompile(`"([a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*)"`)

// idsInSource pulls every finding ID the program can emit straight out of
// the source. Going through the source rather than through a run means the
// test covers the branches this machine happens not to take, which is most
// of them: no single computer has both an Intel and an AMD coprocessor.
func idsInSource(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			// Take every literal of the right shape, and skip only the
			// lines that look up an interface string, which share it.
			//
			// This started out the other way round, listing the ways a
			// finding gets its ID, and missed a new one three times: ID:,
			// then ID =, then id := and id, fix =. Listing the one thing
			// to leave out is the only version that stays correct.
			if strings.Contains(line, ".ui(") {
				continue
			}
			for _, m := range findingID.FindAllStringSubmatch(line, -1) {
				if looksLikeAFilename(m[1]) {
					continue
				}
				seen[m[1]] = true
			}
		}
	}
	var ids []string
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// The whole product of this tool is the explanation attached to a finding.
// A finding the catalogue has never heard of renders as [[its-id]], which
// is a bug that only shows up on somebody else's hardware, where you are
// not watching.
func TestEveryFindingHasText(t *testing.T) {
	cat, err := loadCatalog("en")
	if err != nil {
		t.Fatal(err)
	}
	ids := idsInSource(t)
	if len(ids) < 10 {
		t.Fatalf("only found %d finding IDs in the source, the scan is broken", len(ids))
	}
	for _, id := range ids {
		text, ok := cat.Checks[id]
		if !ok {
			t.Errorf("%s can be reported but has no entry in messages/en.json", id)
			continue
		}
		if strings.TrimSpace(text.Title) == "" {
			t.Errorf("%s has no title", id)
		}
		if strings.TrimSpace(text.Reveals) == "" {
			t.Errorf("%s does not say what it reveals, which is the point of it", id)
		}
	}
	t.Logf("%d finding IDs, all with text", len(ids))
}

// A catalogue entry nobody can ever reach is dead weight that translators
// would waste their time on.
func TestNoOrphanText(t *testing.T) {
	cat, err := loadCatalog("en")
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]bool{}
	for _, id := range idsInSource(t) {
		live[id] = true
	}
	for id := range cat.Checks {
		if !live[id] {
			t.Errorf("messages/en.json has text for %s, which nothing can report", id)
		}
	}
}

// Every language file has to parse, and every one of them has to carry the
// interface strings, since those have no sensible English fallback on a
// screen that is otherwise in Spanish.
func TestEveryLanguageLoads(t *testing.T) {
	for _, code := range availableLanguages() {
		cat, err := loadCatalog(code)
		if err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if cat.Code != code {
			t.Errorf("messages/%s.json declares code %q", code, cat.Code)
		}
		for key := range english.UI {
			if _, ok := cat.UI[key]; !ok {
				t.Errorf("%s is missing the interface string %q", code, key)
			}
		}
	}
}

// A half-finished translation has to stay useful: missing entries fall back
// to English rather than leaving a blank where an explanation should be.
//
// Tested against a catalogue built right here rather than against a real
// language file, so it keeps testing the fallback even now that Spanish is
// complete and has nothing left to fall back from.
func TestPartialTranslationFallsBack(t *testing.T) {
	if _, err := loadCatalog("en"); err != nil {
		t.Fatal(err)
	}
	half := Catalog{Code: "xx", Checks: map[string]CheckText{
		"recall.off": {Title: "Traducido"},
	}}

	// Half an entry: the title is translated, the rest is not.
	done := half.check("recall.off")
	if done.Title != "Traducido" {
		t.Errorf("the translated title came back as %q", done.Title)
	}
	if done.Reveals != english.Checks["recall.off"].Reveals || done.Reveals == "" {
		t.Error("a half-translated entry did not fill its gaps from English")
	}

	// No entry at all.
	missing := half.check("tpm.present")
	if missing.Title != english.Checks["tpm.present"].Title {
		t.Errorf("an untranslated entry came back as %q instead of falling back", missing.Title)
	}
	if missing.Reveals == "" {
		t.Error("an untranslated explanation came back blank, which is the worst outcome")
	}
}

// How complete each translation is. Not a failure, because a partial one is
// useful from the day it starts, but worth seeing when checks get added
// faster than they get translated.
func TestTranslationCoverage(t *testing.T) {
	en, err := loadCatalog("en")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range availableLanguages() {
		if code == "en" {
			continue
		}
		cat, err := loadCatalog(code)
		if err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		have := 0
		for id := range en.Checks {
			if _, ok := cat.Checks[id]; ok {
				have++
			}
		}
		t.Logf("%s covers %d of %d findings", code, have, len(en.Checks))
	}
}

// Filenames have exactly the same shape as a finding ID, and there is no
// clever way to tell "prefs.js" from "tpm.present" by looking at it. So the
// extensions get named.
var fileExtensions = map[string]bool{
	"dll": true, "js": true, "json": true, "exe": true, "go": true,
	"conf": true, "so": true, "sh": true, "txt": true, "md": true,
	"yml": true, "yaml": true, "log": true, "cfg": true,
}

func looksLikeAFilename(id string) bool {
	dot := strings.LastIndex(id, ".")
	return dot >= 0 && fileExtensions[id[dot+1:]]
}
