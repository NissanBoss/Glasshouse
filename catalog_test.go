package main

import (
	"os"
	"path/filepath"
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
			// Only lines that actually build a finding or report a gap.
			if !strings.Contains(line, "ID:") && !strings.Contains(line, "ID =") &&
				!strings.Contains(line, "unreadable(") {
				continue
			}
			for _, m := range findingID.FindAllStringSubmatch(line, -1) {
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
func TestPartialTranslationFallsBack(t *testing.T) {
	if _, err := os.Stat(filepath.Join("messages", "es.json")); err != nil {
		t.Skip("no Spanish catalogue to test against")
	}
	es, err := loadCatalog("es")
	if err != nil {
		t.Fatal(err)
	}
	// tpm.present is deliberately untranslated, so it should come back in
	// English rather than empty.
	text := es.check("tpm.present")
	if text.Title == "" || strings.HasPrefix(text.Title, "[[") {
		t.Errorf("untranslated entry came back as %q instead of falling back", text.Title)
	}
	if text.Reveals == "" {
		t.Error("untranslated explanation came back blank, which is the worst outcome")
	}
}
