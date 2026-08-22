package main

// Every human-readable string lives in messages/<lang>.json and is loaded
// from here. Nothing a person reads is written in Go anywhere else in this
// program, so adding a language means adding one file and touching no code.

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed messages/*.json
var messageFiles embed.FS

type CheckText struct {
	Title string `json:"title"`
	// Reveals answers the only question that matters to the reader: what
	// does this say about me?
	Reveals string `json:"reveals"`
	// Fix says what to do, or explains why there is nothing to do. The
	// second case is the more valuable one and the harder to write.
	Fix string `json:"fix"`
}

type Catalog struct {
	Language string               `json:"language"`
	Code     string               `json:"code"`
	UI       map[string]string    `json:"ui"`
	Checks   map[string]CheckText `json:"checks"`
}

// english is the fallback. A half-translated file should show English for
// the missing lines rather than blanks, because a blank explanation in a
// tool whose whole job is explaining is worse than the wrong language.
var english Catalog

func loadCatalog(code string) (Catalog, error) {
	if english.Code == "" {
		var err error
		if english, err = readCatalog("en"); err != nil {
			return Catalog{}, err
		}
	}
	if code == "" || code == "en" {
		return english, nil
	}
	c, err := readCatalog(code)
	if err != nil {
		return Catalog{}, err
	}
	return c, nil
}

func readCatalog(code string) (Catalog, error) {
	raw, err := messageFiles.ReadFile("messages/" + code + ".json")
	if err != nil {
		return Catalog{}, fmt.Errorf("no messages for language %q (have: %s)",
			code, strings.Join(availableLanguages(), ", "))
	}
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return Catalog{}, fmt.Errorf("messages/%s.json is not valid JSON: %w", code, err)
	}
	return c, nil
}

func availableLanguages() []string {
	entries, err := messageFiles.ReadDir("messages")
	if err != nil {
		return nil
	}
	var codes []string
	for _, e := range entries {
		codes = append(codes, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(codes)
	return codes
}

func (c Catalog) ui(key string) string {
	if s, ok := c.UI[key]; ok && s != "" {
		return s
	}
	if s, ok := english.UI[key]; ok && s != "" {
		return s
	}
	// Loud on purpose. A missing key is a bug in the catalogue and should
	// look like one instead of quietly printing nothing.
	return "[[" + key + "]]"
}

func (c Catalog) check(id string) CheckText {
	t, ok := c.Checks[id]
	if !ok {
		t = CheckText{}
	}
	fallback := english.Checks[id]
	if t.Title == "" {
		t.Title = fallback.Title
	}
	if t.Reveals == "" {
		t.Reveals = fallback.Reveals
	}
	if t.Fix == "" {
		t.Fix = fallback.Fix
	}
	if t.Title == "" {
		t.Title = "[[" + id + "]]"
	}
	return t
}
