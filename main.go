package main

// glasshouse looks at what this machine gives away about you, and sorts
// what it finds by whether you can do anything about it.
//
// It reads. It never writes, and it never opens a socket: a tool that asks
// you to trust it with your privacy has no business phoning home, and the
// easiest way to prove that is to have no code that could.

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var version = "unreleased"

func main() {
	lang := flag.String("lang", "en", "language for the report")
	reveal := flag.Bool("reveal", false,
		"print identifiers in full instead of masking them")
	asJSON := flag.Bool("json", false, "write the findings as JSON")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("glasshouse " + version)
		return
	}

	cat, err := loadCatalog(*lang)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	results := collect()

	if *asJSON {
		if err := renderJSON(os.Stdout, cat, results, *reveal); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	render(os.Stdout, cat, results, *reveal, elevated())
}

func collect() []Result {
	var results []Result
	for _, c := range platformChecks() {
		found := c.Run()
		if len(found) == 0 {
			// A check that returns nothing is a bug, not a clean machine,
			// and the report says so rather than quietly dropping it.
			found = []Finding{unreadable("check.silent", c.ID,
				"the check returned no result at all")}
		}
		for _, f := range found {
			results = append(results, Result{Check: c, Finding: f})
		}
	}
	return results
}

func usage() {
	fmt.Fprintln(os.Stderr, `glasshouse - see what your computer says about you

  glasshouse                 look at this machine and report
  glasshouse --lang es       report in another language
  glasshouse --reveal        show identifiers in full, not masked
  glasshouse --json          machine-readable output
  glasshouse --version

Languages available: `+strings.Join(availableLanguages(), ", ")+`

It only reads. It changes nothing and sends nothing anywhere.
Some checks need administrator rights; without them the report says
which ones it could not read instead of leaving them out.`)
}
