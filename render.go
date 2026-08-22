package main

// Turning findings into something worth reading.
//
// The order is deliberate. Sealed things come last, not first, even though
// they are the scariest: a report that opens with four paragraphs about
// coprocessors you cannot remove teaches people that privacy is hopeless,
// and they close it. What they can actually change goes at the top.
//
// What could not be checked goes last of all inside its group, and then
// gets its own loud line in the summary, because a gap in the report is
// not a clean result and must never be able to pass for one.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

var groupOrder = []string{"telemetry", "identity", "network", "firmware", "platform"}

// fixOrder puts the actionable first and the immovable last.
var fixOrder = []Fixability{Settable, Costly, Sealed, Clear}

type Result struct {
	Check   Check
	Finding Finding
}

func render(out io.Writer, cat Catalog, results []Result, reveal, elevated bool) {
	title := cat.ui("title")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+title)
	fmt.Fprintln(out, "  "+strings.Repeat("=", len(title)))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+cat.ui("intro"))
	fmt.Fprintln(out)

	gaps := 0
	counts := map[Fixability]int{}
	for _, r := range results {
		if r.Finding.How == Unreadable {
			gaps++
			continue
		}
		counts[r.Finding.Fix]++
	}

	for _, group := range groupsPresent(results) {
		fmt.Fprintln(out, "  "+strings.ToUpper(cat.ui("group."+group)))
		fmt.Fprintln(out)
		for _, r := range sortedForGroup(results, group) {
			renderOne(out, cat, r, reveal)
		}
	}

	fmt.Fprintln(out, "  "+cat.ui("summary.title"))
	fmt.Fprintln(out)
	for _, f := range fixOrder {
		if counts[f] == 0 {
			continue
		}
		fmt.Fprintf(out, "    %-30s %d\n", cat.ui("fix."+fixKey(f)), counts[f])
	}
	if gaps > 0 {
		fmt.Fprintf(out, "    %-30s %d\n", cat.ui("summary.gaps"), gaps)
		fmt.Fprintln(out)
		for _, line := range wrap(cat.ui("summary.gaps.warning"), 66) {
			fmt.Fprintln(out, "    "+line)
		}
		if !elevated {
			fmt.Fprintln(out)
			for _, line := range wrap(cat.ui("summary.gaps.elevate"), 66) {
				fmt.Fprintln(out, "    "+line)
			}
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+cat.ui("closing"))
	fmt.Fprintln(out)
}

func renderOne(out io.Writer, cat Catalog, r Result, reveal bool) {
	f := r.Finding
	text := cat.check(f.ID)
	const pad = "        "

	tag := cat.ui("fix.short." + fixKey(f.Fix))
	if f.How == Unreadable {
		tag = cat.ui("fix.short.unknown")
	}
	fmt.Fprintf(out, "    [%s] %s\n", tag, text.Title)

	if f.How == Unreadable {
		fmt.Fprintf(out, "%s%s %s\n", pad, cat.ui("label.couldnot"), f.Why)
		fmt.Fprintf(out, "%s%s %s\n", pad, cat.ui("label.source"), f.Source)
		for _, line := range wrap(cat.ui("gap.meaning"), 66) {
			fmt.Fprintln(out, pad+line)
		}
		fmt.Fprintln(out)
		return
	}

	if v := f.Shown(reveal); v != "" {
		fmt.Fprintf(out, "%s%s %s\n", pad, cat.ui("label.value"), v)
	}
	if f.Detail != "" {
		fmt.Fprintf(out, "%s%s %s\n", pad, cat.ui("label.detail"), f.Detail)
	}
	fmt.Fprintf(out, "%s%s %s\n", pad, cat.ui("label.reach"), cat.ui("reach."+reachKey(f.Reach)))
	if f.Source != "" {
		fmt.Fprintf(out, "%s%s %s\n", pad, cat.ui("label.source"), f.Source)
	}
	if f.How == Inferred {
		fmt.Fprintf(out, "%s%s %s\n", pad, cat.ui("label.inferred"), f.Why)
	}

	for _, line := range wrap(text.Reveals, 66) {
		fmt.Fprintln(out, pad+line)
	}
	if text.Fix != "" {
		fmt.Fprintln(out)
		for _, line := range wrap(cat.ui("label.fix")+" "+text.Fix, 66) {
			fmt.Fprintln(out, pad+line)
		}
	}
	fmt.Fprintln(out)
}

// JSON output, for diffing a machine against itself over time. Identifiers
// obey the same masking rule as the printed report: you have to ask.
type jsonFinding struct {
	Check     string `json:"check"`
	Group     string `json:"group"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	Fix       string `json:"fixability"`
	Reach     string `json:"reach"`
	Certainty string `json:"certainty"`
	Source    string `json:"source,omitempty"`
	Value     string `json:"value,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Note      string `json:"note,omitempty"`
}

func renderJSON(out io.Writer, cat Catalog, results []Result, reveal bool) error {
	items := make([]jsonFinding, 0, len(results))
	for _, r := range results {
		items = append(items, jsonFinding{
			Check:     r.Check.ID,
			Group:     r.Check.Group,
			ID:        r.Finding.ID,
			Title:     cat.check(r.Finding.ID).Title,
			Fix:       fixKey(r.Finding.Fix),
			Reach:     reachKey(r.Finding.Reach),
			Certainty: certaintyKey(r.Finding.How),
			Source:    r.Finding.Source,
			Value:     r.Finding.Shown(reveal),
			Detail:    r.Finding.Detail,
			Note:      r.Finding.Why,
		})
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}

func groupsPresent(results []Result) []string {
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Check.Group] = true
	}
	var out []string
	for _, g := range groupOrder {
		if seen[g] {
			out = append(out, g)
			delete(seen, g)
		}
	}
	var rest []string
	for g := range seen {
		rest = append(rest, g)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func sortedForGroup(results []Result, group string) []Result {
	var out []Result
	for _, r := range results {
		if r.Check.Group == group {
			out = append(out, r)
		}
	}
	rank := map[Fixability]int{}
	for i, f := range fixOrder {
		rank[f] = i
	}
	// Unreadable sinks below everything: it is a gap, not a verdict, and
	// it should not sit above findings we actually established.
	weight := func(r Result) int {
		if r.Finding.How == Unreadable {
			return len(fixOrder) + 1
		}
		return rank[r.Finding.Fix]
	}
	sort.SliceStable(out, func(i, j int) bool { return weight(out[i]) < weight(out[j]) })
	return out
}

func fixKey(f Fixability) string {
	switch f {
	case Sealed:
		return "sealed"
	case Costly:
		return "costly"
	case Settable:
		return "settable"
	}
	return "clear"
}

func reachKey(r Reach) string {
	switch r {
	case Installed:
		return "installed"
	case Network:
		return "network"
	case Remote:
		return "remote"
	}
	return "local"
}

func certaintyKey(c Certainty) string {
	switch c {
	case Inferred:
		return "inferred"
	case Unreadable:
		return "unreadable"
	}
	return "measured"
}

// wrap breaks a paragraph at word boundaries. Explanations are the product
// here, so they run long, and long lines are the fastest way to make people
// stop reading them.
func wrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}
