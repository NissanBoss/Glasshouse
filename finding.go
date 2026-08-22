package main

// What a check reports, and the three axes we sort and qualify it by.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Fixability is the axis nobody else reports, and the reason this tool
// exists. Telling someone their firmware is closed is useless on its own.
// Telling them it is closed AND that no amount of effort will change it,
// because the fuses are already burned, saves them a weekend.
type Fixability int

const (
	// Burned into silicon or signed by a vendor key you do not hold.
	// Nothing you do will change it. Buying different hardware is the
	// only lever.
	Sealed Fixability = iota

	// Changeable, but the cost is real: an external SPI programmer, a
	// possible brick, a warranty, or losing a security feature you
	// probably want to keep.
	Costly

	// A setting. Reversible, no hardware, no risk beyond the obvious.
	Settable

	// Already private, or the hardware simply is not there.
	Clear
)

// Reach is how far the thing travels: who ends up able to see it.
type Reach int

const (
	Local     Reach = iota // stays on the machine unless something sends it
	Installed              // any program you run can read it
	Network                // leaves the machine on its own
	Remote                 // reachable from outside, even when powered down
)

// Certainty separates the three things a check can honestly say, and
// exists because the first version of this tool could not tell them apart.
//
// A check that failed to read a key returned nothing, which came out on
// screen looking exactly like a machine with nothing to report. In a tool
// whose entire argument is honesty, "I could not look" reading as "you are
// fine" is the worst bug available.
type Certainty int

const (
	Measured   Certainty = iota // we read the actual value
	Inferred                    // deduced from something else, and we say so
	Unreadable                  // we could not look, which is not the same as fine
)

type Finding struct {
	// ID keys into the message catalogue. Every word a human reads lives
	// there and not here, so translating never means touching Go.
	ID string

	Fix   Fixability
	Reach Reach
	How   Certainty

	// Source is where we looked: a registry path, an SMBIOS table. Printed
	// so that anyone can go and check the claim themselves rather than
	// taking this program's word for it.
	Source string

	// Value is what we actually found. It is often an identifier, which
	// makes it exactly the kind of string that should not end up pasted
	// into a bug report, so it is masked unless asked for.
	Value     string
	Sensitive bool

	// Detail carries runtime specifics that no catalogue can hold: a
	// version number, a device name, a count. Kept short.
	Detail string

	// Why explains an Inferred or Unreadable result. Free text, not
	// translated, because it names things like access denied.
	Why string
}

// Shown gives the value as it should appear on screen. A sensitive value
// collapses to a short digest: enough to tell two machines apart or to
// confirm a change took effect, useless to anyone tracking you.
func (f Finding) Shown(reveal bool) string {
	if f.Value == "" || reveal || !f.Sensitive {
		return f.Value
	}
	if strings.TrimSpace(f.Value) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(f.Value))
	return "hidden:" + hex.EncodeToString(sum[:])[:8]
}

// unreadable builds the finding a check should return when it could not
// look. Kept as a constructor so no check invents its own way of saying it
// and so none of them can go back to returning nothing.
func unreadable(id, source, why string) Finding {
	return Finding{ID: id, Fix: Settable, Reach: Local,
		How: Unreadable, Source: source, Why: why}
}

// Check is one thing we look at. A check must always return at least one
// finding: silence is not a result.
type Check struct {
	ID    string
	Run   func() []Finding
	Group string
}
