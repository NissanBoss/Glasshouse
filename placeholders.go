package main

import "strings"

// placeholderSerial recognises the strings manufacturers leave in the
// firmware tables when they never bothered writing a real serial.
//
// Reporting one of these as an identifier would be worse than saying
// nothing: it invents a fingerprint that does not exist, and it is shared
// with every other machine off the same line.
func placeholderSerial(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "to be filled by o.e.m.", "to be filled by oem", "default string",
		"none", "not specified", "not applicable", "system serial number",
		"chassis serial number", "0123456789", "unknown", "n/a",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff":
		return true
	}
	return false
}
