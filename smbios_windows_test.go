//go:build windows

package main

import "testing"

// buildTable assembles one SMBIOS structure the way firmware lays it out:
// the formatted area, then null-terminated strings, then a double null.
func buildTable(kind byte, fields []byte, strs ...string) []byte {
	out := append([]byte{kind, byte(4 + len(fields)), 0x10, 0x00}, fields...)
	for _, s := range strs {
		out = append(out, []byte(s)...)
		out = append(out, 0)
	}
	out = append(out, 0)
	return out
}

func TestParseSMBIOS(t *testing.T) {
	// Type 1: manufacturer, product, version and serial are string indexes
	// at offsets 4 to 7, then sixteen bytes of UUID.
	uuid := []byte{
		0x78, 0x56, 0x34, 0x12, // little endian, reads back as 12345678
		0x34, 0x12, // 1234
		0x78, 0x56, // 5678
		0x9a, 0xbc, // big endian from here
		0xde, 0xf0, 0x11, 0x22, 0x33, 0x44,
	}
	fields := append([]byte{1, 2, 3, 4}, uuid...)
	data := buildTable(1, fields, "ACME", "Board", "1.0", "SERIAL123")
	data = append(data, buildTable(127, nil)...)

	entries := parseSMBIOS(data)
	if len(entries) != 2 {
		t.Fatalf("expected 2 structures, parsed %d", len(entries))
	}

	e, ok := smbiosOfKind(entries, 1)
	if !ok {
		t.Fatal("no type 1 structure found")
	}
	if got := e.text(7); got != "SERIAL123" {
		t.Errorf("serial came back as %q", got)
	}
	if got := e.text(4); got != "ACME" {
		t.Errorf("manufacturer came back as %q", got)
	}
	// Index 0 means the field was left empty, not "the first string".
	if got := (smbiosEntry{Fields: []byte{1, 4, 0, 0, 0}, Strings: []string{"x"}}).text(4); got != "" {
		t.Errorf("string index 0 should be empty, got %q", got)
	}

	if got := formatUUID(uuid); got != "12345678-1234-5678-9abc-def011223344" {
		t.Errorf("UUID came back as %q, the endianness is wrong", got)
	}
}

// A board with no UUID writes all zeroes or all ones. Reporting either as
// an identifier would invent a fingerprint that does not exist.
func TestEmptyUUIDIsNotAnIdentifier(t *testing.T) {
	zeroes := make([]byte, 16)
	ones := make([]byte, 16)
	for i := range ones {
		ones[i] = 0xFF
	}
	if got := formatUUID(zeroes); got != "" {
		t.Errorf("an all-zero UUID came back as %q", got)
	}
	if got := formatUUID(ones); got != "" {
		t.Errorf("an all-ones UUID came back as %q", got)
	}
	if got := formatUUID([]byte{1, 2, 3}); got != "" {
		t.Errorf("a short buffer came back as %q instead of nothing", got)
	}
}

// Firmware tables come from outside the program and are not always sane.
// The parser has to stop rather than read past the end of the buffer.
func TestParserSurvivesRubbish(t *testing.T) {
	for _, junk := range [][]byte{
		nil,
		{1},
		{1, 200, 0, 0},              // length runs past the end
		{1, 2, 0, 0},                // length below the four byte header
		{1, 4, 0, 0},                // no string terminator at all
		{1, 4, 0, 0, 'a', 'b', 'c'}, // string runs off the end
	} {
		parseSMBIOS(junk) // must simply return, not panic
	}
}
