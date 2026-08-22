//go:build windows

package main

// Reading the SMBIOS tables the firmware leaves for the operating system.
//
// This is where the hardware identifiers actually live: the system UUID and
// the board serial, both burned in at the factory, both readable by any
// program without asking anyone for permission, and neither of them
// changeable. The registry copies of this data are partial, so we go to the
// source.
//
// GetSystemFirmwareTable needs no privileges, which is worth knowing: so
// does every other program on the machine that wants to fingerprint it.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemFirmwareTable = kernel32.NewProc("GetSystemFirmwareTable")
)

// 'RSMB', the raw SMBIOS provider, as the DWORD Windows expects.
const providerRSMB = 0x52534D42

type smbiosEntry struct {
	Kind    byte
	Fields  []byte   // the formatted area, header included
	Strings []string // the string table that follows it, indexed from 1
}

// text pulls a string out of the table by the one-based index stored in the
// formatted area. Index 0 means the field was left empty.
func (e smbiosEntry) text(offset int) string {
	if offset >= len(e.Fields) {
		return ""
	}
	i := int(e.Fields[offset])
	if i == 0 || i > len(e.Strings) {
		return ""
	}
	return strings.TrimSpace(e.Strings[i-1])
}

func rawSMBIOS() ([]byte, error) {
	size, _, err := procGetSystemFirmwareTable.Call(providerRSMB, 0, 0, 0)
	if size == 0 {
		return nil, fmt.Errorf("GetSystemFirmwareTable gave no size: %v", err)
	}
	buf := make([]byte, size)
	n, _, err := procGetSystemFirmwareTable.Call(providerRSMB, 0,
		uintptr(unsafe.Pointer(&buf[0])), size)
	if n == 0 || n > size {
		return nil, fmt.Errorf("GetSystemFirmwareTable read nothing: %v", err)
	}
	// RawSMBIOSData puts four bytes of version info and a length in front
	// of the tables themselves.
	const header = 8
	if int(n) <= header {
		return nil, errors.New("SMBIOS data too short to hold any table")
	}
	return buf[header:n], nil
}

func parseSMBIOS(data []byte) []smbiosEntry {
	var entries []smbiosEntry
	for i := 0; i+4 <= len(data); {
		kind, length := data[i], int(data[i+1])
		if length < 4 || i+length > len(data) {
			break
		}
		e := smbiosEntry{Kind: kind, Fields: data[i : i+length]}

		// The string table runs to a double null. A structure with no
		// strings at all is still terminated by two null bytes.
		j := i + length
		for j < len(data) {
			if data[j] == 0 {
				if j+1 < len(data) && data[j+1] == 0 {
					j += 2
					break
				}
				j++
				continue
			}
			start := j
			for j < len(data) && data[j] != 0 {
				j++
			}
			e.Strings = append(e.Strings, string(data[start:j]))
		}
		entries = append(entries, e)
		i = j
		if kind == 127 { // end-of-table marker
			break
		}
	}
	return entries
}

func smbiosOfKind(entries []smbiosEntry, kind byte) (smbiosEntry, bool) {
	for _, e := range entries {
		if e.Kind == kind {
			return e, true
		}
	}
	return smbiosEntry{}, false
}

// formatUUID renders the system UUID. SMBIOS stores the first three groups
// little-endian, which is why a raw hex dump of these bytes never matches
// what other tools report.
func formatUUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	empty, unset := true, true
	for _, x := range b[:16] {
		if x != 0x00 {
			empty = false
		}
		if x != 0xFF {
			unset = false
		}
	}
	if empty || unset {
		return "" // the board never had one written
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

func smbiosTables() ([]smbiosEntry, error) {
	raw, err := rawSMBIOS()
	if err != nil {
		return nil, err
	}
	return parseSMBIOS(raw), nil
}

// The checks

func checkSystemUUID() []Finding {
	const where = "SMBIOS type 1 (System Information)"
	tables, err := smbiosTables()
	if err != nil {
		return []Finding{unreadable("system-uuid.present", where, err.Error())}
	}
	e, ok := smbiosOfKind(tables, 1)
	if !ok {
		return []Finding{unreadable("system-uuid.present", where, "no type 1 structure")}
	}
	const uuidAt = 8
	if len(e.Fields) < uuidAt+16 {
		return []Finding{unreadable("system-uuid.present", where, "type 1 structure too short")}
	}
	uuid := formatUUID(e.Fields[uuidAt : uuidAt+16])
	if uuid == "" {
		return []Finding{{ID: "system-uuid.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "system-uuid.present", Fix: Sealed, Reach: Installed,
		How: Measured, Source: where, Value: uuid, Sensitive: true}}
}

func checkBoardSerial() []Finding {
	const where = "SMBIOS types 1 and 2 (System and Baseboard)"
	tables, err := smbiosTables()
	if err != nil {
		return []Finding{unreadable("board-serial.present", where, err.Error())}
	}
	const serialAt = 7
	var serials []string
	for _, kind := range []byte{1, 2} {
		e, ok := smbiosOfKind(tables, kind)
		if !ok {
			continue
		}
		s := e.text(serialAt)
		if placeholderSerial(s) {
			continue
		}
		serials = append(serials, s)
	}
	if len(serials) == 0 {
		return []Finding{{ID: "board-serial.absent", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	return []Finding{{ID: "board-serial.present", Fix: Sealed, Reach: Installed,
		How: Measured, Source: where,
		Value: strings.Join(serials, " / "), Sensitive: true}}
}
