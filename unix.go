//go:build linux || darwin

package main

// Bits that Linux and macOS do the same way: both keep the interesting
// things in plain files, and both name their resolvers in /etc/resolv.conf.

import (
	"os"
	"path/filepath"
	"strings"
)

// root is where the system files live. Tests move it so the checks can run
// against a fixture directory instead of the machine they run on, which is
// the only way to test a reader for hardware you do not have.
var root = "/"

func at(parts ...string) string {
	return filepath.Join(append([]string{root}, parts...)...)
}

// readTrimmed returns the contents of a one-line file. Most of /sys is
// these, and they always come back with a trailing newline.
func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// deniedErr separates "you are not root" from "this machine has none".
// Under /sys the first is common on purpose: the hardware identifiers are
// root-only precisely because they are identifiers.
func deniedErr(err error) bool {
	return err != nil && os.IsPermission(err)
}

func checkResolvConf() []Finding {
	where := at("etc/resolv.conf")
	b, err := os.ReadFile(where)
	if err != nil {
		return []Finding{unreadable("dns-servers.plain", where, err.Error())}
	}
	var servers []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "nameserver"); ok {
			if s := strings.TrimSpace(rest); s != "" {
				servers = append(servers, s)
			}
		}
	}
	if len(servers) == 0 {
		return []Finding{{ID: "dns-servers.none", Fix: Clear, Reach: Local,
			How: Measured, Source: where}}
	}
	// A resolver on loopback means something local does the real lookups,
	// and this file has stopped saying who actually sees them.
	id := "dns-servers.plain"
	if allLoopback(servers) {
		id = "dns-servers.stub"
	}
	return []Finding{{ID: id, Fix: Settable, Reach: Network,
		How: Measured, Source: where, Detail: strings.Join(servers, ", ")}}
}

func allLoopback(servers []string) bool {
	for _, s := range servers {
		if !strings.HasPrefix(s, "127.") && s != "::1" {
			return false
		}
	}
	return len(servers) > 0
}
