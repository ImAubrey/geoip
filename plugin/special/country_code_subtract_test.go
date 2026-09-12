package special

import (
	"encoding/json"
	"testing"

	"github.com/Loyalsoldier/geoip/lib"
)

func TestCountryCodeSubtract(t *testing.T) {
	container := lib.NewContainer()
	addEntry(t, container, "US", "1.1.1.0/24", "2001:db8::/32")
	addEntry(t, container, "CN", "2.0.0.0/24")
	addEntry(t, container, "CLOUDFLARE", "1.1.1.0/24")
	addEntry(t, container, "ANYCAST", "1.1.1.1/32", "2.0.0.0/25", "2001:db8::/48")

	converter, err := newCountryCodeSubtract(
		lib.ActionRemove,
		json.RawMessage(`{"sourceList":["anycast"]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := converter.Input(container); err != nil {
		t.Fatal(err)
	}

	assertLookup(t, container, "1.1.1.1", "US", false)
	assertLookup(t, container, "1.1.1.2", "US", true)
	assertLookup(t, container, "2.0.0.1", "CN", false)
	assertLookup(t, container, "2.0.0.129", "CN", true)
	assertLookup(t, container, "2001:db8::1", "US", false)
	assertLookup(t, container, "2001:db8:1::1", "US", true)
	assertLookup(t, container, "1.1.1.1", "ANYCAST", true)
	assertLookup(t, container, "1.1.1.1", "CLOUDFLARE", true)
}

func addEntry(t *testing.T, container lib.Container, name string, prefixes ...string) {
	t.Helper()
	entry := lib.NewEntry(name)
	for _, prefix := range prefixes {
		if err := entry.AddPrefix(prefix); err != nil {
			t.Fatal(err)
		}
	}
	if err := container.Add(entry); err != nil {
		t.Fatal(err)
	}
}

func assertLookup(t *testing.T, container lib.Container, ip, list string, want bool) {
	t.Helper()
	_, found, err := container.Lookup(ip, list)
	if err != nil {
		t.Fatal(err)
	}
	if found != want {
		t.Fatalf("lookup %s in %s: got %t, want %t", ip, list, found, want)
	}
}
