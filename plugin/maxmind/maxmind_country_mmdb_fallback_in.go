package maxmind

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"go4.org/netipx"
)

const (
	TypeMaxmindMMDBFallback = "maxmindMMDBFallback"
	DescMaxmindMMDBFallback = "Use MaxMind country mmdb only for ranges missing from the primary mmdb"
)

func init() {
	lib.RegisterInputConfigCreator(TypeMaxmindMMDBFallback, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newMMDBFallbackIn(action, data)
	})
	lib.RegisterInputConverter(TypeMaxmindMMDBFallback, &MMDBFallbackIn{
		Description: DescMaxmindMMDBFallback,
	})
}

func newMMDBFallbackIn(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var tmp struct {
		PrimaryURI  string     `json:"primaryURI"`
		FallbackURI string     `json:"fallbackURI"`
		Want        []string   `json:"wantedList"`
		OnlyIPType  lib.IPType `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.PrimaryURI == "" {
		tmp.PrimaryURI = defaultIPInfoCountryMMDBFile
	}
	if tmp.FallbackURI == "" {
		tmp.FallbackURI = defaultGeoLite2MMDBFile
	}

	wantList := make(map[string]bool)
	for _, want := range tmp.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList[want] = true
		}
	}

	return &MMDBFallbackIn{
		Type:        TypeMaxmindMMDBFallback,
		Action:      action,
		Description: DescMaxmindMMDBFallback,
		PrimaryURI:  tmp.PrimaryURI,
		FallbackURI: tmp.FallbackURI,
		Want:        wantList,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type MMDBFallbackIn struct {
	Type        string
	Action      lib.Action
	Description string
	PrimaryURI  string
	FallbackURI string
	Want        map[string]bool
	OnlyIPType  lib.IPType
}

func (m *MMDBFallbackIn) GetType() string {
	return m.Type
}

func (m *MMDBFallbackIn) GetAction() lib.Action {
	return m.Action
}

func (m *MMDBFallbackIn) GetDescription() string {
	return m.Description
}

func (m *MMDBFallbackIn) Input(container lib.Container) (lib.Container, error) {
	primaryContent, err := readMMDBContent(m.PrimaryURI)
	if err != nil {
		return nil, err
	}

	primaryIPv4, primaryIPv6, err := m.primaryCoverage(primaryContent)
	if err != nil {
		return nil, err
	}

	fallbackContent, err := readMMDBContent(m.FallbackURI)
	if err != nil {
		return nil, err
	}

	entries, err := m.fallbackEntries(fallbackContent, primaryIPv4, primaryIPv6)
	if err != nil {
		return nil, err
	}

	var ignoreIPType lib.IgnoreIPOption
	switch m.OnlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	for _, entry := range entries {
		switch m.Action {
		case lib.ActionAdd:
			if err := container.Add(entry, ignoreIPType); err != nil {
				return nil, err
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemovePrefix, ignoreIPType); err != nil {
				return nil, err
			}
		default:
			return nil, lib.ErrUnknownAction
		}
	}

	return container, nil
}

func readMMDBContent(uri string) ([]byte, error) {
	switch {
	case strings.HasPrefix(strings.ToLower(uri), "http://"), strings.HasPrefix(strings.ToLower(uri), "https://"):
		return lib.GetRemoteURLContent(uri)
	default:
		return os.ReadFile(uri)
	}
}

func (m *MMDBFallbackIn) primaryCoverage(content []byte) (*netipx.IPSet, *netipx.IPSet, error) {
	db, err := maxminddb.FromBytes(content)
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()

	var ipv4Builder, ipv6Builder netipx.IPSetBuilder
	hasIPv4, hasIPv6 := false, false

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		record := ipInfoCountryRecord{}
		subnet, err := networks.Network(&record)
		if err != nil {
			return nil, nil, err
		}
		if record.countryCode() == "" || subnet == nil {
			continue
		}

		prefix, ipType, err := prefixFromStdIPNet(subnet)
		if err != nil {
			return nil, nil, err
		}
		switch ipType {
		case lib.IPv4:
			if m.OnlyIPType == lib.IPv6 {
				continue
			}
			ipv4Builder.AddPrefix(prefix)
			hasIPv4 = true
		case lib.IPv6:
			if m.OnlyIPType == lib.IPv4 {
				continue
			}
			ipv6Builder.AddPrefix(prefix)
			hasIPv6 = true
		}
	}
	if networks.Err() != nil {
		return nil, nil, networks.Err()
	}

	var ipv4Set, ipv6Set *netipx.IPSet
	if hasIPv4 {
		ipv4Set, err = ipv4Builder.IPSet()
		if err != nil {
			return nil, nil, err
		}
	}
	if hasIPv6 {
		ipv6Set, err = ipv6Builder.IPSet()
		if err != nil {
			return nil, nil, err
		}
	}

	return ipv4Set, ipv6Set, nil
}

func (m *MMDBFallbackIn) fallbackEntries(content []byte, primaryIPv4, primaryIPv6 *netipx.IPSet) (map[string]*lib.Entry, error) {
	db, err := maxminddb.FromBytes(content)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	entries := make(map[string]*lib.Entry, 300)
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record geoip2.Country
		subnet, err := networks.Network(&record)
		if err != nil {
			return nil, err
		}

		name := maxmindCountryCode(record)
		if name == "" || subnet == nil {
			continue
		}
		if len(m.Want) > 0 && !m.Want[name] {
			continue
		}

		prefix, ipType, err := prefixFromStdIPNet(subnet)
		if err != nil {
			return nil, err
		}

		var primarySet *netipx.IPSet
		switch ipType {
		case lib.IPv4:
			if m.OnlyIPType == lib.IPv6 {
				continue
			}
			primarySet = primaryIPv4
		case lib.IPv6:
			if m.OnlyIPType == lib.IPv4 {
				continue
			}
			primarySet = primaryIPv6
		}

		prefixes, err := fallbackPrefixes(prefix, primarySet)
		if err != nil {
			return nil, err
		}
		if len(prefixes) == 0 {
			continue
		}

		entry, found := entries[name]
		if !found {
			entry = lib.NewEntry(name)
		}
		for _, fallbackPrefix := range prefixes {
			if err := entry.AddPrefix(fallbackPrefix); err != nil {
				return nil, err
			}
		}
		entries[name] = entry
	}

	return entries, networks.Err()
}

func maxmindCountryCode(record geoip2.Country) string {
	switch {
	case strings.TrimSpace(record.Country.IsoCode) != "":
		return strings.ToUpper(strings.TrimSpace(record.Country.IsoCode))
	case strings.TrimSpace(record.RegisteredCountry.IsoCode) != "":
		return strings.ToUpper(strings.TrimSpace(record.RegisteredCountry.IsoCode))
	case strings.TrimSpace(record.RepresentedCountry.IsoCode) != "":
		return strings.ToUpper(strings.TrimSpace(record.RepresentedCountry.IsoCode))
	default:
		return ""
	}
}

func prefixFromStdIPNet(network *net.IPNet) (netip.Prefix, lib.IPType, error) {
	prefix, ok := netipx.FromStdIPNet(network)
	if !ok {
		return netip.Prefix{}, "", lib.ErrInvalidIPNet
	}

	addr := prefix.Addr()
	switch {
	case addr.Is4():
		return prefix, lib.IPv4, nil
	case addr.Is4In6():
		bits := prefix.Bits()
		if bits < 96 {
			return netip.Prefix{}, "", lib.ErrInvalidPrefix
		}
		normalized, err := addr.Unmap().Prefix(bits - 96)
		if err != nil {
			return netip.Prefix{}, "", err
		}
		return normalized, lib.IPv4, nil
	case addr.Is6():
		return prefix, lib.IPv6, nil
	default:
		return netip.Prefix{}, "", lib.ErrInvalidIPLength
	}
}

func fallbackPrefixes(prefix netip.Prefix, primarySet *netipx.IPSet) ([]netip.Prefix, error) {
	if primarySet == nil {
		return []netip.Prefix{prefix}, nil
	}

	var builder netipx.IPSetBuilder
	builder.AddPrefix(prefix)
	builder.RemoveSet(primarySet)

	set, err := builder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("generate fallback prefixes for %s: %w", prefix, err)
	}

	return set.Prefixes(), nil
}
