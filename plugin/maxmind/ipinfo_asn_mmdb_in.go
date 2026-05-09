package maxmind

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/oschwald/maxminddb-golang"
)

const (
	TypeIPInfoASNMMDB = "ipinfoASNMMDB"
	DescIPInfoASNMMDB = "Convert IPInfo ASN mmdb database to other formats"
)

var defaultIPInfoASNMMDBFile = filepath.Join("./", "ipinfo", "ipinfo_lite.mmdb")

func init() {
	lib.RegisterInputConfigCreator(TypeIPInfoASNMMDB, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newIPInfoASNMMDB(action, data)
	})
	lib.RegisterInputConverter(TypeIPInfoASNMMDB, &IPInfoASNMMDB{
		Description: DescIPInfoASNMMDB,
	})
}

func newIPInfoASNMMDB(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var tmp struct {
		URI        string              `json:"uri"`
		Want       map[string][]string `json:"wantedList"`
		OnlyIPType lib.IPType          `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.URI == "" {
		tmp.URI = defaultIPInfoASNMMDBFile
	}

	wantList := make(map[string][]string)
	for list, asnList := range tmp.Want {
		list = strings.ToUpper(strings.TrimSpace(list))
		if list == "" {
			continue
		}

		for _, raw := range asnList {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}

			var sources []string
			switch {
			case isURL(raw):
				fetched, err := fetchASNs(raw)
				if err != nil {
					continue
				}
				sources = fetched

			case isRIRCountryPattern(raw):
				parts := strings.SplitN(raw, ":", 2)
				fetched, err := fetchASNFromRIR(parts[0], parts[1])
				if err != nil {
					continue
				}
				sources = fetched

			default:
				sources = []string{raw}
			}

			for _, asnEntry := range sources {
				entry := normalizeIPInfoASN(asnEntry)
				if entry == "" {
					continue
				}
				wantList[entry] = append(wantList[entry], list)
			}
		}
	}

	if len(wantList) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] wantedList must be specified in config", TypeIPInfoASNMMDB, action)
	}

	return &IPInfoASNMMDB{
		Type:        TypeIPInfoASNMMDB,
		Action:      action,
		Description: DescIPInfoASNMMDB,
		URI:         tmp.URI,
		Want:        wantList,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type IPInfoASNMMDB struct {
	Type        string
	Action      lib.Action
	Description string
	URI         string
	Want        map[string][]string
	OnlyIPType  lib.IPType
}

func (i *IPInfoASNMMDB) GetType() string {
	return i.Type
}

func (i *IPInfoASNMMDB) GetAction() lib.Action {
	return i.Action
}

func (i *IPInfoASNMMDB) GetDescription() string {
	return i.Description
}

func (i *IPInfoASNMMDB) Input(container lib.Container) (lib.Container, error) {
	var content []byte
	var err error
	switch {
	case strings.HasPrefix(strings.ToLower(i.URI), "http://"), strings.HasPrefix(strings.ToLower(i.URI), "https://"):
		content, err = lib.GetRemoteURLContent(i.URI)
	default:
		content, err = os.ReadFile(i.URI)
	}
	if err != nil {
		return nil, err
	}

	entries := make(map[string]*lib.Entry)
	if err := i.generateEntries(content, entries); err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] no entry is generated", i.Type, i.Action)
	}

	var ignoreIPType lib.IgnoreIPOption
	switch i.OnlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	for _, entry := range entries {
		switch i.Action {
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

func (i *IPInfoASNMMDB) generateEntries(content []byte, entries map[string]*lib.Entry) error {
	db, err := maxminddb.FromBytes(content)
	if err != nil {
		return err
	}
	defer db.Close()

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		record := struct {
			ASN string `maxminddb:"asn"`
		}{}

		subnet, err := networks.Network(&record)
		if err != nil {
			return err
		}

		asn := normalizeIPInfoASN(record.ASN)
		if asn == "" || subnet == nil {
			continue
		}

		listArr, found := i.Want[asn]
		if !found {
			continue
		}

		for _, listName := range listArr {
			entry, got := entries[listName]
			if !got {
				entry = lib.NewEntry(listName)
			}
			if err := entry.AddPrefix(subnet); err != nil {
				return err
			}
			entries[listName] = entry
		}
	}

	return networks.Err()
}

func normalizeIPInfoASN(raw string) string {
	entry := strings.ToLower(strings.TrimSpace(raw))
	entry = strings.TrimPrefix(entry, "as")
	return strings.TrimSpace(entry)
}
