package special

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
)

const (
	TypeCountryCodeSubtract = "countryCodeSubtract"
	DescCountryCodeSubtract = "Subtract selected lists from two-letter country-code entries"
)

var countryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)

func init() {
	lib.RegisterInputConfigCreator(TypeCountryCodeSubtract, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newCountryCodeSubtract(action, data)
	})
	lib.RegisterInputConverter(TypeCountryCodeSubtract, &CountryCodeSubtract{
		Description: DescCountryCodeSubtract,
	})
}

func newCountryCodeSubtract(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var args struct {
		SourceList []string `json:"sourceList"`
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &args); err != nil {
			return nil, err
		}
	}
	if action != lib.ActionRemove {
		return nil, fmt.Errorf("❌ [type %s] only supports `remove` action", TypeCountryCodeSubtract)
	}

	sourceList := make(map[string]bool)
	for _, name := range args.SourceList {
		if name = strings.ToUpper(strings.TrimSpace(name)); name != "" {
			sourceList[name] = true
		}
	}
	if len(sourceList) == 0 {
		return nil, fmt.Errorf("❌ [type %s] sourceList must be specified", TypeCountryCodeSubtract)
	}

	return &CountryCodeSubtract{
		Type:        TypeCountryCodeSubtract,
		Action:      action,
		Description: DescCountryCodeSubtract,
		SourceList:  sourceList,
	}, nil
}

type CountryCodeSubtract struct {
	Type        string
	Action      lib.Action
	Description string
	SourceList  map[string]bool
}

func (c *CountryCodeSubtract) GetType() string {
	return c.Type
}

func (c *CountryCodeSubtract) GetAction() lib.Action {
	return c.Action
}

func (c *CountryCodeSubtract) GetDescription() string {
	return c.Description
}

func (c *CountryCodeSubtract) Input(container lib.Container) (lib.Container, error) {
	excluded := lib.NewEntry("COUNTRY-CODE-EXCLUDED")
	for name := range c.SourceList {
		entry, found := container.GetEntry(name)
		if !found {
			return nil, fmt.Errorf("❌ [type %s] source entry %s not found", TypeCountryCodeSubtract, name)
		}
		prefixes, err := entry.MarshalPrefix()
		if err != nil {
			return nil, err
		}
		for _, prefix := range prefixes {
			if err := excluded.AddPrefix(prefix); err != nil {
				return nil, err
			}
		}
	}

	for entry := range container.Loop() {
		if !countryCodePattern.MatchString(entry.GetName()) {
			continue
		}
		if err := entry.RemovePrefixSet(excluded); err != nil {
			return nil, err
		}
	}

	return container, nil
}
