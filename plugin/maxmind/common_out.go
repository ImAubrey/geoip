package maxmind

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

var (
	defaultOutputName       = "Country.mmdb"
	defaultMaxmindOutputDir = filepath.Join("./", "output", "maxmind")
	defaultDBIPOutputDir    = filepath.Join("./", "output", "db-ip")
	defaultIPInfoOutputDir  = filepath.Join("./", "output", "ipinfo")
)

type ipInfoCountryRecord struct {
	Continent     string `maxminddb:"continent"`
	ContinentCode string `maxminddb:"continent_code"`
	ContinentName string `maxminddb:"continent_name"`
	Country       string `maxminddb:"country"`
	CountryCode   string `maxminddb:"country_code"`
	CountryName   string `maxminddb:"country_name"`
}

func (i ipInfoCountryRecord) countryCode() string {
	switch {
	case strings.TrimSpace(i.CountryCode) != "":
		return strings.ToUpper(strings.TrimSpace(i.CountryCode))
	default:
		return strings.ToUpper(strings.TrimSpace(i.Country))
	}
}

func (i ipInfoCountryRecord) countryName() string {
	switch {
	case strings.TrimSpace(i.CountryName) != "":
		return strings.TrimSpace(i.CountryName)
	case strings.TrimSpace(i.CountryCode) != "":
		return strings.TrimSpace(i.Country)
	default:
		return ""
	}
}

func (i ipInfoCountryRecord) continentCode() string {
	switch {
	case strings.TrimSpace(i.ContinentCode) != "":
		return strings.TrimSpace(i.ContinentCode)
	default:
		return strings.TrimSpace(i.Continent)
	}
}

func (i ipInfoCountryRecord) continentName() string {
	switch {
	case strings.TrimSpace(i.ContinentName) != "":
		return strings.TrimSpace(i.ContinentName)
	case strings.TrimSpace(i.ContinentCode) != "":
		return strings.TrimSpace(i.Continent)
	default:
		return ""
	}
}

func newMMDBOut(iType string, iDesc string, action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
	var tmp struct {
		OutputName string     `json:"outputName"`
		OutputDir  string     `json:"outputDir"`
		Want       []string   `json:"wantedList"`
		Overwrite  []string   `json:"overwriteList"`
		Exclude    []string   `json:"excludedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`

		SourceMMDBURI string `json:"sourceMMDBURI"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.OutputName == "" {
		tmp.OutputName = defaultOutputName
	}

	if tmp.OutputDir == "" {
		switch iType {
		case TypeMaxmindMMDBOut:
			tmp.OutputDir = defaultMaxmindOutputDir

		case TypeDBIPCountryMMDBOut:
			tmp.OutputDir = defaultDBIPOutputDir

		case TypeIPInfoCountryMMDBOut:
			tmp.OutputDir = defaultIPInfoOutputDir
		}
	}

	return &MMDBOut{
		Type:        iType,
		Action:      action,
		Description: iDesc,
		OutputName:  tmp.OutputName,
		OutputDir:   tmp.OutputDir,
		Want:        tmp.Want,
		Overwrite:   tmp.Overwrite,
		Exclude:     tmp.Exclude,
		OnlyIPType:  tmp.OnlyIPType,

		SourceMMDBURI: tmp.SourceMMDBURI,
	}, nil
}

func (m *MMDBOut) GetExtraInfo() (map[string]interface{}, error) {
	if strings.TrimSpace(m.SourceMMDBURI) == "" {
		return nil, nil
	}

	var content []byte
	var err error
	switch {
	case strings.HasPrefix(strings.ToLower(m.SourceMMDBURI), "http://"), strings.HasPrefix(strings.ToLower(m.SourceMMDBURI), "https://"):
		content, err = lib.GetRemoteURLContent(m.SourceMMDBURI)
	default:
		content, err = os.ReadFile(m.SourceMMDBURI)
	}
	if err != nil {
		return nil, err
	}

	db, err := maxminddb.FromBytes(content)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	infoList := make(map[string]interface{})
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		switch m.Type {
		case TypeMaxmindMMDBOut, TypeDBIPCountryMMDBOut:
			var record geoip2.Country
			_, err := networks.Network(&record)
			if err != nil {
				return nil, err
			}

			switch {
			case strings.TrimSpace(record.Country.IsoCode) != "":
				countryCode := strings.ToUpper(strings.TrimSpace(record.Country.IsoCode))
				if _, found := infoList[countryCode]; !found {
					infoList[countryCode] = geoip2.Country{
						Continent: record.Continent,
						Country:   record.Country,
					}
				}

			case strings.TrimSpace(record.RegisteredCountry.IsoCode) != "":
				countryCode := strings.ToUpper(strings.TrimSpace(record.RegisteredCountry.IsoCode))
				if _, found := infoList[countryCode]; !found {
					infoList[countryCode] = geoip2.Country{
						Continent: record.Continent,
						Country:   record.RegisteredCountry,
					}
				}

			case strings.TrimSpace(record.RepresentedCountry.IsoCode) != "":
				countryCode := strings.ToUpper(strings.TrimSpace(record.RepresentedCountry.IsoCode))
				if _, found := infoList[countryCode]; !found {
					infoList[countryCode] = geoip2.Country{
						Continent: record.Continent,
						Country: struct {
							Names             map[string]string `maxminddb:"names"`
							IsoCode           string            `maxminddb:"iso_code"`
							GeoNameID         uint              `maxminddb:"geoname_id"`
							IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
						}{
							Names:             record.RepresentedCountry.Names,
							IsoCode:           record.RepresentedCountry.IsoCode,
							GeoNameID:         record.RepresentedCountry.GeoNameID,
							IsInEuropeanUnion: record.RepresentedCountry.IsInEuropeanUnion,
						},
					}
				}
			}

		case TypeIPInfoCountryMMDBOut:
			record := ipInfoCountryRecord{}

			_, err := networks.Network(&record)
			if err != nil {
				return nil, err
			}
			countryCode := record.countryCode()
			if countryCode == "" {
				continue
			}
			if _, found := infoList[countryCode]; !found {
				infoList[countryCode] = record
			}

		default:
			return nil, lib.ErrNotSupportedFormat
		}

	}

	if networks.Err() != nil {
		return nil, networks.Err()
	}

	if len(infoList) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] no extra info found in the source MMDB file: %s", m.Type, m.Action, m.SourceMMDBURI)
	}

	return infoList, nil
}
