package maxmind

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
)

const (
	TypeASNCSV = "maxmindGeoLite2ASNCSV"
	DescASNCSV = "Convert MaxMind GeoLite2 ASN CSV data to other formats"
)

var (
	defaultASNIPv4File = filepath.Join("./", "geolite2", "GeoLite2-ASN-Blocks-IPv4.csv")
	defaultASNIPv6File = filepath.Join("./", "geolite2", "GeoLite2-ASN-Blocks-IPv6.csv")
)

func init() {
	lib.RegisterInputConfigCreator(TypeASNCSV, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newGeoLite2ASNCSV(action, data)
	})
	lib.RegisterInputConverter(TypeASNCSV, &GeoLite2ASNCSV{
		Description: DescASNCSV,
	})
}

func mapRIRToURL(rir string) string {
	switch strings.ToLower(rir) {
	case "apnic":
		return "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	case "ripe":
		return "http://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
	case "arin":
		return "http://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
	case "lacnic":
		return "http://ftp.lacnic.net/lacnic/stats/lacnic/delegated-lacnic-latest"
	case "afrinic":
		return "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest"
	default:
		return ""
	}
}
func fetchASNFromRIR(rir, country string) ([]string, error) {
	url := mapRIRToURL(rir)
	if url == "" {
		return nil, fmt.Errorf("unsupported RIR: %s", rir)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	asnList := []string{}
	scanner := bufio.NewScanner(resp.Body)
	// RIR: 小写，country: 大写
	rirLower := strings.ToLower(rir)
	countryUpper := strings.ToUpper(country)

	for scanner.Scan() {
		line := scanner.Text()
		// 格式: rir|CC|type|start|count|...
		// 例如: apnic|JP|asn|1234|10|...
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		if strings.ToLower(parts[0]) != rirLower {
			continue
		}
		if strings.ToUpper(parts[1]) != countryUpper || parts[2] != "asn" {
			continue
		}
		startNum, err1 := strconv.Atoi(parts[3])
		count, err2 := strconv.Atoi(parts[4])
		if err1 != nil || err2 != nil {
			continue
		}
		for i := 0; i < count; i++ {
			asnList = append(asnList, fmt.Sprintf("AS%d", startNum+i))
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("scanner error: %v", err)
	}
	return asnList, nil
}
func isRIRCountryPattern(raw string) bool {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return false
	}
	// parts[0] 是否在支持的 RIR 列表里
	switch strings.ToLower(parts[0]) {
	case "apnic", "ripe", "arin", "lacnic", "afrinic":
		return true
	default:
		return false
	}
}
func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// fetchASNs grabs the body at url, then tries JSON unmarshal; if that fails, falls back to splitting lines.
func fetchASNs(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// trim BOM/spaces to peek
	data := strings.TrimSpace(string(body))
	var asnList []string
	if strings.HasPrefix(data, "[") {
		// try JSON array of strings
		if err := json.Unmarshal([]byte(data), &asnList); err == nil {
			return asnList, nil
		}
		// if JSON fails, fallback to lines
	}
	// plain-text: split by newlines, ignore empty
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			asnList = append(asnList, line)
		}
	}
	return asnList, nil
}
func newGeoLite2ASNCSV(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var tmp struct {
		IPv4File   string              `json:"ipv4"`
		IPv6File   string              `json:"ipv6"`
		Want       map[string][]string `json:"wantedList"`
		OnlyIPType lib.IPType          `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	// When both of IP files are not specified,
	// it means user wants to use the default ones
	if tmp.IPv4File == "" && tmp.IPv6File == "" {
		tmp.IPv4File = defaultASNIPv4File
		tmp.IPv6File = defaultASNIPv6File
	}

	// Filter want list
	wantList := make(map[string][]string) // map[asn][]listname
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
			if isURL(raw) {
				// fetch remote content
				fetched, err := fetchASNs(raw)
				if err != nil {
					// if fetch fails, skip or log; here we skip silently
					continue
				}
				sources = fetched
			} else if isRIRCountryPattern(raw) {
				parts := strings.SplitN(raw, ":", 2)
				rir := parts[0]
				country := parts[1]
				fetched, err := fetchASNFromRIR(rir, country)
				if err != nil {
					// 拉不到就跳过
					continue
				}
				sources = fetched

				// 3. 其余当单个 ASN 处理
			} else {
				sources = []string{raw}
			}

			for _, asnEntry := range sources {
				// normalize "AS123" → "123"
				entry := strings.ToLower(strings.TrimSpace(asnEntry))
				entry = strings.TrimPrefix(entry, "as")
				if entry == "" {
					continue
				}
				// stash into wantList map
				if arr, ok := wantList[entry]; ok {
					wantList[entry] = append(arr, list)
				} else {
					wantList[entry] = []string{list}
				}
			}
		}
	}

	if len(wantList) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] wantedList must be specified in config", TypeASNCSV, action)
	}

	return &GeoLite2ASNCSV{
		Type:        TypeASNCSV,
		Action:      action,
		Description: DescASNCSV,
		IPv4File:    tmp.IPv4File,
		IPv6File:    tmp.IPv6File,
		Want:        wantList,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type GeoLite2ASNCSV struct {
	Type        string
	Action      lib.Action
	Description string
	IPv4File    string
	IPv6File    string
	Want        map[string][]string
	OnlyIPType  lib.IPType
}

func (g *GeoLite2ASNCSV) GetType() string {
	return g.Type
}

func (g *GeoLite2ASNCSV) GetAction() lib.Action {
	return g.Action
}

func (g *GeoLite2ASNCSV) GetDescription() string {
	return g.Description
}

func (g *GeoLite2ASNCSV) Input(container lib.Container) (lib.Container, error) {
	entries := make(map[string]*lib.Entry)

	if g.IPv4File != "" {
		if err := g.process(g.IPv4File, entries); err != nil {
			return nil, err
		}
	}

	if g.IPv6File != "" {
		if err := g.process(g.IPv6File, entries); err != nil {
			return nil, err
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] no entry is generated", g.Type, g.Action)
	}

	var ignoreIPType lib.IgnoreIPOption
	switch g.OnlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	for _, entry := range entries {
		switch g.Action {
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

func (g *GeoLite2ASNCSV) process(file string, entries map[string]*lib.Entry) error {
	if entries == nil {
		entries = make(map[string]*lib.Entry)
	}

	var f io.ReadCloser
	var err error
	switch {
	case strings.HasPrefix(strings.ToLower(file), "http://"), strings.HasPrefix(strings.ToLower(file), "https://"):
		f, err = lib.GetRemoteURLReader(file)
	default:
		f, err = os.Open(file)
	}

	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.Read() // skip header

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) < 2 {
			return fmt.Errorf("❌ [type %s | action %s] invalid record: %v", g.Type, g.Action, record)
		}

		if listArr, found := g.Want[strings.TrimSpace(record[1])]; found {
			for _, listName := range listArr {
				entry, got := entries[listName]
				if !got {
					entry = lib.NewEntry(listName)
				}
				if err := entry.AddPrefix(strings.TrimSpace(record[0])); err != nil {
					return err
				}
				entries[listName] = entry
			}
		}
	}

	return nil
}
