package maxmind

import (
	"net/netip"
	"testing"

	"github.com/Loyalsoldier/geoip/lib"
)

func TestNormalizeIPInfoPrefixCapsIPv6At64(t *testing.T) {
	tests := []struct {
		name string
		in   string
		typ  lib.IPType
		want string
	}{
		{
			name: "ipv6 host",
			in:   "2001:db8:1:2:3:4:5:6/128",
			typ:  lib.IPv6,
			want: "2001:db8:1:2::/64",
		},
		{
			name: "ipv6 already 64",
			in:   "2001:db8:1:2::/64",
			typ:  lib.IPv6,
			want: "2001:db8:1:2::/64",
		},
		{
			name: "ipv6 broader than 64",
			in:   "2001:db8::/32",
			typ:  lib.IPv6,
			want: "2001:db8::/32",
		},
		{
			name: "ipv4 unchanged",
			in:   "192.0.2.1/32",
			typ:  lib.IPv4,
			want: "192.0.2.1/32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tt.in)
			got, err := normalizeIPInfoPrefix(prefix, tt.typ)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}
