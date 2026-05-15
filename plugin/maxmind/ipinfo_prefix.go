package maxmind

import (
	"net"
	"net/netip"

	"github.com/Loyalsoldier/geoip/lib"
)

const maxIPInfoIPv6PrefixBits = 64

func normalizeIPInfoNetwork(network *net.IPNet) (netip.Prefix, error) {
	prefix, ipType, err := prefixFromStdIPNet(network)
	if err != nil {
		return netip.Prefix{}, err
	}

	return normalizeIPInfoPrefix(prefix, ipType)
}

func normalizeIPInfoPrefix(prefix netip.Prefix, ipType lib.IPType) (netip.Prefix, error) {
	if ipType != lib.IPv6 || prefix.Bits() <= maxIPInfoIPv6PrefixBits {
		return prefix, nil
	}

	normalized, err := prefix.Addr().Prefix(maxIPInfoIPv6PrefixBits)
	if err != nil {
		return netip.Prefix{}, err
	}

	return normalized.Masked(), nil
}
