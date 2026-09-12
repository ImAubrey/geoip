#!/usr/bin/env python3

import argparse
import io
import ipaddress
import urllib.request
from pathlib import Path

import pyarrow.parquet as parquet


DEFAULT_IPV4_URL = (
    "https://raw.githubusercontent.com/ut-dacs/anycast-census/"
    "main/IPv4-latest.parquet"
)
DEFAULT_IPV6_URL = (
    "https://raw.githubusercontent.com/ut-dacs/anycast-census/"
    "main/IPv6-latest.parquet"
)


def read_parquet(source: str, columns: list[str]):
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(
            source, headers={"User-Agent": "ImAubrey/geoip anycast builder"}
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read()
        return parquet.read_table(io.BytesIO(data), columns=columns)
    return parquet.read_table(source, columns=columns)


def filtered_prefixes(source: str, version: int) -> list[ipaddress._BaseNetwork]:
    suffix = f"v{version}"
    ab_columns = [f"AB_ICMP{suffix}", f"AB_TCP{suffix}", f"AB_DNS{suffix}"]
    gcd_columns = [f"GCD_ICMP{suffix}", f"GCD_TCP{suffix}"]
    columns = ["prefix", *ab_columns, *gcd_columns]
    if version == 4:
        columns.append("partial")

    values = read_parquet(source, columns).to_pydict()
    prefixes: set[ipaddress._BaseNetwork] = set()
    for index, raw_prefix in enumerate(values["prefix"]):
        max_ab = max(values[column][index] or 0 for column in ab_columns)
        max_gcd = max(values[column][index] or 0 for column in gcd_columns)
        if max_ab <= 3 and max_gcd <= 1:
            continue
        if version == 4 and values["partial"][index]:
            continue

        prefix = ipaddress.ip_network(raw_prefix, strict=True)
        if prefix.version != version:
            raise ValueError(f"unexpected IPv{prefix.version} prefix in IPv{version} data: {prefix}")
        prefixes.add(prefix)

    return sorted(prefixes, key=lambda prefix: (int(prefix.network_address), prefix.prefixlen))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a high-confidence Anycast prefix list from LACeS census data."
    )
    parser.add_argument("--ipv4", default=DEFAULT_IPV4_URL)
    parser.add_argument("--ipv6", default=DEFAULT_IPV6_URL)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    ipv4 = filtered_prefixes(args.ipv4, 4)
    ipv6 = filtered_prefixes(args.ipv6, 6)
    if not ipv4 or not ipv6:
        raise RuntimeError("Anycast census produced an empty IPv4 or IPv6 list")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(f"{prefix}\n" for prefix in (*ipv4, *ipv6)), encoding="utf-8"
    )
    print(f"Wrote {len(ipv4)} IPv4 and {len(ipv6)} IPv6 Anycast prefixes to {output}")


if __name__ == "__main__":
    main()
