#!/usr/bin/env python3

import argparse
import csv
import io
import ipaddress
import urllib.request
from pathlib import Path


DEFAULT_SOURCE = "https://api.cloudflare.com/local-ip-ranges.csv"


def read_source(source: str) -> str:
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(
            source, headers={"User-Agent": "ImAubrey/geoip WARP builder"}
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read().decode("utf-8")
    return Path(source).read_text(encoding="utf-8")


def load_prefixes(source: str):
    prefixes = {4: set(), 6: set()}
    for line_number, row in enumerate(csv.reader(io.StringIO(read_source(source))), 1):
        if not row or not row[0].strip():
            continue
        try:
            prefix = ipaddress.ip_network(row[0].strip(), strict=True)
        except ValueError as error:
            raise ValueError(f"invalid Cloudflare prefix on line {line_number}: {row[0]}") from error
        prefixes[prefix.version].add(prefix)

    if len(prefixes[4]) < 1000 or len(prefixes[6]) < 1000:
        raise RuntimeError("Cloudflare WARP egress source returned too few IPv4 or IPv6 prefixes")
    return prefixes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build Cloudflare forward-proxy/WARP egress prefix lists."
    )
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    prefixes = load_prefixes(args.source)
    collapsed = []
    for version in (4, 6):
        collapsed.extend(ipaddress.collapse_addresses(prefixes[version]))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(f"{prefix}\n" for prefix in collapsed), encoding="utf-8")
    print(
        f"Wrote {len(collapsed)} collapsed Cloudflare WARP egress prefixes "
        f"from {len(prefixes[4])} IPv4 and {len(prefixes[6])} IPv6 source records"
    )


if __name__ == "__main__":
    main()
