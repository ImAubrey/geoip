#!/usr/bin/env python3
"""Refresh dnscry.pt resolver IPs in custom/common-dns.txt."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path


DEFAULT_SOURCE_URL = "https://www.dnscry.pt/resolvers.json"
BEGIN_MARKER = "# BEGIN dnscry.pt resolvers (managed)"
END_MARKER = "# END dnscry.pt resolvers (managed)"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def fetch_resolvers(source_url: str) -> list[dict[str, object]]:
    request = urllib.request.Request(
        source_url,
        headers={"User-Agent": "ImAubrey/geoip dnscry.pt common-dns updater"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"failed to fetch {source_url}: HTTP {response.status}")
        payload = json.loads(response.read().decode("utf-8"))

    if not isinstance(payload, list):
        raise RuntimeError(f"expected a JSON list from {source_url}")

    resolvers: list[dict[str, object]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise RuntimeError(f"unexpected resolver item in {source_url}: {item!r}")
        resolvers.append(item)
    return resolvers


def clean_domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    domain = value.strip().strip(".").lower()
    if not domain:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(char not in allowed for char in domain):
        return None
    return domain


def collect_entries(resolvers: list[dict[str, object]]) -> tuple[list[str], list[tuple[ipaddress._BaseAddress, str]]]:
    domains: set[str] = set()
    ip_to_hosts: dict[ipaddress._BaseAddress, set[str]] = {}

    for resolver in resolvers:
        host = clean_domain(resolver.get("host"))
        provider = clean_domain(resolver.get("provider"))

        if host:
            domains.add(host)
        if provider:
            domains.add(provider)

        for field in ("ipv4", "ipv6"):
            value = resolver.get(field)
            if not isinstance(value, str) or not value.strip():
                continue
            try:
                addr = ipaddress.ip_address(value.strip())
            except ValueError as exc:
                raise RuntimeError(f"invalid {field} address {value!r} for {host or 'unknown host'}") from exc
            ip_to_hosts.setdefault(addr, set())
            if host:
                ip_to_hosts[addr].add(host)

    ips = sorted(ip_to_hosts.items(), key=lambda item: (item[0].version, int(item[0])))
    return sorted(domains), [(addr, ", ".join(sorted(hosts))) for addr, hosts in ips]


def render_block(source_url: str, domains: list[str], ips: list[tuple[ipaddress._BaseAddress, str]]) -> str:
    ipv4_count = sum(1 for addr, _ in ips if addr.version == 4)
    ipv6_count = sum(1 for addr, _ in ips if addr.version == 6)

    lines = [
        BEGIN_MARKER,
        f"# Source: {source_url}",
        "# Domain names below are comments for review; common-dns only imports IP/CIDR entries.",
        f"# Resolver domains: {len(domains)}",
        f"# IPv4: {ipv4_count}",
        f"# IPv6: {ipv6_count}",
        "# Domains:",
    ]
    lines.extend(f"# - {domain}" for domain in domains)
    lines.append("# IP addresses:")
    for addr, hosts in ips:
        suffix = f" # {hosts}" if hosts else ""
        lines.append(f"{addr.compressed}{suffix}")
    lines.append(END_MARKER)
    return "\n".join(lines)


def replace_managed_block(existing: str, block: str) -> str:
    start = existing.find(BEGIN_MARKER)
    end = existing.find(END_MARKER)

    if start == -1 and end == -1:
        return existing.rstrip() + "\n\n" + block + "\n"

    if start == -1 or end == -1 or end < start:
        raise RuntimeError("found an incomplete dnscry.pt managed block")

    end += len(END_MARKER)
    return existing[:start].rstrip() + "\n\n" + block + "\n" + existing[end:].lstrip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", default=DEFAULT_SOURCE_URL)
    parser.add_argument(
        "--common-dns",
        type=Path,
        default=repo_root() / "custom" / "common-dns.txt",
        help="path to custom/common-dns.txt",
    )
    args = parser.parse_args()

    common_dns = args.common_dns
    if not common_dns.is_absolute():
        common_dns = repo_root() / common_dns

    resolvers = fetch_resolvers(args.source_url)
    domains, ips = collect_entries(resolvers)
    block = render_block(args.source_url, domains, ips)

    existing = common_dns.read_text(encoding="utf-8")
    updated = replace_managed_block(existing, block)
    common_dns.write_text(updated, encoding="utf-8", newline="\n")

    ipv4_count = sum(1 for addr, _ in ips if addr.version == 4)
    ipv6_count = sum(1 for addr, _ in ips if addr.version == 6)
    print(
        f"Updated {common_dns} with {len(domains)} domains, "
        f"{ipv4_count} IPv4 addresses, and {ipv6_count} IPv6 addresses."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
