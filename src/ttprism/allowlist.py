"""Allowlists suppress well-known benign values (vendor sites, sandbox noise).

Allowlist files are YAML::

    domains:            # drop these domain IOCs
      - google.com      #   exact name
      - "*.example.com" #   the name itself and every subdomain
    url_hosts:          # drop URLs whose host matches (same syntax)
      - attack.mitre.org
    ips:                # addresses or CIDR ranges
      - 8.8.8.8
      - 192.0.2.0/24
    hashes: [d41d8cd98f00b204e9800998ecf8427e]
    emails: [noreply@example.com]

``domains`` only drops the bare domain IOC. A URL on that host is still
reported unless the host is also listed in ``url_hosts``, because attackers
routinely host payloads on large platforms. Keep ``url_hosts`` to reference
and documentation sites.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from ttprism._yaml import ConfigError, load_yaml_file, load_yaml_text
from ttprism.extract import normalize_domain
from ttprism.models import HASH_TYPES, IOCType

_HASH_RE = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")
_KEYS = {"domains", "url_hosts", "ips", "hashes", "emails"}

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_MAX_LISTED_KEYS = 10


class AllowlistError(ConfigError):
    pass


@dataclass
class _DomainSet:
    exact: set[str] = field(default_factory=set)
    suffixes: set[str] = field(default_factory=set)

    def add(self, entry: str, where: str) -> None:
        wildcard = entry.startswith("*.")
        # "_" is allowed where URL hosts allow it, so that every reported domain can be listed.
        name = normalize_domain(entry[2:] if wildcard else entry, allow_underscore=True)
        if name is None:
            raise AllowlistError(f"{where}: not a valid domain name: {entry!r}")
        (self.suffixes if wildcard else self.exact).add(name)

    def matches(self, domain: str) -> bool:
        if domain in self.exact or domain in self.suffixes:
            return True
        parts = domain.split(".")
        return any(".".join(parts[i:]) in self.suffixes for i in range(1, len(parts) - 1))

    def update(self, other: _DomainSet) -> None:
        self.exact |= other.exact
        self.suffixes |= other.suffixes


class _NetworkIndex:
    """Networks grouped by IP version and prefix length.

    A lookup costs one set probe per distinct prefix length (at most 33 for
    IPv4, 129 for IPv6) instead of one test per network.
    """

    def __init__(self, networks: tuple[IPNetwork, ...]) -> None:
        self.source = networks
        # version -> prefix length -> network addresses as integers
        self.starts: dict[int, dict[int, set[int]]] = {4: {}, 6: {}}
        for net in networks:
            self.starts[net.version].setdefault(net.prefixlen, set()).add(int(net.network_address))

    def contains(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        value, bits = int(address), address.max_prefixlen
        for prefixlen, starts in self.starts[address.version].items():
            shift = bits - prefixlen
            if (value >> shift) << shift in starts:
                return True
        return False


@dataclass
class Allowlist:
    domains: _DomainSet = field(default_factory=_DomainSet)
    url_hosts: _DomainSet = field(default_factory=_DomainSet)
    # A tuple, so that the index below cannot go stale: changing it means assigning a new one.
    networks: tuple[IPNetwork, ...] = ()
    hashes: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    _index: _NetworkIndex | None = field(default=None, init=False, repr=False, compare=False)

    @classmethod
    def empty(cls) -> Allowlist:
        return cls()

    @classmethod
    def default(cls) -> Allowlist:
        """The allowlist shipped with TTPrism (a fresh copy, safe to extend)."""
        result = cls()
        result.update(_default_allowlist())
        return result

    @classmethod
    def from_file(cls, path: str | Path) -> Allowlist:
        return cls.from_mapping(load_yaml_file(path, AllowlistError), str(path))

    @classmethod
    def from_mapping(cls, data: Any, where: str = "allowlist") -> Allowlist:
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise AllowlistError(f"{where}: expected a mapping at the top level")
        unknown = set(data) - _KEYS
        if unknown:
            # repr() escapes control characters, which YAML "\e" escapes can put in a key.
            names = sorted(_short(repr(key)) for key in unknown)
            more = len(names) - _MAX_LISTED_KEYS
            listed = ", ".join(names[:_MAX_LISTED_KEYS]) + (f" and {more} more" if more > 0 else "")
            raise AllowlistError(f"{where}: unknown keys: {listed}")
        result = cls()
        networks: list[IPNetwork] = []
        for key in _KEYS:
            values = data.get(key) or []
            if not isinstance(values, list):
                raise AllowlistError(f"{where}: '{key}' must be a list")
            for value in values:
                if not isinstance(value, str):
                    raise AllowlistError(f"{where}: '{key}' entries must be strings, got {value!r}")
                if key == "ips":
                    networks.append(_network(value.strip(), f"{where}: {key}"))
                else:
                    result._add(key, value.strip(), f"{where}: {key}")
        result.networks = tuple(networks)
        return result

    def _add(self, key: str, value: str, where: str) -> None:
        if key == "domains":
            self.domains.add(value, where)
        elif key == "url_hosts":
            self.url_hosts.add(value, where)
        elif key == "hashes":
            if not _HASH_RE.fullmatch(value.lower()):
                raise AllowlistError(f"{where}: not an MD5/SHA-1/SHA-256 hex digest: {value!r}")
            self.hashes.add(value.lower())
        elif key == "emails":
            local, at, domain = value.lower().rpartition("@")
            if not at or not local or normalize_domain(domain) is None:
                raise AllowlistError(f"{where}: not an email address: {value!r}")
            self.emails.add(f"{local}@{normalize_domain(domain)}")

    def update(self, other: Allowlist) -> None:
        self.domains.update(other.domains)
        self.url_hosts.update(other.url_hosts)
        if other.networks:
            self.networks = (*self.networks, *other.networks)
        self.hashes |= other.hashes
        self.emails |= other.emails

    def _ip_listed(self, value: str) -> bool:
        address = ipaddress.ip_address(value)
        index = self._index
        if index is None or index.source is not self.networks:  # rebuilt after networks changed
            index = self._index = _NetworkIndex(self.networks)
        if index.contains(address):
            return True
        # "::ffff:198.51.100.7" is 198.51.100.7, as for the reserved-address check.
        mapped = getattr(address, "ipv4_mapped", None)
        return mapped is not None and index.contains(mapped)

    def matches(self, ioc_type: IOCType, value: str) -> bool:
        if ioc_type == IOCType.DOMAIN:
            return self.domains.matches(value)
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return self._ip_listed(value)
        if ioc_type in HASH_TYPES:
            return value in self.hashes
        if ioc_type == IOCType.EMAIL:
            return value in self.emails
        if ioc_type == IOCType.URL:
            host = url_host(value)
            if host.startswith("[") or host[:1].isdigit():
                try:
                    return self._ip_listed(host.strip("[]"))
                except ValueError:
                    pass
            return self.url_hosts.matches(host)
        return False


def _network(value: str, where: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise AllowlistError(f"{where}: not an IP address or CIDR range: {value!r}") from None


def _short(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def url_host(url: str) -> str:
    """Host part of a URL produced by the extractor (lower-case, no port)."""
    authority = url.split("://", 1)[-1]
    for sep in "/?#":
        authority = authority.split(sep, 1)[0]
    authority = authority.rpartition("@")[2]
    if authority.startswith("["):
        return authority.split("]", 1)[0] + "]"
    return authority.split(":", 1)[0]


@functools.cache
def _default_allowlist() -> Allowlist:
    text = resources.files("ttprism").joinpath("data/allowlist.yaml").read_text(encoding="utf-8")
    return Allowlist.from_mapping(
        load_yaml_text(text, "default allowlist", AllowlistError), "default allowlist"
    )
