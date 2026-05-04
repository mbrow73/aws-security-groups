#!/usr/bin/env python3
"""Tenant-owned network surface resolution for CIDR review routing."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class NetworkOwnership:
    cidr: str
    owner_tenant: str | None
    owner_authority: str | None
    network_name: str | None
    classification: str
    reason: str
    allowed: bool = False
    grant_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _port_matches(entry: Any, port: int) -> bool:
    if isinstance(entry, int) and entry == port:
        return True
    if isinstance(entry, str) and entry.isdigit() and int(entry) == port:
        return True
    if isinstance(entry, dict):
        try:
            return int(entry.get("from_port")) <= port <= int(entry.get("to_port"))
        except Exception:
            return False
    return False


def grant_matches_network(
    grant: dict[str, Any],
    network_name: str,
    source_tenant: str | None,
    direction: str | None,
    protocol: str | None,
    from_port: Any,
    to_port: Any,
) -> bool:
    target_networks = grant.get("target_networks") or []
    if target_networks and "*" not in target_networks and network_name not in target_networks:
        return False
    source_tenants = grant.get("source_tenants") or []
    if source_tenants and "*" not in source_tenants and source_tenant not in source_tenants:
        return False
    directions = grant.get("directions") or []
    if directions and "*" not in directions and direction not in directions:
        return False
    protocols = [str(p).lower() for p in grant.get("protocols") or []]
    if protocols and "*" not in protocols and str(protocol or "").lower() not in protocols:
        return False
    try:
        start = int(from_port)
        end = int(to_port)
    except Exception:
        return False
    if start != end:
        return False
    ports = grant.get("ports") or []
    ranges = grant.get("port_ranges") or []
    return any(_port_matches(port, start) for port in ports) or any(_port_matches(r, start) for r in ranges)


def find_matching_network_grant(
    tenant: dict[str, Any],
    network_name: str,
    source_tenant: str | None,
    direction: str | None,
    protocol: str | None,
    from_port: Any,
    to_port: Any,
) -> str | None:
    for grant in tenant.get("reference_grants") or []:
        if not isinstance(grant, dict):
            continue
        if grant_matches_network(grant, network_name, source_tenant, direction, protocol, from_port, to_port):
            return grant.get("name") or "unnamed-grant"
    return None


def _iter_owned_networks(tenants: dict[str, Any]):
    for tenant_slug, tenant in (tenants or {}).items():
        if not isinstance(tenant, dict):
            continue
        authority = tenant.get("review_authority")
        for name, network in (tenant.get("owned_networks") or {}).items():
            if not isinstance(network, dict):
                continue
            for cidr in network.get("cidrs") or []:
                yield tenant_slug, authority, name, network, cidr


def classify_cidr_ownership(
    tenants: dict[str, Any],
    cidr: str,
    protocol: str | None = None,
    from_port: Any = None,
    to_port: Any = None,
) -> NetworkOwnership:
    try:
        requested = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return NetworkOwnership(cidr, None, None, None, "invalid", "invalid CIDR")

    matches = []
    for tenant_slug, authority, name, network, owned_cidr in _iter_owned_networks(tenants):
        try:
            owned = ipaddress.ip_network(str(owned_cidr), strict=False)
        except ValueError:
            continue
        if requested.subnet_of(owned):
            matches.append((tenant_slug, authority, name, network, str(owned)))

    if not matches:
        return NetworkOwnership(cidr, None, "platform-sg", None, "unknown", "CIDR is not registered to a tenant-owned network")

    owners = {(tenant, name) for tenant, _authority, name, _network, _owned in matches}
    if len(owners) > 1:
        return NetworkOwnership(cidr, None, "platform-sg", None, "overlap", "CIDR matches multiple tenant-owned networks")

    tenant_slug, authority, name, network, owned = matches[0]
    return NetworkOwnership(cidr, tenant_slug, authority or "platform-sg", name, "owned", f"CIDR is owned by {tenant_slug}/{name}", False)
