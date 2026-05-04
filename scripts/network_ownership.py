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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _port_allowed(allowed_ports: Any, protocol: str | None, from_port: Any, to_port: Any) -> bool:
    protocol = str(protocol or "").lower()
    if protocol in {"-1", "all"}:
        return False
    try:
        start = int(from_port)
        end = int(to_port)
    except Exception:
        return False
    if start != end:
        return False
    if isinstance(allowed_ports, dict):
        candidates = allowed_ports.get(protocol) or []
    elif isinstance(allowed_ports, list):
        candidates = allowed_ports
    else:
        return False
    for entry in candidates:
        if isinstance(entry, int) and entry == start:
            return True
        if isinstance(entry, str) and entry.isdigit() and int(entry) == start:
            return True
        if isinstance(entry, dict):
            try:
                e_start = int(entry.get("from_port"))
                e_end = int(entry.get("to_port"))
            except Exception:
                continue
            if e_start <= start <= e_end and e_start <= end <= e_end:
                return True
    return False


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
    if not _port_allowed(network.get("allowed_ports"), protocol, from_port, to_port):
        return NetworkOwnership(cidr, tenant_slug, authority or "platform-sg", name, "owned_port_mismatch", f"CIDR is owned by {tenant_slug}/{name}, but port is not pre-approved")

    return NetworkOwnership(cidr, tenant_slug, authority or "platform-sg", name, "owned_allowed", f"CIDR is owned by {tenant_slug}/{name} and port is allowed", True)
