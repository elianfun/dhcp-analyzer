import re
import ipaddress
from dataclasses import dataclass, field


@dataclass
class DhcpRange:
    start: str
    end: str
    subnet: str


@dataclass
class FixedAddress:
    name: str
    mac: str
    ip: str
    subnet: str


@dataclass
class DhcpConfig:
    ranges: list[DhcpRange] = field(default_factory=list)
    fixed_addresses: list[FixedAddress] = field(default_factory=list)
    # 所有在 dhcpd.conf 宣告的子網路（含無 range 的純宣告）
    known_subnets: list[tuple[str, str]] = field(default_factory=list)  # (network, netmask)


def _normalize_mac(mac: str) -> str:
    return mac.lower().strip(";")


def parse_conf(content: str) -> DhcpConfig:
    config = DhcpConfig()
    current_subnet = None
    current_host_name = None
    current_host_mac = None
    current_host_ip = None
    brace_depth = 0
    host_brace_start = None

    for line in content.splitlines():
        stripped = line.strip()

        # track current subnet
        m = re.match(r'subnet\s+([\d.]+)\s+netmask\s+([\d.]+)', stripped)
        if m:
            current_subnet = m.group(1)
            config.known_subnets.append((m.group(1), m.group(2)))

        # range
        m = re.match(r'range(?:\s+dynamic-bootp)?\s+([\d.]+)\s+([\d.]+)', stripped)
        if m and current_subnet:
            config.ranges.append(DhcpRange(
                start=m.group(1),
                end=m.group(2),
                subnet=current_subnet
            ))

        # host block start
        m = re.match(r'host\s+(\S+)\s*\{?', stripped)
        if m:
            current_host_name = m.group(1).strip("{").strip()
            current_host_mac = None
            current_host_ip = None
            host_brace_start = brace_depth

        # hardware ethernet
        m = re.match(r'hardware\s+ethernet\s+([\da-fA-F:]+)', stripped)
        if m and current_host_name is not None:
            current_host_mac = _normalize_mac(m.group(1))

        # fixed-address
        m = re.match(r'fixed-address\s+([\d.]+)', stripped)
        if m and current_host_name is not None:
            current_host_ip = m.group(1).strip(";")

        brace_depth += stripped.count("{") - stripped.count("}")

        # end of host block
        if current_host_name is not None and host_brace_start is not None:
            if brace_depth <= host_brace_start and ("}" in stripped):
                if current_host_mac and current_host_ip:
                    config.fixed_addresses.append(FixedAddress(
                        name=current_host_name,
                        mac=current_host_mac,
                        ip=current_host_ip,
                        subnet=current_subnet or ""
                    ))
                current_host_name = None
                current_host_mac = None
                current_host_ip = None
                host_brace_start = None

    return config


def ip_in_any_range(ip: str, ranges: list[DhcpRange]) -> DhcpRange | None:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for r in ranges:
            if ipaddress.ip_address(r.start) <= ip_obj <= ipaddress.ip_address(r.end):
                return r
    except ValueError:
        pass
    return None


def ip_in_fixed(ip: str, fixed_addresses: list[FixedAddress]) -> FixedAddress | None:
    for fa in fixed_addresses:
        if fa.ip == ip:
            return fa
    return None


def ip_in_known_subnet(ip: str, known_subnets: list[tuple[str, str]]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network, netmask in known_subnets:
            net = ipaddress.ip_network(f"{network}/{netmask}", strict=False)
            if ip_obj in net:
                return True
    except ValueError:
        pass
    return False
