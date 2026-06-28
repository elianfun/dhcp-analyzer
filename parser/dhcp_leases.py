import re
from dataclasses import dataclass


@dataclass
class Lease:
    ip: str
    mac: str
    state: str          # active / free / expired / released
    hostname: str
    starts: str
    ends: str


def _normalize_mac(mac: str) -> str:
    return mac.lower().strip(";")


def parse_leases(content: str) -> list[Lease]:
    leases: dict[str, Lease] = {}

    ip = mac = state = hostname = starts = ends = None

    for line in content.splitlines():
        stripped = line.strip()

        m = re.match(r'^lease\s+([\d.]+)\s*\{', stripped)
        if m:
            ip = m.group(1)
            mac = state = hostname = starts = ends = None
            continue

        if stripped.startswith("hardware ethernet"):
            m = re.match(r'hardware\s+ethernet\s+([\da-fA-F:]+)', stripped)
            if m:
                mac = _normalize_mac(m.group(1))

        elif stripped.startswith("binding state"):
            m = re.match(r'binding\s+state\s+(\w+)', stripped)
            if m:
                state = m.group(1)

        elif stripped.startswith("client-hostname"):
            m = re.match(r'client-hostname\s+"([^"]*)"', stripped)
            if m:
                hostname = m.group(1)

        elif stripped.startswith("starts"):
            m = re.match(r'starts\s+\d+\s+([\d/]+ [\d:]+)', stripped)
            if m:
                starts = m.group(1)

        elif stripped.startswith("ends"):
            m = re.match(r'ends\s+\d+\s+([\d/]+ [\d:]+)', stripped)
            if m:
                ends = m.group(1)

        elif stripped == "}":
            if ip and mac and state:
                # 同一 IP 可能有多筆記錄，保留最新的 active，否則保留最後一筆
                existing = leases.get(ip)
                if existing is None or state == "active" or existing.state != "active":
                    leases[ip] = Lease(
                        ip=ip,
                        mac=mac,
                        state=state,
                        hostname=hostname or "",
                        starts=starts or "",
                        ends=ends or ""
                    )
            ip = None

    return list(leases.values())


def get_active_leases(leases: list[Lease]) -> dict[str, Lease]:
    return {l.ip: l for l in leases if l.state == "active"}
