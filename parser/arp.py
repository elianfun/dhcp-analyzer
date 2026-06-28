import mysql.connector
from dataclasses import dataclass


@dataclass
class ArpEntry:
    ip: str
    mac: str
    source_device: str
    interface: str


# ARP 來源設備（LibreNMS 監控的 L3 設備）
ARP_SOURCE_DEVICES = [
    "192.168.180.254",
    "192.168.199.254",
    "10.10.70.2",
    "10.18.255.41",
]

DB_CONFIG = {
    "user": "librenms",
    "password": "librenms",
    "host": "192.168.50.55",
    "database": "librenms",
}


def _normalize_mac(mac: str) -> str:
    mac = mac.lower().replace("-", ":").strip()
    parts = mac.split(":")
    return ":".join(p.zfill(2) for p in parts)


def fetch_arp_entries() -> list[ArpEntry]:
    placeholders = ", ".join(["%s"] * len(ARP_SOURCE_DEVICES))
    query = f"""
        SELECT
            devices.hostname  AS source_device,
            ipv4_mac.ipv4_address AS ip,
            ipv4_mac.mac_address  AS mac,
            ports.ifName          AS interface
        FROM ipv4_mac
        LEFT JOIN ports
            ON  ipv4_mac.device_id = ports.device_id
            AND ipv4_mac.port_id   = ports.port_id
        LEFT JOIN devices
            ON  ipv4_mac.device_id = devices.device_id
        WHERE devices.hostname IN ({placeholders})
    """
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute(query, ARP_SOURCE_DEVICES)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    entries = []
    for source_device, ip, mac, interface in rows:
        formatted_mac = ":".join(mac[i:i+2] for i in range(0, len(mac), 2))
        entries.append(ArpEntry(
            ip=ip,
            mac=_normalize_mac(formatted_mac),
            source_device=source_device,
            interface=interface or "",
        ))
    return entries


def get_arp_by_ip(entries: list[ArpEntry]) -> dict[str, ArpEntry]:
    result: dict[str, ArpEntry] = {}
    for e in entries:
        if e.ip not in result:
            result[e.ip] = e
    return result
