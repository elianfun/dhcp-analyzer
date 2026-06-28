import paramiko
from dataclasses import dataclass, field
from parser.dhcp_conf import (
    parse_conf, ip_in_any_range, ip_in_fixed, ip_in_known_subnet, DhcpConfig
)
from parser.dhcp_leases import parse_leases, get_active_leases
from parser.arp import fetch_arp_entries, get_arp_by_ip, ArpEntry
from parser.dns_lookup import bulk_reverse_lookup


DHCP_SERVERS = [
    {"host": "192.168.50.1", "name": "DHCP01P"},
    {"host": "192.168.50.4", "name": "DHCP04P"},
    {"host": "192.168.50.5", "name": "DHCP05P"},
    {"host": "172.21.5.1",   "name": "DHCP08P"},
]

SSH_USER = "inno"
SSH_KEY  = "/home/inno/.ssh/id_ed25519"

CONF_PATH   = "/etc/dhcp/dhcpd.conf"
LEASES_PATH = "/var/lib/dhcp/dhcpd.leases"


@dataclass
class Anomaly:
    type: str           # A / B / C / D
    ip: str
    arp_mac: str
    arp_source: str
    arp_interface: str
    lease_mac: str
    lease_state: str
    lease_hostname: str
    fixed_name: str
    fixed_mac: str
    dhcp_server: str
    description: str
    subnet_managed: bool = False  # IP 所屬子網路是否有在任何 dhcpd.conf 宣告
    dns_name: str = ""            # PTR 反查結果


@dataclass
class AnalysisResult:
    anomalies: list[Anomaly] = field(default_factory=list)
    arp_total: int = 0
    servers_ok: list[str] = field(default_factory=list)
    servers_error: list[dict] = field(default_factory=list)


def _ssh_read(client: paramiko.SSHClient, path: str) -> str:
    _, stdout, _ = client.exec_command(f"cat {path}")
    return stdout.read().decode("utf-8", errors="replace")


def _fetch_dhcp_data(server: dict) -> tuple[DhcpConfig | None, dict, str | None]:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server["host"], username=SSH_USER, key_filename=SSH_KEY, timeout=10)

        conf_content   = _ssh_read(client, CONF_PATH)
        leases_content = _ssh_read(client, LEASES_PATH)
        client.close()

        config = parse_conf(conf_content)
        leases = parse_leases(leases_content)
        active = get_active_leases(leases)
        return config, active, None
    except Exception as e:
        return None, {}, str(e)


def run_analysis() -> AnalysisResult:
    result = AnalysisResult()

    # 1. 取得所有 DHCP server 的設定與 lease
    all_ranges        = []
    all_fixed         = []
    all_leases        = {}   # ip -> (Lease, server_name)
    all_known_subnets = []   # 所有 dhcpd.conf 宣告過的子網路

    for srv in DHCP_SERVERS:
        config, active, error = _fetch_dhcp_data(srv)
        if error:
            result.servers_error.append({"server": srv["name"], "error": error})
            continue

        result.servers_ok.append(srv["name"])
        all_ranges.extend(config.ranges)
        all_fixed.extend(config.fixed_addresses)
        all_known_subnets.extend(config.known_subnets)

        for ip, lease in active.items():
            if ip not in all_leases:
                all_leases[ip] = (lease, srv["name"])

    # 去重（不同 server 可能宣告相同子網路）
    all_known_subnets = list(set(all_known_subnets))

    # 2. 取得 ARP 資料
    arp_entries = fetch_arp_entries()
    arp_by_ip   = get_arp_by_ip(arp_entries)
    result.arp_total = len(arp_by_ip)

    fixed_by_ip = {fa.ip: fa for fa in all_fixed}

    # 3. 比對邏輯
    for ip, arp in arp_by_ip.items():
        in_range       = ip_in_any_range(ip, all_ranges)
        fixed          = fixed_by_ip.get(ip)
        lease_tup      = all_leases.get(ip)
        lease          = lease_tup[0] if lease_tup else None
        srv_name       = lease_tup[1] if lease_tup else ""
        in_managed_net = ip_in_known_subnet(ip, all_known_subnets)

        def base(t, desc) -> Anomaly:
            return Anomaly(
                type=t,
                ip=ip,
                arp_mac=arp.mac,
                arp_source=arp.source_device,
                arp_interface=arp.interface,
                lease_mac=lease.mac if lease else "",
                lease_state=lease.state if lease else "",
                lease_hostname=lease.hostname if lease else "",
                fixed_name=fixed.name if fixed else "",
                fixed_mac=fixed.mac if fixed else "",
                dhcp_server=srv_name,
                description=desc,
                subnet_managed=in_managed_net,
            )

        if in_range and not lease and not fixed:
            # Type A：佔用 DHCP pool，無 lease 無 fixed-address
            result.anomalies.append(base(
                "A",
                f"IP 落在 DHCP pool {in_range.start}-{in_range.end}，"
                f"但無 active lease 且未登錄 fixed-address，疑似手動設靜態 IP"
            ))

        elif lease and arp.mac != lease.mac:
            # Type B：ARP MAC 與 lease MAC 不符
            result.anomalies.append(base(
                "B",
                f"Active lease MAC ({lease.mac}) 與 ARP MAC ({arp.mac}) 不符，可能發生 IP 衝突"
            ))

        elif fixed and arp.mac != fixed.mac:
            # Type C：ARP MAC 與 fixed-address MAC 不符
            result.anomalies.append(base(
                "C",
                f"fixed-address 登錄 MAC ({fixed.mac}) 與 ARP MAC ({arp.mac}) 不符，"
                f"設備可能已更換但設定未更新"
            ))

        elif not in_range and not fixed:
            # Type D：不在任何 DHCP pool，也未登錄 fixed-address
            if in_managed_net:
                desc = "IP 所屬子網路有 DHCP 設定，但此 IP 未登錄 fixed-address，管理者忘記登記"
            else:
                desc = "IP 所屬子網路未在任何 dhcpd.conf 宣告，屬於純靜態管理網段"
            result.anomalies.append(base("D", desc))

    # 依類型 → subnet_managed(managed優先) → IP 排序
    result.anomalies.sort(key=lambda a: (a.type, not a.subnet_managed, a.ip))

    # DNS 反查（平行查詢，填入每筆異常）
    all_ips   = [a.ip for a in result.anomalies]
    dns_cache = bulk_reverse_lookup(all_ips)
    for a in result.anomalies:
        a.dns_name = dns_cache.get(a.ip, "")

    return result
