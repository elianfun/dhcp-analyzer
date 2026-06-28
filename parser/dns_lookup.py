import dns.resolver
import dns.reversename
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed

DNS_SERVERS = [
    "192.168.197.1",
    "192.168.97.1",
    "192.168.222.1",
]

_TIMEOUT   = 1.0   # seconds per DNS server
_MAX_WORKERS = 80


def _reverse_lookup(ip: str) -> str:
    """對 3 台 DNS server 依序做 PTR 查詢，回傳第一個成功的結果，全失敗回傳空字串。"""
    try:
        ptr_name = dns.reversename.from_address(ip)
    except Exception:
        return ""

    for server in DNS_SERVERS:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server]
            resolver.timeout     = _TIMEOUT
            resolver.lifetime    = _TIMEOUT
            answers = resolver.resolve(ptr_name, "PTR")
            if answers:
                return str(answers[0]).rstrip(".")
        except (dns.exception.DNSException, OSError):
            continue
    return ""


def bulk_reverse_lookup(ips: list[str]) -> dict[str, str]:
    """平行對所有 IP 做反查，回傳 {ip: dns_name}。"""
    results: dict[str, str] = {}
    unique_ips = list(set(ips))

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(_reverse_lookup, ip): ip for ip in unique_ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = ""
    return results
