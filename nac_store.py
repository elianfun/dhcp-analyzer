import json
import os

_PATH = os.path.join(os.path.dirname(__file__), "nac_macs.json")
_DEFAULT = ["bc:24:11:eb:3f:77"]


def _normalize(mac: str) -> str:
    return mac.lower().strip()


def load() -> list[str]:
    if os.path.exists(_PATH):
        try:
            with open(_PATH) as f:
                data = json.load(f)
            return [_normalize(m) for m in data if m.strip()]
        except Exception:
            pass
    return list(_DEFAULT)


def save(macs: list[str]) -> None:
    with open(_PATH, "w") as f:
        json.dump([_normalize(m) for m in macs if m.strip()], f, indent=2)


def is_nac_mac(mac: str, nac_macs: list[str]) -> bool:
    return _normalize(mac) in nac_macs
