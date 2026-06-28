import hashlib
import os

# Session 簽名金鑰，正式部署請改為隨機長字串或設定環境變數 SESSION_SECRET
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dhcp-analyzer-secret-key-change-me")


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# 帳號設定：{ "帳號": "密碼" }
# 新增帳號直接在此加一行即可
USERS: dict[str, str] = {
    "admin":  _hash("admin1234"),
    "inno":   _hash("inno1234"),
}


def verify_password(username: str, plain: str) -> bool:
    hashed = USERS.get(username)
    if not hashed:
        return False
    return _hash(plain) == hashed
