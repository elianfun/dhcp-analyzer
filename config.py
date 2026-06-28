import hashlib
import os

# 修改這裡設定帳號與密碼
AUTH_USERNAME = os.environ.get("DHCP_USER", "admin")
_RAW_PASSWORD = os.environ.get("DHCP_PASS", "admin1234")

# 密碼以 SHA-256 hash 儲存，不明文比對
AUTH_PASSWORD_HASH = hashlib.sha256(_RAW_PASSWORD.encode()).hexdigest()

# Session 簽名金鑰，正式部署請改為隨機長字串
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dhcp-analyzer-secret-key-change-me")


def verify_password(plain: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == AUTH_PASSWORD_HASH
