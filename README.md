# DHCP Analyzer

即時比對 ISC-DHCP Server 設定、租約記錄與網路 ARP 資料，自動偵測 IP 配發異常的 Web 工具。

## 背景與問題

在多台 ISC-DHCP Server 的環境中，管理者有時會在設備端直接設定靜態 IP，卻忘記將該 IP 回填至 DHCP 設定檔（`dhcpd.conf`）。這會導致：

- DHCP Server 未來可能將同一個 IP 重複配發給其他設備，造成 IP 衝突
- 靜態 IP 使用情況缺乏追蹤，難以稽核

本工具透過比對以下三個資料來源，自動找出差異：

| 資料來源 | 取得方式 |
|---|---|
| ARP 現況（目前在線 IP ↔ MAC） | 直接查詢 LibreNMS MySQL 資料庫 |
| DHCP 配發範圍 + 固定 IP 設定 | SSH 讀取各 DHCP Server 的 `dhcpd.conf` |
| 目前有效的 DHCP 租約 | SSH 讀取各 DHCP Server 的 `dhcpd.leases` |

---

## 異常類型說明

| 類型 | 說明 | 嚴重度 |
|---|---|---|
| **A** | IP 落在 DHCP Pool 範圍內，但無 active lease 也無 fixed-address 登錄。疑似設備端手動設靜態 IP 佔用了 DHCP 配發池，下次 DHCP 有可能重複配發此 IP | 🔴 高 |
| **B** | IP 有 active lease，但 ARP 顯示的 MAC 與 lease 記錄的 MAC 不符。可能已發生 IP 衝突（兩台設備同時使用同一 IP） | 🔴 高 |
| **C** | IP 有 fixed-address 設定，但 ARP 顯示的 MAC 與設定中的 MAC 不符。設備可能已更換，但 dhcpd.conf 尚未更新 | 🟡 中 |
| **D (DHCP管理網段)** | IP 所屬子網路在 dhcpd.conf 中有宣告，但此 IP 既不在 DHCP Pool 範圍內，也未登錄 fixed-address。管理者忘記登記 | 🟡 中 |
| **D (純靜態網段)** | IP 所屬子網路完全未出現在任何 dhcpd.conf。屬於純靜態管理的網段，僅供參考 | ⚪ 低 |
| **NAC** | ARP MAC 符合 NAC 設備 MAC 清單。此 IP 已被 NAC 封鎖，不列入 A/B/C/D 異常 | 🟢 封鎖中 |

---

## 系統架構

```
                 ┌─────────────────────────────────────┐
                 │         192.168.50.74               │
                 │   dhcp-analyzer (FastAPI + Web UI)  │
                 └──────┬──────────────┬───────────────┘
                        │ SSH          │ MySQL
          ┌─────────────┴──────┐   ┌──┴──────────────┐
          │  4 台 ISC-DHCP     │   │  LibreNMS        │
          │  Server            │   │  192.168.50.55   │
          │  192.168.50.1      │   │                  │
          │  192.168.50.4      │   │  ipv4_mac 資料表  │
          │  192.168.50.5      │   │  (ARP 現況)       │
          │  172.21.5.1        │   └──────────────────┘
          │                    │
          │  /etc/dhcp/dhcpd.conf
          │  /var/lib/dhcp/dhcpd.leases
          └────────────────────┘
```

**ARP 資料來源設備**（LibreNMS 監控的 L3 Switch/Router）：
- `192.168.180.254`
- `192.168.199.254`
- `10.10.70.2`
- `10.18.255.41`

---

## 安裝與部署

### 環境需求

- Python 3.10+
- 執行主機可 SSH 連線到所有 DHCP Server（使用 key 認證）
- 執行主機可連線到 LibreNMS MySQL（port 3306）

### 1. 安裝相依套件

```bash
pip install -r requirements.txt
```

### 2. SSH Key 設定

在執行主機產生 key pair：

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N '' -C 'dhcp-analyzer@<host>'
```

將 public key 加到每台 DHCP Server：

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo '<public key>' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### 3. 設定調整

編輯 `analyzer.py` 調整以下參數：

```python
# DHCP Server 清單
DHCP_SERVERS = [
    {"host": "192.168.50.1", "name": "DHCP01P"},
    {"host": "192.168.50.4", "name": "DHCP04P"},
    {"host": "192.168.50.5", "name": "DHCP05P"},
    {"host": "172.21.5.1",   "name": "DHCP08P"},
]

SSH_USER = "inno"
SSH_KEY  = "/home/inno/.ssh/id_ed25519"
```

編輯 `parser/arp.py` 調整 LibreNMS MySQL 連線與 ARP 來源設備：

```python
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
```

編輯 `config.py` 調整帳號密碼與 Session 金鑰：

```python
USERS: dict[str, str] = {
    "admin": _hash("admin1234"),
    "inno":  _hash("inno1234"),
}

SESSION_SECRET = os.environ.get("SESSION_SECRET", "dhcp-analyzer-secret-key-change-me")
```

### 4. NAC 設備 MAC 設定

NAC 設備 MAC 儲存於 `nac_macs.json`，可直接編輯或透過 Web UI 的「NAC 設定」按鈕管理：

```json
["bc:24:11:eb:3f:77"]
```

ARP MAC 符合清單的 IP 將被標記為「NAC 封鎖」，不列入 A/B/C/D 異常。

### 5. 啟動服務

```bash
cd dhcp-analyzer
uvicorn app:app --host 0.0.0.0 --port 8080
```

瀏覽器開啟 `http://<host>:8080`，以帳號密碼登入後即可使用。

**服務管理指令：**

```bash
# 查看是否在跑
pgrep -a uvicorn

# 停止
kill $(pgrep -f uvicorn)

# 重啟
kill $(pgrep -f uvicorn) 2>/dev/null; sleep 1
cd ~/dhcp-analyzer && nohup /home/inno/.local/bin/uvicorn app:app --host 0.0.0.0 --port 8080 > /tmp/dhcp-analyzer.log 2>&1 &

# 查看即時 log
tail -f /tmp/dhcp-analyzer.log
```

---

## 專案結構

```
dhcp-analyzer/
├── app.py                  # FastAPI 後端，REST API、認證、靜態檔案服務
├── analyzer.py             # 核心比對邏輯（SSH 取資料 + 異常偵測 + DNS 反查）
├── config.py               # 帳號密碼設定
├── nac_store.py            # NAC MAC 清單讀寫（nac_macs.json）
├── nac_macs.json           # NAC 設備 MAC 清單（Web UI 可即時更新）
├── parser/
│   ├── dhcp_conf.py        # 解析 dhcpd.conf（pool range、fixed-address、known subnets）
│   ├── dhcp_leases.py      # 解析 dhcpd.leases（active lease 記錄）
│   ├── arp.py              # 查詢 LibreNMS MySQL 取得 ARP 現況
│   └── dns_lookup.py       # 平行 PTR 反查（對 3 台 DNS Server）
├── static/
│   ├── index.html          # 主頁 Web UI（Bootstrap 5 + Vanilla JS）
│   └── login.html          # 登入頁面
└── requirements.txt
```

---

## API

| Endpoint | Method | 說明 |
|---|---|---|
| `GET /` | GET | Web UI 主頁（需登入） |
| `GET /login` | GET | 登入頁面 |
| `POST /login` | POST | 登入驗證 |
| `GET /logout` | GET | 登出 |
| `GET /api/analyze` | GET | 執行分析，回傳所有異常（結果快取 5 分鐘） |
| `GET /api/analyze?refresh=true` | GET | 強制重新分析（略過快取） |
| `GET /api/summary` | GET | 快速回傳目前快取的統計數字 |
| `GET /api/nac-macs` | GET | 取得目前 NAC MAC 清單 |
| `POST /api/nac-macs` | POST | 更新 NAC MAC 清單（自動清除分析快取） |

### `/api/analyze` 回應格式

```json
{
  "arp_total": 8898,
  "servers_ok": ["DHCP01P", "DHCP04P", "DHCP05P", "DHCP08P"],
  "servers_error": [],
  "anomaly_count": 4309,
  "cached": true,
  "cache_age": 42,
  "anomalies": [
    {
      "type": "A",
      "ip": "172.17.111.101",
      "arp_mac": "2c:62:5a:10:51:4f",
      "arp_source": "192.168.180.254",
      "arp_interface": "irb.3111",
      "lease_mac": "",
      "lease_state": "",
      "lease_hostname": "",
      "fixed_name": "",
      "fixed_mac": "",
      "dhcp_server": "",
      "description": "IP 落在 DHCP pool ...",
      "subnet_managed": true,
      "dns_name": "host01.example.com",
      "nac_blocked": false
    }
  ]
}
```

---

## 依賴套件

| 套件 | 版本 | 用途 |
|---|---|---|
| fastapi | 0.115.5 | Web 框架 |
| uvicorn | 0.32.1 | ASGI Server |
| paramiko | 3.5.0 | SSH 連線讀取 DHCP Server 設定與租約 |
| mysql-connector-python | 9.1.0 | 查詢 LibreNMS MySQL ARP 資料 |
| dnspython | 2.7.0 | PTR 反查（指定 DNS Server） |
| python-multipart | 0.0.20 | 表單登入解析 |
| itsdangerous | 2.2.0 | Session 簽名 |

---

## 注意事項

- 分析結果快取 5 分鐘，避免頻繁 SSH 與 MySQL 查詢。可按「強制重新分析」即時更新。
- LibreNMS 每 5 分鐘更新一次 ARP 資料，因此分析結果最多落後 5 分鐘。
- Type B（MAC 衝突）代表目前可能正在發生 IP 衝突，應優先處理。
- Type A（佔用 Pool）在下次 DHCP 配發時才會實際衝突，但仍應儘早登錄至 `dhcpd.conf`。
- NAC 封鎖的 IP 更新 NAC MAC 設定後，須重新分析才會重新分類。
- Session 有效期為 8 小時，逾時需重新登入。
