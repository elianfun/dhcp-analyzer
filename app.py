import time
import threading
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from analyzer import run_analysis, AnalysisResult

app = FastAPI(title="DHCP Analyzer")
app.mount("/static", StaticFiles(directory="static"), name="static")

# 快取：避免每次請求都重跑（預設 5 分鐘 TTL）
_cache: dict = {"result": None, "ts": 0}
_lock = threading.Lock()
CACHE_TTL = 300  # seconds


def _to_dict(result: AnalysisResult) -> dict:
    return {
        "arp_total": result.arp_total,
        "servers_ok": result.servers_ok,
        "servers_error": result.servers_error,
        "anomaly_count": len(result.anomalies),
        "anomalies": [
            {
                "type": a.type,
                "ip": a.ip,
                "arp_mac": a.arp_mac,
                "arp_source": a.arp_source,
                "arp_interface": a.arp_interface,
                "lease_mac": a.lease_mac,
                "lease_state": a.lease_state,
                "lease_hostname": a.lease_hostname,
                "fixed_name": a.fixed_name,
                "fixed_mac": a.fixed_mac,
                "dhcp_server": a.dhcp_server,
                "description": a.description,
                "subnet_managed": a.subnet_managed,
                "dns_name": a.dns_name,
            }
            for a in result.anomalies
        ],
    }


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.get("/api/analyze")
def analyze(refresh: bool = False):
    global _cache
    now = time.time()

    with _lock:
        if not refresh and _cache["result"] and (now - _cache["ts"]) < CACHE_TTL:
            data = _cache["result"]
            data["cached"] = True
            data["cache_age"] = int(now - _cache["ts"])
            return JSONResponse(data)

        try:
            result = run_analysis()
            data = _to_dict(result)
            data["cached"] = False
            data["cache_age"] = 0
            _cache["result"] = data
            _cache["ts"] = now
            return JSONResponse(data)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/summary")
def summary():
    """快速回傳目前快取的統計數字，不觸發重新分析。"""
    if _cache["result"]:
        r = _cache["result"]
        by_type = {}
        for a in r["anomalies"]:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        return {
            "anomaly_count": r["anomaly_count"],
            "by_type": by_type,
            "arp_total": r["arp_total"],
            "cache_age": int(time.time() - _cache["ts"]),
        }
    return {"anomaly_count": None, "message": "尚未執行分析"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=False)
