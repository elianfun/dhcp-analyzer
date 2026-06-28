import time
import threading
from fastapi import FastAPI, Request, Form, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from analyzer import run_analysis, AnalysisResult
from config import AUTH_USERNAME, SESSION_SECRET, verify_password

app = FastAPI(title="DHCP Analyzer")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=28800)  # 8 小時
app.mount("/static", StaticFiles(directory="static"), name="static")

# 快取（5 分鐘 TTL）
_cache: dict = {"result": None, "ts": 0}
_lock = threading.Lock()
CACHE_TTL = 300


# ---------- Auth ----------

def require_login(request: Request):
    if not request.session.get("user"):
        return None
    return request.session["user"]


@app.get("/login")
def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=302)
    return FileResponse("static/login.html")


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == AUTH_USERNAME and verify_password(password):
        request.session["user"] = username
        return RedirectResponse("/", status_code=302)
    return FileResponse("static/login.html", status_code=401,
                        headers={"X-Login-Error": "帳號或密碼錯誤"})


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ---------- Pages ----------

@app.get("/")
def index(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login", status_code=302)
    return FileResponse("static/index.html")


# ---------- API ----------

def _auth_api(request: Request):
    if not request.session.get("user"):
        raise __import__("fastapi").HTTPException(status_code=401, detail="Unauthorized")


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


@app.get("/api/analyze")
def analyze(request: Request, refresh: bool = False):
    _auth_api(request)
    global _cache
    now = time.time()

    with _lock:
        if not refresh and _cache["result"] and (now - _cache["ts"]) < CACHE_TTL:
            data = dict(_cache["result"])
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
def summary(request: Request):
    _auth_api(request)
    if _cache["result"]:
        r = _cache["result"]
        by_type: dict = {}
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
