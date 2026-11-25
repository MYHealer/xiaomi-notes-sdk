"""
mi_auth.py - 小米账号登录 + 自动续登工具

功能:
  1. QR 码扫码登录（不依赖 HyperConnect）
  2. 凭据持久化（passToken + ssecurity + userId + serviceToken）
  3. 自动续登（用 passToken 重新获取 serviceToken）

用法:
  python mi_auth.py              # 交互式 QR 扫码登录
  python mi_auth.py --refresh    # 强制用 passToken 续登
  python mi_auth.py --status     # 查看当前凭据状态
  python mi_auth.py --ensure     # 确保凭据有效（过期则自动续登）

供 noteapi_pc.py 调用:
  from mi_auth import get_credentials, refresh_token
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, ".runtime")
AUTH_FILE = os.path.join(RUNTIME, "mi_auth.json")
AUTH_COMPAT = os.path.join(RUNTIME, "noteapi_auth.json")  # backward compat

ACCOUNT_HOST = "https://account.xiaomi.com"
SID = "micloud"  # passport sid for notes/cloud drive

# serviceToken TTL. ~24h observed, refresh 4h early.
TOKEN_TTL = 20 * 3600

PC_UA = ("APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f "
         "Chrome/144.0.7559.111")


# ── credential I/O ──────────────────────────────────────────────
def load_auth() -> Dict[str, Any]:
    if os.path.exists(AUTH_FILE):
        return json.load(open(AUTH_FILE, encoding="utf-8"))
    if os.path.exists(AUTH_COMPAT):
        old = json.load(open(AUTH_COMPAT, encoding="utf-8"))
        return {
            "passToken": "", "ssecurity": old.get("ssecurity", ""),
            "userId": old.get("userId", ""), "cUserId": old.get("cUserId", ""),
            "serviceToken": old.get("token", ""), "deviceId": "",
            "loginAt": 0, "refreshAt": int(time.time()),  # assume fresh
        }
    return {}


def save_auth(data: Dict[str, Any]) -> None:
    os.makedirs(RUNTIME, exist_ok=True)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    # sync noteapi_auth.json for backward compat
    compat = {
        "token": data.get("serviceToken", ""),
        "ssecurity": data.get("ssecurity", ""),
        "cUserId": data.get("cUserId", ""),
        "userId": data.get("userId", ""),
    }
    with open(AUTH_COMPAT, "w", encoding="utf-8") as f:
        json.dump(compat, f, indent=2, ensure_ascii=False)


# ── HTTP helpers ─────────────────────────────────────────────────
def _http_get(url: str, cookie: Optional[str] = None,
              timeout: int = 30) -> Tuple[int, str, Any]:
    hdrs = {"User-Agent": PC_UA, "Accept": "*/*"}
    if cookie:
        hdrs["Cookie"] = cookie
    req = urllib.request.Request(url, headers=hdrs, method="GET")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    op = urllib.request.build_opener(NoRedirect)
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except Exception as e:
        return 0, f"<{type(e).__name__}: {e}>", {}


def _strip(s: str) -> str:
    return s.split("&&&START&&&", 1)[-1] if "&&&START&&&" in s else s


def _cookies(headers) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        raw = headers.get_all("Set-Cookie") or []
    except Exception:
        raw = []
    for item in raw:
        head = item.split(";")[0].strip()
        if "=" in head:
            k, v = head.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ── deviceId / uDevId ───────────────────────────────────────────
def _machine_id() -> str:
    import subprocess
    for cmd in [
        ["wmic", "bios", "get", "serialnumber"],
        ["powershell", "-NoProfile", "-Command",
         "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"],
    ]:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 errors="replace", timeout=20).stdout
            for ln in out.splitlines():
                ln = ln.strip()
                if ln and not re.match(r"^serialnumber$", ln, re.I):
                    return ln
        except Exception:
            continue
    return ""


def _get_device_id() -> str:
    mid = _machine_id()
    if not mid or len(mid) < 4:
        return "pc_probe"
    return "pc_" + hashlib.md5(mid.encode("utf-8")).hexdigest()


def _udevid(uid: str, devid: str) -> str:
    return base64.b64encode(
        hashlib.sha1(f"{uid}{devid}".encode()).digest()).decode()


# ── QR login ─────────────────────────────────────────────────────
def login_qr(sid: str = SID, timeout: int = 300) -> Optional[Dict[str, Any]]:
    params = {
        "_qrsize": "480",
        "qs": urllib.parse.quote(f"?sid={sid}&_json=true"),
        "callback": "",  # empty avoids "Callback连接不合法" error
        "_hasLogo": "false", "sid": sid, "serviceParam": "",
        "_locale": "zh_CN", "_dc": str(int(time.time() * 1000)),
    }
    url = f"{ACCOUNT_HOST}/longPolling/loginUrl?" + \
          "&".join(f"{k}={v}" for k, v in params.items())
    print("[login] getting login URL...")
    st, body, _ = _http_get(url, timeout=15)
    if st != 200:
        print(f"[login] FAIL: HTTP {st}")
        return None
    parsed = json.loads(_strip(body))
    login_url = parsed.get("loginUrl", "")
    lp_url = parsed.get("lp", "")
    if not login_url or not lp_url:
        print("[login] FAIL: no loginUrl/lp")
        return None

    print(f"\n[login] Open this link on phone, scan QR with Mi Home app:")
    print(f"  {login_url}\n")

    print(f"[login] Waiting for scan ({timeout}s timeout)...")
    st2, body2, hdrs2 = _http_get(lp_url, timeout=timeout)
    if st2 != 200:
        print(f"[login] FAIL: HTTP {st2}")
        return None

    data = json.loads(_strip(body2))
    pt = data.get("passToken", "")
    ssec = data.get("ssecurity", "")
    uid = str(data.get("userId", ""))
    loc = data.get("location", "")
    cid = data.get("cUserId", "")

    if not pt or not ssec or not uid:
        print("[login] FAIL: incomplete data")
        return None

    print(f"[login] OK passToken len={len(pt)} ssecurity={ssec}")

    # get serviceToken from location
    stok = ""
    if loc:
        st3, _, hdrs3 = _http_get(loc.replace("\\/", "/"), timeout=15)
        sc = _cookies(hdrs3)
        stok = sc.get("serviceToken", "")
        if not cid:
            cid = sc.get("cUserId", "")
    if not stok:
        stok = pt
    print(f"[login] OK serviceToken len={len(stok)}")

    devid = _get_device_id()
    auth = {
        "passToken": pt, "ssecurity": ssec, "userId": uid,
        "cUserId": cid, "serviceToken": stok, "deviceId": devid,
        "loginAt": int(time.time()), "refreshAt": int(time.time()),
    }
    save_auth(auth)
    print(f"[login] Saved to {AUTH_FILE}")
    return auth


# ── Phase1/Phase2 refresh ────────────────────────────────────────
def refresh_token(auth: Optional[Dict[str, Any]] = None,
                  sid: str = SID) -> Optional[Dict[str, Any]]:
    if auth is None:
        auth = load_auth()
    pt = auth.get("passToken", "")
    uid = auth.get("userId", "")
    cid = auth.get("cUserId", "")
    devid = auth.get("deviceId", "") or _get_device_id()

    if not pt:
        print("[refresh] FAIL: no passToken, need login")
        return None
    if not uid:
        print("[refresh] FAIL: no userId")
        return None

    # Phase1
    parts = []
    if pt:
        parts.append(f"passToken={pt}")
    if uid:
        parts.append(f"userId={uid}")
    if cid:
        parts.append(f"cUserId={cid}")
    parts.append(f"deviceId={devid}")
    parts.append(f"uDevId={_udevid(uid, devid)}")
    parts.append("uLocale=zh_CN")
    parts.append("pass_ua=pc")
    cookie = "; ".join(parts)

    url1 = (f"{ACCOUNT_HOST}/pass/serviceLogin"
            f"?_locale=zh_CN&_snsNone=true&sid={sid}&_json=true")
    print("[refresh] Phase1: serviceLogin...")
    st1, body1, hdrs1 = _http_get(url1, cookie=cookie, timeout=30)
    if st1 != 200:
        print(f"[refresh] FAIL: Phase1 HTTP {st1}")
        return None

    sc1 = _cookies(hdrs1)
    try:
        j1 = json.loads(_strip(body1))
    except Exception as e:
        print(f"[refresh] FAIL: Phase1 JSON: {e}")
        return None
    if j1.get("code", -1) != 0:
        print(f"[refresh] FAIL: Phase1 code={j1.get('code')}")
        return None

    loc = j1.get("location", "")
    ssec = j1.get("ssecurity", "")
    nonce = str(j1.get("nonce", ""))
    new_cid = sc1.get("cUserId", cid) or j1.get("cUserId", cid)
    print(f"[refresh] OK ssecurity={ssec}")

    # Phase2
    raw_sign = f"nonce={nonce}" + (f"&{ssec}" if ssec else "")
    cs = base64.b64encode(hashlib.sha1(raw_sign.encode()).digest()).decode()
    sep = "&" if "?" in loc else "?"
    url2 = f"{loc}{sep}clientSign={urllib.parse.quote(cs, safe='')}"
    print("[refresh] Phase2: get serviceToken...")
    st2, _, hdrs2 = _http_get(url2, cookie=None, timeout=30)
    if st2 != 200:
        print(f"[refresh] FAIL: Phase2 HTTP {st2}")
        return None

    sc2 = _cookies(hdrs2)
    new_tok = sc2.get("serviceToken") or sc2.get(f"{sid}_serviceToken")
    if not new_tok:
        print("[refresh] FAIL: no serviceToken in Phase2")
        return None

    print(f"[refresh] OK serviceToken len={len(new_tok)}")
    auth["serviceToken"] = new_tok
    auth["ssecurity"] = ssec
    auth["cUserId"] = new_cid
    auth["deviceId"] = devid
    auth["refreshAt"] = int(time.time())
    save_auth(auth)
    print("[refresh] Credentials saved")
    return auth


# ── auto-refresh ─────────────────────────────────────────────────
def is_token_valid(auth: Dict[str, Any]) -> bool:
    ra = auth.get("refreshAt", 0)
    return bool(ra) and (time.time() - ra) < TOKEN_TTL


def get_credentials() -> Optional[Dict[str, str]]:
    """Get valid credentials. Auto-refresh if expired. Returns dict or None."""
    auth = load_auth()
    if not auth.get("serviceToken"):
        print("[auth] no credentials, need login")
        return None
    if not is_token_valid(auth):
        print("[auth] token expired, refreshing...")
        auth = refresh_token(auth)
        if not auth:
            print("[auth] refresh failed, need login")
            return None
    return {
        "token": auth["serviceToken"], "ssecurity": auth["ssecurity"],
        "userId": auth["userId"], "cUserId": auth.get("cUserId", ""),
    }


def ensure_valid() -> bool:
    return get_credentials() is not None


# ── CLI ──────────────────────────────────────────────────────────
def _status():
    auth = load_auth()
    if not auth:
        print("No credentials. Run: python mi_auth.py")
        return
    for k in ("userId", "cUserId", "deviceId", "ssecurity"):
        print(f"{k:14s} {auth.get(k, '')}")
    st = auth.get("serviceToken", "")
    pt = auth.get("passToken", "")
    if st:
        print(f"{'serviceToken':14s} {st[:40]}... len={len(st)}")
    else:
        print("serviceToken   (empty)")
    if pt:
        print(f"{'passToken':14s} {pt[:40]}... len={len(pt)}")
    else:
        print("passToken      (empty)")
    for k in ("loginAt", "refreshAt"):
        ts = auth.get(k, 0)
        if ts:
            age = (time.time() - ts) / 3600
            print(f"{k:14s} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} ({age:.1f}h ago)")
    print(f"{'status':14s} {'valid' if is_token_valid(auth) else 'EXPIRED'}")


def main():
    a = sys.argv[1:]
    if "--status" in a:
        _status()
        return 0
    if "--refresh" in a:
        return 0 if refresh_token() else 1
    if "--ensure" in a:
        ok = ensure_valid()
        print(f"credentials {'valid' if ok else 'INVALID'}")
        return 0 if ok else 1
    return 0 if login_qr() else 1


if __name__ == "__main__":
    sys.exit(main())
