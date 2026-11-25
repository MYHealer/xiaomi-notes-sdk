"""
noteapi 完整认证链路 —— 严格复刻 PC 端 service-token-manager.ts

★ 本脚本修正了此前全部三处错误（均有 PC 端 JS 源码逐行依据）:

错误 1: uDevId 硬编码 "probe"
  官方 buildCookieHeader:
      deviceId = getDeviceId()                       // "pc_" + md5(machineId)
      uDevId   = base64(sha1(userId + deviceId))     ← 必须派生!
  → 这就是 serviceLogin 报 20014 的根因

错误 2: sid 用 "micloud"
  官方 businessService.ts:
      MICLAW="miclaw", MICLAW_ECOLOGY="miclaw_ecology",
      MICLOUD_DRIVE="micloud_drive", XIAOMI_HOME="xiaomi_home", XIAOMI_OAUTH="xiaomi_oauth"
  → noteapi 走的是 service = MICLOUD_DRIVE = "micloud_drive"

错误 3: ssecurity 与 token 散抓后随机配对
  官方 serviceTokens[sid] = { token, expiredAt, ssecurity, nonce, ... }
  → 二者必须来自【同一次】serviceLogin/Phase2 握手

官方流程（service-token-manager.ts）:
  Phase1 GET {account}/pass/serviceLogin?_locale=zh_CN&_snsNone=true&sid=<SID>&_json=true
         Cookie: passToken; userId; cUserId; deviceId; uDevId; uLocale; pass_ua
         → { code, location, ssecurity, nonce, cUserId }
  Phase2 GET {location}&clientSign=<urlenc(base64(sha1("nonce=<n>&<ssec>")))>
         (不带 cookie)
         → Set-Cookie: serviceToken 或 <sid>_serviceToken

用法:
  python noteapi_auth.py --deviceid      # 只算本机 deviceId（验证用）
  python noteapi_auth.py --dry-run       # 只做 Phase1（验证 20014 是否消失）
  python noteapi_auth.py                 # 完整换取 + 打 noteapi
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from ctypes import wintypes
from typing import Any, Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, ".runtime")

ACCOUNT_HOST = "https://account.xiaomi.com"
NOTE_HOST = "noteapi.micloud.xiaomi.net"
NOTE_IP = "220.181.52.214"

# ★ BUSINESS_SID_CONFIG (electron-main.js @406762) 的权威双键表:
#     BusinessService(应用层)      →  passport sid
#     miclaw                      →  miclaw
#     miclaw_ecology              →  miclaw-ecology      ← 下划线变连字符
#     micloud_drive               →  micloud             ← 去掉 _drive 后缀
#     xiaomi_home                 →  mijia
#     xiaomi_oauth                →  oauth2.0
#   q7(e){ let r = W_[e].sid; ... }  ← 唯一的 service→sid 转换点
#   ★ 不要把应用层枚举名直接当 sid 传 passport, 会得到 21315 无效的sid
SID = "micloud"

KEYRING_TARGET = "session.com.neoruaa.mix-api-bridge"
PC_UA = ("miNative PC/Normal(Apple Mac16,10) Darwin/25.6.0 SDKV/0.0.1 "
         "MK/TWFjLW1pbmkubGFu L/zh-CN DEVT/UEM= DEVS/TWFj BRA/QXBwbGU= "
         "APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f Chrome/144.0.7559.111"
         if False else
         "APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f Chrome/144.0.7559.111")

IV = b"0102030405060708"

# ★ 端点清单 —— 全部来自 notes-c2/c3 dex 字符串表 (非推测)
#   实测结论:
#     200 → user/full, user/guide/status, todo/v1/user/records
#     404 → user/folder, user/special/note        (网关级, 路径不完整)
ENDPOINTS: List[Tuple[str, Dict[str, Any]]] = [
    ("/mic/note/v3.1/user/full",          {"limit": "1"}),
    ("/mic/note/pc/v3.1/user/full",       {"limit": "1"}),
    ("/mic/note/v3.1/user/guide/status",  {}),
    ("/mic/note/v3.1/user/folder",        {}),
    ("/mic/note/v3.1/user/special/note",  {}),
    ("/mic/note/v3.1/user/note",          {"limit": "1"}),
    ("/mic/todo/v1/user/records",         {}),
]


# ══════════════════════════════════════════════════════════════════
# deviceId —— 复刻 getDeviceId() / HKt() / WKt()
# ══════════════════════════════════════════════════════════════════
def machine_id() -> str:
    """WKt(): win32 取 BIOS 序列号"""
    cmds = [
        ["wmic", "bios", "get", "serialnumber"],
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"],
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "(Get-WmiObject -Class Win32_BIOS).SerialNumber"],
    ]
    for c in cmds:
        try:
            out = subprocess.run(c, capture_output=True, text=True,
                                 errors="replace", timeout=20).stdout
            for ln in out.splitlines():
                ln = ln.strip()
                if ln and not re.match(r"^serialnumber$", ln, re.I):
                    return ln
        except Exception:
            continue
    return ""


def get_device_id() -> str:
    """rDe(): "pc_" + (SN 14位且第5位是'/' ? SN[:5]+md5(SN) : md5(SN))"""
    mid = machine_id()
    if not mid or len(mid) < 4:
        raise RuntimeError(f"machine id unavailable: {mid!r}")
    h = hashlib.md5(mid.encode("utf-8")).hexdigest()
    if len(mid) == 14 and mid[5] == "/":
        return "pc_" + mid[:5] + h
    return "pc_" + h


def derive_udevid(user_id: str, device_id: str) -> str:
    """buildCookieHeader: base64(sha1(userId + deviceId))"""
    return base64.b64encode(
        hashlib.sha1(f"{user_id}{device_id}".encode()).digest()).decode()


# ══════════════════════════════════════════════════════════════════
# keyring 会话
# ══════════════════════════════════════════════════════════════════
class CREDENTIAL(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR)]


def read_session() -> Dict[str, str]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    PCRED = ctypes.POINTER(CREDENTIAL)
    advapi32.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                   wintypes.DWORD, ctypes.POINTER(PCRED)]
    advapi32.CredReadW.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    p = PCRED()
    if not advapi32.CredReadW(KEYRING_TARGET, 1, 0, ctypes.byref(p)):
        raise RuntimeError(f"CredRead 失败 err={ctypes.get_last_error()}")
    c = p.contents
    blob = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize)
    advapi32.CredFree(p)
    n = len(blob) - (len(blob) % 2)
    txt = blob[:n].decode("utf-16-le", errors="replace")
    if txt.endswith("\x00"):
        txt = txt[:-1]
    return json.loads(txt)


def http_get(url: str, cookie: Optional[str] = None,
             ua: str = PC_UA) -> Tuple[int, str, Any]:
    hdrs = {"User-Agent": ua, "Accept": "*/*"}
    if cookie:
        hdrs["Cookie"] = cookie
    req = urllib.request.Request(url, headers=hdrs, method="GET")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    op = urllib.request.build_opener(NoRedirect)
    try:
        with op.open(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except Exception as e:
        return 0, f"<{type(e).__name__}: {e}>", {}


def strip_prefix(s: str) -> str:
    return s.split("&&&START&&&", 1)[-1] if "&&&START&&&" in s else s


def get_setcookies(headers) -> Dict[str, str]:
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


# ══════════════════════════════════════════════════════════════════
# 官方流程
# ══════════════════════════════════════════════════════════════════
def phase1(sess: Dict[str, str], sid: str,
           device_id: str) -> Optional[dict]:
    """service-token-manager.ts phase1CallPassServiceLogin"""
    uid = sess.get("user_id", "")
    cid = sess.get("c_user_id", "")
    pt = sess.get("pass_token", "")

    # ★ 官方 buildCookieHeader 的精确顺序
    parts = []
    if pt:
        parts.append(f"passToken={pt}")
    if uid:
        parts.append(f"userId={uid}")
    if cid:
        parts.append(f"cUserId={cid}")
    parts.append(f"deviceId={device_id}")
    parts.append(f"uDevId={derive_udevid(uid, device_id)}")
    parts.append("uLocale=zh_CN")
    parts.append("pass_ua=pc")
    cookie = "; ".join(parts)

    url = (f"{ACCOUNT_HOST}/pass/serviceLogin"
           f"?_locale=zh_CN&_snsNone=true&sid={sid}&_json=true")
    print(f"  GET {url}")
    print(f"  Cookie: passToken=…; userId={uid}; cUserId=…; "
          f"deviceId={device_id}; uDevId=…; uLocale; pass_ua")

    st, body, hdrs = http_get(url, cookie=cookie)
    print(f"  => HTTP {st}")
    if st != 200:
        print(f"  ✗ body: {body[:300]}")
        return None

    sc = get_setcookies(hdrs)
    cid2 = sc.get("cUserId", cid)

    raw = strip_prefix(body)
    m = re.search(r'"nonce"\s*:\s*(\d+)', raw)
    nonce_raw = m.group(1) if m else ""
    try:
        j = json.loads(raw)
    except Exception as e:
        print(f"  ✗ JSON 解析失败: {e}\n     {raw[:300]!r}")
        return None
    if nonce_raw:
        j["nonce"] = nonce_raw         # ◆ 防 float 丢精度

    code = j.get("code", -1)
    print(f"  code={code} description={j.get('description','')!r}")
    if code != 0:
        print(f"  ✗ 失败 (code={code})")
        return None

    loc = j.get("location", "")
    ssec = j.get("ssecurity", "")
    nonce = str(j.get("nonce", ""))
    print(f"  ✓ location len={len(loc)}")
    print(f"  ✓ ssecurity len={len(ssec)}")
    print(f"  ✓ nonce len={len(nonce)}")
    print(f"  ✓ cUserId = {cid2}")
    return {"loc": loc, "ssecurity": ssec, "nonce": nonce, "cUserId": cid2}


def phase2(p1: dict, sid: str) -> Optional[dict]:
    """phase2CallRedirectUrl"""
    ssec = p1["ssecurity"].strip()
    raw = f"nonce={p1['nonce']}" + (f"&{ssec}" if ssec else "")
    cs = base64.b64encode(hashlib.sha1(raw.encode()).digest()).decode()
    url = p1["loc"] + ("&" if "?" in p1["loc"] else "?") + \
        "clientSign=" + urllib.parse.quote(cs, safe="")
    print(f"  GET {url[:120]}…")
    st, body, hdrs = http_get(url, cookie=None)      # ★ 不带 cookie
    print(f"  => HTTP {st}")
    sc = get_setcookies(hdrs)
    print(f"  Set-Cookie keys: {list(sc.keys())}")
    tok = sc.get("serviceToken") or sc.get(f"{sid}_serviceToken")
    if not tok:
        print(f"  ✗ 无 serviceToken. body: {strip_prefix(body)[:250]!r}")
        return None
    print(f"  ✓ serviceToken len={len(tok)} head={tok[:6]!r}")
    return {"token": tok, "cookies": sc, "cUserId": sc.get("cUserId", p1["cUserId"])}


# ══════════════════════════════════════════════════════════════════
# noteapi 客户端（复用 notes_client_android 的精确实现）
# ══════════════════════════════════════════════════════════════════
def _aes(ssecurity: str, mode: int):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = base64.b64decode(ssecurity)
    assert len(key) == 16, f"aesKey invalid len={len(key)}"
    c = Cipher(algorithms.AES(key), modes.CBC(IV))
    return c.encryptor() if mode == 1 else c.decryptor()


def _pad(b: bytes) -> bytes:
    n = 16 - (len(b) % 16)
    return b + bytes([n]) * n


def _unpad(b: bytes) -> bytes:
    if not b:
        return b
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 and b[-n:] == bytes([n]) * n else b


def sign(method: str, path: str, params: Dict[str, Any], ssec: str) -> str:
    """pn.b.n —— [METHOD.upper(), Uri.getEncodedPath(), k=v 字典序, ssecurity]"""
    parts = [method.upper(), urllib.parse.urlparse(path).path]
    for k in sorted(params.keys()):
        parts.append(f"{k}={params[k]}")
    parts.append(ssec)
    return base64.b64encode(
        hashlib.sha1("&".join(parts).encode()).digest()).decode()


def call_note(path: str, params: Dict[str, Any], auth: dict) -> Tuple[str, str]:
    """用官方算法构造 GET 请求（IP 钉住 + 正确 SNI）"""
    ssec = auth["ssecurity"]
    p: Dict[str, Any] = {
        "_apkversion": "4.3.5",
        "_apkversioncode": "43005",
        "_backend": "false",
        "_delta": "0",
        "_count": "1",
    }
    for k, v in params.items():
        if k.startswith("_"):
            p[k] = v
        else:
            e = _aes(ssec, 1)
            ct = e.update(_pad(str(v).encode())) + e.finalize()
            p[k] = base64.b64encode(ct).decode()
    p["signature"] = sign("GET", path, p, ssec)

    qs = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                  for k, v in p.items())
    # ★ 官方 Cookie: 只有 serviceToken + cUserId
    ck = "; ".join(x for x in [
        f"serviceToken={auth['token']}" if auth.get("token") else "",
        f"cUserId={auth.get('cUserId','')}" if auth.get("cUserId") else "",
    ] if x)
    lines = [
        f"GET {path}?{qs} HTTP/1.1",
        f"Host: {NOTE_HOST}",
        f"Cookie: {ck}",
        "User-Agent: APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f Chrome/144.0.7559.111",
        "X-E2EE: 1.0.0",
        "X-E2EE-STATUS: 0",
        "apk-version: 4.3.5",
        "apk-version-code: 43005",
        "backend: false",
        "X-XIAOMI-SUPPORT-REDIRECT: true",
        "Accept: */*",
        "Connection: close",
    ]
    req = ("\r\n".join(lines) + "\r\n\r\n").encode()
    ctx = ssl.create_default_context()
    s = socket.create_connection((NOTE_IP, 443), timeout=20)
    ss = ctx.wrap_socket(s, server_hostname=NOTE_HOST)
    ss.sendall(req)
    buf = b""
    while True:
        d = ss.recv(65536)
        if not d:
            break
        buf += d
    ss.close()
    txt = buf.decode("utf-8", "replace")
    head, _, payload = txt.partition("\r\n\r\n")
    return head.split("\r\n")[0], payload


def show(status: str, body: str, ssec: str) -> None:
    print(f"     → {status}")
    b = body.strip()
    if not b:
        print("        (空)")
        return
    # ★ E2EE 响应头: "ac\\r\\n" = AES+CBC 密文, "@json:" = 明文 JSON
    #   真实结构: ac\r\n<base64>\r\n0\r\n   (末尾 0 = chunked 终止块)
    #   此前 strip() 只去空白, 残留 \r 与 chunk 尾 → base64 必失败
    enc = False
    for pre in ("ac", "@json:"):
        if b.startswith(pre):
            b = b[len(pre):]
            enc = pre == "ac"
            break
    # 取第一个非空行 = 纯 base64 (同时丢掉前后 \r 与 chunk 终止的 0)
    lines = [ln.strip() for ln in b.splitlines() if ln.strip()]
    b = lines[0] if lines else ""
    if b.startswith("{") or b.startswith("["):
        enc = False
    if enc and b:
        try:
            d = _aes(ssec, 2)
            b = _unpad(d.update(base64.b64decode(b)) + d.finalize()).decode(
                "utf-8", "replace")
            print("        [AES 解密后]")
        except Exception as e:
            print(f"        [解密失败 {type(e).__name__}] {b[:200]}")
            return
    if b.startswith("@json:"):
        b = b[6:]
    try:
        print("        " + json.dumps(json.loads(b), ensure_ascii=False)[:700])
    except Exception:
        print("        " + b[:700])


def cmd_probe() -> int:
    """--probe: 复用 .runtime/noteapi_auth.json, 遍历 APK 提取的全端点清单"""
    p = os.path.join(RUNTIME, "noteapi_auth.json")
    auth = json.load(open(p, encoding="utf-8"))
    print("=" * 74)
    print(f"noteapi 端点探测 —— token len={len(auth['token'])}")
    print("=" * 74)
    for path, params in ENDPOINTS:
        print(f"\n  {path}   {params or ''}")
        try:
            st, body = call_note(path, params, auth)
            show(st, body, auth["ssecurity"])
        except Exception as e:
            print(f"     ERR {type(e).__name__}: {e}")
    return 0


def main() -> int:
    a = sys.argv[1:]
    do_did = "--deviceid" in a
    dry = "--dry-run" in a

    if "--probe" in a:
        return cmd_probe()

    print("=" * 74)
    print("noteapi 认证链路 —— 对齐 PC 端 service-token-manager.ts")
    print("=" * 74)

    did = get_device_id()
    print(f"  deviceId   = {did}")
    try:
        mid = machine_id()
        print(f"  machineId  = {mid}  (len={len(mid)})")
    except Exception:
        pass
    if do_did:
        return 0
    print(f"  sid        = {SID}")

    sess = read_session()
    uid = sess.get("user_id", "")
    print(f"  userId     = {uid}")
    print(f"  uDevId     = {derive_udevid(uid, did)}")
    print()

    print("── Phase 1 ─────────────────────────────────────")
    p1 = phase1(sess, SID, did)
    if not p1:
        print("\n  ✗ Phase1 失败")
        return 1
    if dry:
        print("\n  [--dry-run] Phase1 通过")
        return 0

    print("\n── Phase 2 ─────────────────────────────────────")
    p2 = phase2(p1, SID)
    if not p2:
        return 1

    auth = {"token": p2["token"], "ssecurity": p1["ssecurity"],
            "cUserId": p2["cUserId"], "userId": uid}

    print("\n── 打 noteapi ──────────────────────────────────")
    for path, params in ENDPOINTS:
        print(f"\n  {path}")
        try:
            st, body = call_note(path, params, auth)
            show(st, body, p1["ssecurity"])
        except Exception as e:
            print(f"     ERR {type(e).__name__}: {e}")

    # 保存可用配对
    os.makedirs(RUNTIME, exist_ok=True)
    out = os.path.join(RUNTIME, "noteapi_auth.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(auth, f, ensure_ascii=False, indent=2)
    print(f"\n  ✓ 凭据已存 → {out}  (⚠ 含活 token)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
