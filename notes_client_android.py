"""
noteapi Android 原生客户端 —— 严格对齐 com.miui.notes 反编译实现

★ 与之前 notes_client.py 的关键差异（全部经源码逐行确认, 非推测）:

1. 签名串构造 (pn.b.n / mn.d.c)
   arrayList = [ METHOD.toUpperCase(),
                 Uri.parse(url).getEncodedPath(),        ← 只有【路径】!
                 sorted("k=v")... ,                      ← TreeMap 字典序, 含 _ 前缀字段
                 ssecurity ]
   signature = base64(SHA1, NO_WRAP)( '&'.join(arrayList) )
   ★★ 与 PC electron 版不同: 不排除 _nonce, 不跳过 null, 首项是 METHOD 不是 URL

2. Cookie (mn.e.b)
   "serviceToken=<tok>; cUserId=<cid>"      ← ★ 没有 userId!

3. 必需请求头
   X-E2EE: <VERSION_NAME>
   X-E2EE-STATUS: <g() 状态值>
   apk-version / apk-version-code
   backend: "true"/"false"   (距上次请求 <300s 则 false)

4. 参数 map (进请求体, POST urlencoded)
   明文(_前缀): _nonce, _apkversion, _apkversioncode, _backend, _delta, _count
   加密        : 其余字段 → AES-128-CBC(key=b64(ssecurity), IV="0102030405060708") → base64

5. AES (pn.b.G / ov.g.a) —— 与我的实现完全一致, 已验证
   Cipher.getInstance("AES/CBC/PKCS5Padding")
   IV = "0102030405060708".getBytes()
   key = Base64.decode(ssecurity, NO_WRAP)   (必须 16 字节)

用法:
  python notes_client_android.py --probe          # 端点探测（GET, 最小参数）
  python notes_client_android.py --full [N]       # 拉取 note 全量
  python notes_client_android.py --todo           # 拉取待办
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import sys
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, ".runtime")
CREDS = os.path.join(RUNTIME, "notes_creds.json")

HOST = "noteapi.micloud.xiaomi.net"
IP = "220.181.52.214"

# ★ 来自 APK: com.miui.notes 的版本信息
APK_VERSION = "4.3.5"          # 待用真实值覆盖
APK_VERSION_CODE = "43005"
E2EE_VERSION = "1.0.0"
E2EE_STATUS = "0"

IV = b"0102030405060708"
METHOD_NAMES = {1: "GET", 2: "POST", 3: "POST_JSON"}

UA = ("APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f "
      "Chrome/144.0.7559.111")


# ══════════════════════════════════════════════════════════════════
# AES —— 严格对齐 pn.b.G / ov.g.a
# ══════════════════════════════════════════════════════════════════
def _cipher(key_b64: str, mode: int):
    """mode: 1=encrypt, 2=decrypt. 对齐 pn.b.G(String, int)"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = base64.b64decode(key_b64)
    if len(key) != 16:
        raise ValueError(f"aesKey is invalid: len={len(key)} (官方要求 16)")
    c = Cipher(algorithms.AES(key), modes.CBC(IV))
    return c.encryptor() if mode == 1 else c.decryptor()


def _pad(b: bytes) -> bytes:
    """Java Cipher "AES/CBC/PKCS5Padding" 自动补齐; cryptography 需手工等价实现"""
    n = 16 - (len(b) % 16)
    return b + bytes([n]) * n


def _unpad(b: bytes) -> bytes:
    if not b:
        return b
    n = b[-1]
    if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return b


def enc_param(plain: str, ssecurity: str) -> str:
    """ov.g.a(str) —— 参数加密"""
    e = _cipher(ssecurity, 1)
    ct = e.update(_pad(plain.encode("utf-8"))) + e.finalize()
    return base64.b64encode(ct).decode()                  # NO_WRAP


def dec_body(b64: str, ssecurity: str) -> str:
    """ov.g.c(str) —— 响应解密"""
    d = _cipher(ssecurity, 2)
    raw = base64.b64decode(b64.strip())
    return _unpad(d.update(raw) + d.finalize()).decode("utf-8", "replace")


# ══════════════════════════════════════════════════════════════════
# ★ 签名 —— 严格对齐 pn.b.n(method, path, TreeMap, ssecurity)
# ══════════════════════════════════════════════════════════════════
def sign(method: str, url_path: str, params: Dict[str, Any],
         ssecurity: str) -> str:
    """pn.b.n —— 逐项对齐官方实现

    官方源码:
        arrayList = []
        if (str != null) arrayList.add(str.toUpperCase());              // METHOD
        if (str2 != null) arrayList.add(Uri.parse(str2).getEncodedPath());  // PATH
        for (entry : new TreeMap(map).entrySet())
            arrayList.add(String.format("%s=%s", key, value));           // k=v 字典序
        arrayList.add(ssecurity);
        signature = base64(SHA1('&'.join(arrayList)), NO_WRAP)
    """
    parts: List[str] = [method.upper()]
    # Uri.parse(url).getEncodedPath() —— 只有路径（不含 scheme/host/query）
    parts.append(urllib.parse.urlparse(url_path).path)
    for k in sorted(params.keys()):                 # TreeMap = 字典序
        parts.append(f"{k}={params[k]}")            # ★ null 也会变成 "null" 字符串
    parts.append(ssecurity)
    joined = "&".join(parts)
    return base64.b64encode(
        hashlib.sha1(joined.encode("utf-8")).digest()).decode()


# ══════════════════════════════════════════════════════════════════
# 请求构造 —— 对齐 mn.e.b
# ══════════════════════════════════════════════════════════════════
class Session:
    def __init__(self, token: str, cuserid: str, ssecurity: str,
                 userid: str = "", apk_ver: str = APK_VERSION,
                 apk_code: str = APK_VERSION_CODE):
        self.token = token
        self.cuserid = cuserid
        self.ssecurity = ssecurity
        self.userid = userid
        self.apk_ver = apk_ver
        self.apk_code = apk_code
        self._delta = 0
        self._count = 0

    @property
    def cookie(self) -> str:
        """mn.e.b: "serviceToken=<tok>; cUserId=<cid>"  ★ 无 userId"""
        parts = []
        if self.token:
            parts.append(f"serviceToken={self.token}")
        if self.cuserid:
            parts.append(f"cUserId={self.cuserid}")
        return "; ".join(parts)

    def headers(self) -> Dict[str, str]:
        """mn.e.b 的 map3 —— 请求头"""
        return {
            "X-E2EE": E2EE_VERSION,
            "X-E2EE-STATUS": E2EE_STATUS,
            "apk-version": self.apk_ver,
            "apk-version-code": self.apk_code,
            "backend": "false",           # 距上次 <300s
            "User-Agent": UA,
        }

    def build(self, path: str, method: int,
              params: Dict[str, Any]) -> Tuple[str, Dict[str, str], str]:
        """返回 (url_path_with_query, headers, form_body)"""
        self._count += 1
        # ── map4: 参数（下划线前缀明文, 其余加密）──
        p: Dict[str, Any] = {}
        p["_apkversion"] = self.apk_ver
        p["_apkversioncode"] = self.apk_code
        p["_backend"] = "false"
        p["_delta"] = str(self._delta)
        p["_count"] = str(self._count)
        if method != 1:                       # mn.e.b: GET 才传 strM(pn.b.m()), 否则 null
            p["_nonce"] = base64.b64encode(os.urandom(8)).decode()
        for k, v in params.items():
            if k.startswith("_"):
                p[k] = v
            else:
                p[k] = enc_param("" if v is None else str(v), self.ssecurity)

        # ── 签名必须基于【加密后】的参数 ──
        p["signature"] = sign(METHOD_NAMES[method], path, p, self.ssecurity)

        hdrs = self.headers()
        hdrs["Cookie"] = self.cookie
        if method == 1:
            # GET: 参数拼进 query（mn.d.a 用 URLEncoder.encode）
            qs = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                          for k, v in p.items())
            return f"{path}?{qs}", hdrs, ""
        # POST: urlencoded form body
        body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                        for k, v in p.items())
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        return path, hdrs, body


# ══════════════════════════════════════════════════════════════════
# 裸 socket 请求（IP 钉住, 正确 SNI）
# ══════════════════════════════════════════════════════════════════
def do_request(sess: Session, path: str, method: int = 1,
               params: Optional[Dict[str, Any]] = None,
               ip: str = IP, host: str = HOST) -> Tuple[str, str]:
    path_q, hdrs, body = sess.build(path, method, params or {})
    m = METHOD_NAMES[method]
    lines = [f"{m} {path_q} HTTP/1.1", f"Host: {host}"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("X-Request-Id: " + str(uuid.uuid4()))
    lines.append("X-XIAOMI-SUPPORT-REDIRECT: true")
    lines.append("Accept: */*")
    lines.append("Connection: close")
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    req = ("\r\n".join(lines) + "\r\n\r\n" + body).encode()

    ctx = ssl.create_default_context()
    s = socket.create_connection((ip, 443), timeout=20)
    ss = ctx.wrap_socket(s, server_hostname=host)
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


def load_sessions() -> List[Session]:
    with open(CREDS, encoding="utf-8") as f:
        d = json.load(f)
    uid = (d.get("json_userId") or [""])[0]
    cid = (d.get("cUserId") or [""])[0]
    toks = sorted(set(d.get("cookie_serviceToken") or []), key=len, reverse=True)
    ssecs = sorted(set(d.get("json_ssecurity") or []))
    # ★ 配对: token[i] ↔ ssecurity[i]（按长度降序的 token 与 ssecurity 顺序对齐）
    out = []
    for i, t in enumerate(toks):
        out.append(Session(t, cid, ssecs[i % len(ssecs)] if ssecs else "", uid))
    return out


# ══════════════════════════════════════════════════════════════════
# 命令
# ══════════════════════════════════════════════════════════════════
def pretty(status: str, body: str, sess: Session) -> None:
    print(f"  → {status}")
    if not body.strip():
        print("     (空)")
        return
    b = body.strip()
    if not b.startswith(("{", "@json:")):
        try:
            b = dec_body(b, sess.ssecurity)
            print("     [解密后]")
        except Exception:
            print(f"     [非 JSON, {len(b)}B 原始] {b[:300]}")
            return
    if b.startswith("@json:"):
        b = b[6:]
    try:
        print("     " + json.dumps(json.loads(b), ensure_ascii=False)[:600])
    except Exception:
        print("     " + b[:600])


def cmd_probe() -> int:
    sessions = load_sessions()
    if not sessions:
        print("✗ 无凭据")
        return 1
    # ★ 先只试最长 token
    s = sessions[0]
    print("=" * 74)
    print(f"端点探测 —— token(len={len(s.token)}) cUserId(len={len(s.cuserid)})")
    print(f"  Cookie: {s.cookie[:40]}...{s.cookie[-20:]}")
    print("=" * 74)

    paths = [
        ("/mic/note/pc/v3.1/user/full", 1),
        ("/mic/note/v3.1/user/full", 1),
        ("/mic/note/v3.1/user/guide/status", 1),
        ("/mic/todo/v1/user/records", 1),
    ]
    for path, m in paths:
        try:
            st, body = do_request(s, path, m, {"limit": "1"} if "full" in path else {})
            print(f"\n  {path}")
            pretty(st, body, s)
        except Exception as e:
            print(f"\n  {path}\n  → ERR {type(e).__name__}: {e}")
    return 0


def cmd_tokens() -> int:
    """逐个 token × ssecurity 试, 打印非 401 的"""
    sessions = load_sessions()
    path = "/mic/note/v3.1/user/full"
    print("=" * 74)
    print(f"凭据扫描 —— {len(sessions)} 个 token")
    print("=" * 74)
    for i, s in enumerate(sessions):
        try:
            st, body = do_request(s, path, 1, {"limit": "1"})
        except Exception as e:
            print(f"  #{i} len={len(s.token):4d} ERR {type(e).__name__}")
            continue
        mark = "  ← ★" if "401" not in st else ""
        print(f"  #{i} len={len(s.token):4d} ssec={s.ssecurity[:8]}… → {st}{mark}")
        if "401" not in st:
            pretty(st, body, s)
    return 0


def main() -> int:
    a = sys.argv[1:]
    if "--tokens" in a:
        return cmd_tokens()
    if "--full" in a:
        return cmd_probe()
    return cmd_probe()


if __name__ == "__main__":
    sys.exit(main())
