"""
noteapi 真实可达性验证 —— 修正 IP 后重测

背景（此前结论被推翻）：
  之前把 noteapi.micloud.xiaomi.net 解析到了 220.181.52.214，
  并据此写下「公网不可达」。但干净 DNS 解析显示：
      noteapi.micloud.xiaomi.net  → 161.117.96.24   (阿里云香港段)
      galleryapi/api.micloud/statusapi/relocationapi → 220.181.52.214
  也就是说 .214 是「另一批服务的 IP」，noteapi 根本不在那台机器上。
  恒定的 401 Basic 是打错 IP 打出来的假结论。

本脚本做三件事（全部只读 GET，无任何写操作）：
  1. 直接连 161.117.96.24 + 正确 SNI，验证 TLS 证书
  2. 裸请求（无 Cookie）看状态码
  3. 用 .runtime/notes_creds.json 里的真实凭据做 token×ssecurity 配对

用法:
  python probe_noteapi_real.py --tls            # 只验 TLS
  python probe_noteapi_real.py --bare           # 裸请求
  python probe_noteapi_real.py --pair           # 全配对（110 组合）
  python probe_noteapi_real.py --pair --quick   # 只试最长的 token
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
CREDS = os.path.join(HERE, ".runtime", "notes_creds.json")

HOST = "noteapi.micloud.xiaomi.net"
IP = "161.117.96.24"
PATH = "/mic/note/pc/v3.1/user/full"
UA = ("APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f "
      "Chrome/144.0.7559.111")
IV = b"0102030405060708"


# ══════════════════════════════════════════════════════════════════
# 密码学（与 notes_client.py 一致）
# ══════════════════════════════════════════════════════════════════
def _pad(b: bytes) -> bytes:
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
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = base64.b64decode(ssecurity)
    c = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    return base64.b64encode(
        c.update(_pad(plain.encode("utf-8"))) + c.finalize()).decode()


def dec_body(b64: str, ssecurity: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = base64.b64decode(ssecurity)
    raw = base64.b64decode(b64.strip())
    d = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    return _unpad(d.update(raw) + d.finalize()).decode("utf-8", "replace")


def sign(uri: str, method: str, params: Dict[str, Any], ssecurity: str) -> str:
    parts: List[str] = [uri.upper(), method]
    for k in sorted(params.keys()):
        if k == "_nonce":
            continue
        if params[k] is not None:
            parts.append(f"{k}={params[k]}")
    parts.append(ssecurity)
    return base64.b64encode(
        hashlib.sha1("&".join(parts).encode("utf-8")).digest()).decode()


def build_params(params: Dict[str, Any], ssecurity: str,
                 uri: str = PATH, method: str = "GET") -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in params.items():
        out[k] = v if k.startswith("_") else enc_param(str(v), ssecurity)
    out["signature"] = sign(uri, method, out, ssecurity)
    return out


# ══════════════════════════════════════════════════════════════════
# 裸 socket 请求（IP 钉住 + 正确 SNI）
# ══════════════════════════════════════════════════════════════════
def raw_get(path: str, query: str = "", cookie: Optional[str] = None,
            extra: Optional[Dict[str, str]] = None,
            ip: str = IP, host: str = HOST) -> Tuple[str, str]:
    """返回 (status_line, full_response_text)"""
    url = path + (("?" + query) if query else "")
    hdrs = [f"GET {url} HTTP/1.1", f"Host: {host}",
            f"User-Agent: {UA}",
            f"X-Request-Id: {uuid.uuid4()}",
            "X-XIAOMI-SUPPORT-REDIRECT: true",
            "Accept: */*",
            "Connection: close"]
    if cookie:
        hdrs.insert(3, f"Cookie: {cookie}")
    for k, v in (extra or {}).items():
        hdrs.append(f"{k}: {v}")
    req = ("\r\n".join(hdrs) + "\r\n\r\n").encode()

    ctx = ssl.create_default_context()
    s = socket.create_connection((ip, 443), timeout=15)
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
    return txt.split("\r\n", 1)[0], txt


def cmd_tls() -> int:
    print("=" * 74)
    print(f"TLS 验证 —— {HOST} @ {IP}")
    print("=" * 74)
    try:
        ctx = ssl.create_default_context()
        s = socket.create_connection((IP, 443), timeout=15)
        ss = ctx.wrap_socket(s, server_hostname=HOST)
        c = ss.getpeercert()
        sub = dict(x[0] for x in c["subject"])
        print(f"  协议      : {ss.version()}")
        print(f"  主题 CN   : {sub.get('commonName')}")
        print(f"  颁发者    : {dict(x[0] for x in c['issuer']).get('commonName')}")
        print(f"  SAN       : {[v for _, v in c.get('subjectAltName', [])]}")
        print(f"  有效期至  : {c.get('notAfter')}")
        ss.close()
        print("\n  ✓ 证书校验通过 —— 这是 noteapi 的合法节点")
    except Exception as e:
        print(f"  ✗ {type(e).__name__}: {e}")
        return 1
    return 0


def cmd_bare() -> int:
    print("=" * 74)
    print("裸请求（无 Cookie）")
    print("=" * 74)
    for p in ("/", "/mic", "/mic/note/pc/v3.1/user/full"):
        try:
            line, txt = raw_get(p)
            print(f"  {p:34s} → {line}")
        except Exception as e:
            print(f"  {p:34s} → ERR {type(e).__name__}: {e}")
    return 0


def cmd_pair(quick: bool) -> int:
    with open(CREDS, encoding="utf-8") as f:
        d = json.load(f)
    uid = (d.get("json_userId") or [""])[0]
    cid = (d.get("cUserId") or [""])[0]
    toks = sorted(set(d.get("cookie_serviceToken") or []), key=len, reverse=True)
    if quick:
        toks = toks[:1]
    ssecs = sorted(set(d.get("json_ssecurity") or []))

    print("=" * 74)
    print("凭据配对 —— 只读 GET /full")
    print("=" * 74)
    print(f"  userId={uid}  cUserId(len)={len(cid)}")
    print(f"  tokens={len(toks)}  ssecurity={len(ssecs)}  "
          f"组合={len(toks)*len(ssecs)}")
    print(f"  目标 {IP} ({HOST})\n")

    hits = 0
    for ti, tok in enumerate(toks):
        for si, s in enumerate(ssecs):
            try:
                qs = urllib.parse.urlencode(build_params({"syncTag": "", "limit": "1"}, s))
            except Exception as e:
                print(f"  加密失败 tok#{ti} ssec#{si}: {e}")
                continue
            cookie = f"userId={uid}; serviceToken={tok}; cUserId={cid}"
            try:
                line, txt = raw_get(PATH, qs, cookie)
            except Exception as e:
                print(f"  ERR tok#{ti}(len{len(tok)}) ssec#{si}: {type(e).__name__}")
                continue
            if " 200 " in line:
                hits += 1
                body = txt.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in txt else ""
                print(f"  ✓✓✓ tok#{ti}(len{len(tok)}) ssec#{si} → {line}")
                # 尝试解密响应
                dec = body
                try:
                    if body and not body.lstrip().startswith(("{", "@json:")):
                        dec = dec_body(body.strip(), s)
                except Exception:
                    pass
                print(f"       resp: {dec[:400]}")
            elif " 401 " not in line:
                print(f"  ~  tok#{ti}(len{len(tok)}) ssec#{si} → {line}")
        print(f"  ── tok#{ti}(len{len(tok)}) 试完 {len(ssecs)} 个 ssecurity，"
              f"累计命中 {hits}")

    print(f"\n  总命中: {hits}")
    if not hits:
        print("  ✗ 全 401 —— cookie 组合无效，或仍需额外认证头")
    return 0 if hits else 1


def main() -> int:
    a = sys.argv[1:]
    if "--tls" in a:
        return cmd_tls()
    if "--bare" in a:
        return cmd_bare()
    if "--pair" in a:
        return cmd_pair("--quick" in a)
    # 默认：tls + bare
    rc = cmd_tls()
    print()
    cmd_bare()
    return rc


if __name__ == "__main__":
    sys.exit(main())
