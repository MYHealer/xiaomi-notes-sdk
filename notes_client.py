r"""
小米笔记 PC 侧客户端 —— 按 electron-main.js 逆向出的规范实现

规范来源（全部来自反编译验证, 非猜测）:
  packages/infra/src/network/xiaomiApiCrypto.ts
    IV  = b"0102030405060708"                       (硬编码常量)
    key = base64decode(ssecurity)  → 16B → AES-128-CBC
    参数加密: 不以 "_" 开头的字段用 d7e(v, ssecurity) 加密
    签名 p7e(uri, method, params, ssecurity):
        n = [uri.upper(), method]
        for k in sorted(params.keys()): if k!="_nonce" and params[k]!=null: n.push(f"{k}={v}")
        n.push(ssecurity)
        signature = base64(sha1("&".join(n)))
  packages/infra/src/network/encryptedServiceFetch.ts
    响应体若是 base64 → 用 ssecurity AES-128-CBC 解密; 解不开则当明文
    响应体可能带 "@json:" 前缀 → 剥掉
    308 重定向: 响应 JSON 里的 redirectUrl, 最多跟 _E 跳
  pixel 头:
    X-Request-Id: <uuid4>                (每请求注入)
    X-XIAOMI-SUPPORT-REDIRECT: true      (启用 308 业务重定向)
  cookie: userId / serviceToken / cUserId

★ 本脚本的第一目标不是"拿到笔记", 而是【定位凭据配对】:
  10 个 token × 11 个 ssecurity, 需要找出哪个组合是活的。
  逐个试是唯一可靠办法 —— 不做任何"看起来合理"的假设。

用法:
  python notes_client.py --pair            # 配对搜索（只读 /full, 不写）
  python notes_client.py --list [N]        # 用已配对凭据拉取笔记列表
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, ".runtime")
CREDS = os.path.join(RUNTIME, "notes_creds.json")
PAIR_OUT = os.path.join(RUNTIME, "notes_pair.json")

NOTE_HOST = "https://noteapi.micloud.xiaomi.net"
NOTE_BASE = "/mic/note/pc/v3.1/user"
UA = ("APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f "
      "Chrome/144.0.7559.111")

# ★ 硬编码 IV —— xiaomiApiCrypto.ts: bY = Buffer.from("0102030405060708","utf-8")
IV = b"0102030405060708"

MAX_REDIRECTS = 5


# ══════════════════════════════════════════════════════════════════
# 密码学原语
# ══════════════════════════════════════════════════════════════════
def _aes():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher, algorithms, modes


def aes_key_from_ssecurity(ssecurity: str) -> bytes:
    """ssecurity 是 base64; 解码后必须是 16 或 32 字节 (c7e 的断言)."""
    k = base64.b64decode(ssecurity)
    if len(k) not in (16, 32):
        raise ValueError(f"Invalid AES key length: {len(k)}, expected 16 or 32 bytes")
    return k


def _pad(b: bytes) -> bytes:
    """PKCS#7 —— Node createCipheriv 默认 autoPadding=true, 须手工等价实现"""
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
    """d7e(e, t): AES-CBC(key=iv=base64decode(ssecurity)) → base64"""
    Cipher, algorithms, modes = _aes()
    key = aes_key_from_ssecurity(ssecurity)
    c = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()   # ★ key 与 IV 同源
    ct = c.update(_pad(plain.encode("utf-8"))) + c.finalize()
    return base64.b64encode(ct).decode()


def dec_body(cipher_b64: str, ssecurity: str) -> str:
    """h7e(e, t): base64 → AES-CBC 解密 → utf8"""
    Cipher, algorithms, modes = _aes()
    key = aes_key_from_ssecurity(ssecurity)
    raw = base64.b64decode(cipher_b64.strip())
    d = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    return _unpad(d.update(raw) + d.finalize()).decode("utf-8", "replace")


def sign(uri: str, method: str, params: Dict[str, Any], ssecurity: str) -> str:
    """p7e(uri, method, params, ssecurity) —— 逐字节复刻"""
    parts: List[str] = [uri.upper(), method]
    for k in sorted(params.keys()):
        if k == "_nonce":
            continue
        v = params[k]
        if v is not None:
            parts.append(f"{k}={v}")
    parts.append(ssecurity)
    return base64.b64encode(
        hashlib.sha1("&".join(parts).encode("utf-8")).digest()).decode()


def build_params(params: Dict[str, Any], ssecurity: str,
                 uri: str, method: str) -> Dict[str, str]:
    """kY(e,t,r,i): 非 _ 前缀字段加密, 然后补 signature"""
    out: Dict[str, str] = {}
    for k, v in params.items():
        out[k] = v if k.startswith("_") else enc_param(str(v), ssecurity)
    out["signature"] = sign(uri, method, out, ssecurity)
    return out


# ══════════════════════════════════════════════════════════════════
# 请求
# ══════════════════════════════════════════════════════════════════
_CTX = ssl.create_default_context()


def request(path: str, method: str, params: Dict[str, Any],
            cookie: str, ssecurity: Optional[str] = None,
            retries: int = MAX_REDIRECTS) -> Tuple[int, str, str]:
    """返回 (status, body, final_url)"""
    url = NOTE_HOST + path
    for hop in range(retries + 1):
        if ssecurity:
            body_params = build_params(params, ssecurity, path, method)
        else:
            body_params = dict(params)
        data = urllib.parse.urlencode(body_params).encode()

        if method.upper() == "GET":
            req = urllib.request.Request(url + "?" + data.decode())
        else:
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Cookie", cookie)
        req.add_header("User-Agent", UA)
        req.add_header("X-Request-Id", str(uuid.uuid4()))
        req.add_header("X-XIAOMI-SUPPORT-REDIRECT", "true")   # ★ 必需
        try:
            with urllib.request.urlopen(req, timeout=25, context=_CTX) as r:
                raw = r.read().decode("utf-8", "replace")
                status, fin = r.status, r.url
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            status, fin = e.code, url
        except Exception as e:
            return 0, f"{type(e).__name__}: {e}", url

        # 响应解密（encryptedServiceFetch 的逻辑）
        body = raw
        if ssecurity and raw and not raw.lstrip().startswith(("{", "@json:")):
            try:
                body = dec_body(raw, ssecurity)
            except Exception:
                body = raw
        if body.startswith("@json:"):
            body = body[6:]

        # 308 业务重定向
        if status == 200:
            try:
                j = json.loads(body)
            except Exception:
                return status, body, fin
            rh = (j.get("data") or {}).get("redirectHost") or j.get("redirectHost")
            if rh:
                new = rh if rh.startswith("http") else "https://" + rh
                url = new + path
                continue
            return status, body, fin
        return status, body, fin
    return status, body, url


def cookie_for(uid: str, tok: str, cid: str) -> str:
    parts = [f"userId={uid}", f"serviceToken={tok}"]
    if cid:
        parts.append(f"cUserId={cid}")
    return "; ".join(parts)


# ══════════════════════════════════════════════════════════════════
# 配对搜索
# ══════════════════════════════════════════════════════════════════
def load_creds() -> Dict[str, List[str]]:
    with open(CREDS, encoding="utf-8") as f:
        return json.load(f)


def cmd_pair() -> int:
    d = load_creds()
    toks = sorted(set(d.get("cookie_serviceToken") or []), key=len, reverse=True)
    ssecs = sorted(set(d.get("json_ssecurity") or []))
    uid = (d.get("json_userId") or [""])[0]
    cid = (d.get("cUserId") or [""])[0]
    print("=" * 74)
    print("凭据配对搜索 —— 只读 GET /full, 不产生任何写操作")
    print("=" * 74)
    print(f"  userId={uid}  tokens={len(toks)}  ssecurity={len(ssecs)}  "
          f"cUserId len={len(cid)}")
    print(f"  组合数 = {len(toks)} × {len(ssecs)} = {len(toks)*len(ssecs)}\n")

    path = NOTE_BASE + "/full"
    ok: List[dict] = []
    tried = 0
    for ti, tok in enumerate(toks):
        for si, ssec in enumerate(ssecs):
            tried += 1
            st, body, fin = request(path, "GET",
                                    {"syncTag": "", "limit": "1"},
                                    cookie_for(uid, tok, cid), ssec)
            tag = f"tok#{ti}(len{len(tok)}) ssec#{si}"
            if st == 200:
                print(f"  ✓✓ [{tag}] HTTP 200  ← 配对成功!")
                print(f"      {body[:300]}")
                ok.append({"token": tok, "ssecurity": ssec,
                           "cUserId": cid, "userId": uid, "sample": body[:2000]})
            elif st != 401:
                print(f"  ~  [{tag}] HTTP {st} :: {body[:180]}")
        print(f"  token#{ti} 试完 {len(ssecs)} 个 ssecurity, "
              f"累计 {tried} 次, 命中 {len(ok)}")

    if ok:
        os.makedirs(RUNTIME, exist_ok=True)
        with open(PAIR_OUT, "w", encoding="utf-8") as f:
            json.dump(ok, f, ensure_ascii=False, indent=2)
        print(f"\n  ✓ {len(ok)} 组可用凭据 → {PAIR_OUT}")
    else:
        print("\n  ✗ 全部 401。token 与内存中 ssecurity 不构成有效组合。")
        print("    下一步: 需按 service 刷新 token（NetworkAuthProvider 路径）,")
        print("    或从 passport 重新换 micloud sid 的 token。")
    return 0 if ok else 1


def cmd_list(n: int) -> int:
    if not os.path.exists(PAIR_OUT):
        print("  ✗ 先跑 --pair 得到可用凭据")
        return 1
    with open(PAIR_OUT, encoding="utf-8") as f:
        pairs = json.load(f)
    p = pairs[0]
    ck = cookie_for(p["userId"], p["token"], p.get("cUserId", ""))
    st, body, fin = request(NOTE_BASE + "/full", "GET",
                            {"syncTag": "", "limit": str(n)}, ck, p["ssecurity"])
    print(f"HTTP {st}")
    try:
        j = json.loads(body)
        entries = (j.get("data") or {}).get("entries") or j.get("entries") or []
        print(f"取到 {len(entries)} 篇")
        for e in entries[:20]:
            print(f"  syncId={e.get('id')} tag={e.get('tag')} "
                  f"status={e.get('status')} subject={e.get('subject')!r}")
            c = e.get("content")
            if isinstance(c, str) and c:
                print(f"      content[{len(c)}] {c[:70]!r}")
        print(f"\n  原始 JSON 前 600 字:\n{body[:600]}")
    except Exception as ex:
        print(f"  解析失败: {ex}\n{body[:600]}")
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        sys.exit(0)
    if argv[0] == "--pair":
        sys.exit(cmd_pair())
    if argv[0] == "--list":
        sys.exit(cmd_list(int(argv[1]) if len(argv) > 1 else 20))
    print(__doc__)
