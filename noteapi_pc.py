"""
noteapi_pc.py —— 严格复刻 PC 端 NotesApi / TodoApi 的真实请求

★ 端点取自 electron-main.js (HyperConnect 2.0.1.452, app.asar/dist-electron/main.js)
   而非 APK —— 手机端与 PC 端路由不同!

  NotesApi (Dl = "/mic/note/pc/v3.1/user")
    GET  {Dl}/full                        params: syncTag, limit, syncExtraInfo?, filterTag?
    GET  {Dl}/full/{id}
    GET  {Dl}/full/deleted                params: limit, syncTag?
    GET  {Dl}/guide/status
    GET  /mic/note/v3/user/status         ← 注意: 无 pc 段, 版本 v3
    POST {Dl}/note                        params: entry(JSON), ckey
    POST {Dl}/note/{id}                   params: entry(JSON), ckey
    POST {Dl}/note/{id}/restore           params: ckey
    POST {Dl}/folder                      params: entry(JSON), ckey
    POST {Dl}/folder/{id}/restore         params: ckey

  TodoApi (O4 = "/mic/todo/pc/v1/user/records")
    GET  {O4}                             params: limit, syncToken?
    POST {O4}                             params: record(JSON)
    POST {O4}/{id}/update                 params: eTag, record(JSON)
    POST {O4}/{id}/delete                 params: eTag

  FileApi (https://fileapi.micloud.xiaomi.net)
    GET  /mic/file/v3/user/request_download   params: fileId, type="note_img"
    POST /mic/file/v3/user/request_upload     params: request(JSON), kss(JSON), encryptInfo?
    POST /mic/file/v3/user/commit             params: commit(JSON), encryptInfo?

★ 关键契约 (与手机端差异):
  1. 路径含 **pc** 客户端段, 版本号 pc 之后才出现
  2. note 的 listFull 必须传 **syncTag** (>0 增量, 0/空 全量) + **syncExtraInfo**(不透明游标, 原样回传)
  3. todo 的 sync 必须传 **syncToken**(不透明, 原样回传)
  4. 写操作带 **ckey = randomUUID()** 幂等键
  5. id/tag/folderId 是 **BigInt 雪花 ID**, 必须当**字符串**处理, 禁止 JSON number
  6. 请求方式: GET 参数走 query; 写操作走 **postForm**(application/x-www-form-urlencoded)

用法:
  # ── 认证 ──────────────────────────────────────────────────────
  python noteapi_pc.py --login          # 走完整认证, 存 .runtime/noteapi_auth.json

  # ── 读 ────────────────────────────────────────────────────────
  python noteapi_pc.py --notes          # 拉笔记全量 (翻页至 lastPage)
  python noteapi_pc.py --todos          # 拉待办
  python noteapi_pc.py --status         # 用户/引导状态
  python noteapi_pc.py --recycle        # ★回收站 (翻页 + expireInterval)
  python noteapi_pc.py --folders        # ★文件夹列表 (从 full 流筛 type=folder)
  python noteapi_pc.py --detail <id>    # ★单条详情 (完整 content)
  python noteapi_pc.py --attachment <fileId>  # ★附件下载地址 (fileapi 域)
  python noteapi_pc.py --domains        # 域名发现 (relocation)
  python noteapi_pc.py --all            # 全部
  python noteapi_pc.py --watch          # 轮询 5s, 打印云端新变化 (Ctrl-C 退出)

  # ── 写 ────────────────────────────────────────────────────────
  python noteapi_pc.py --send "标题" "正文"      # 发一条笔记 (手机上会同步到)
  python noteapi_pc.py --send "只有正文"         # 不带标题
  python noteapi_pc.py --send-todo "买牛奶"                      # 发待办
  python noteapi_pc.py --send-todo "买牛奶" --at "09:30"         # 今/明天 9:30 提醒
  python noteapi_pc.py --send-todo "喝水" --at "+2h" --repeat 每天
  python noteapi_pc.py --send-todo "例会" --at "2026-09-16 14:00" --repeat 每周
  python noteapi_pc.py --push           # 写 MARK 笔记+待办, 读回验证, 再更新

  # ── 常驻服务 ──────────────────────────────────────────────────
  python noteapi_pc.py --daemon         # 每 15s 同步一轮 + 每 4 轮自写一条 (自动清理)

--at 支持: "09:30" / "+30m" / "+2h" / "+3d" / "2026-09-16 14:00"
--repeat 支持: 不重复 / 每天 / 每周 / 工作日 / 每月 / 每年

★ 三条实测踩出来的契约 (详见 01-协议规格/07-笔记PC联调结论.md §3.4/3.5):
  1. 待办收发非对称 —— 发送时 entity 字段【扁平】放 contentJson 下;
     服务端回包是【嵌套】的 contentJson.entity。照抄源码 e9t() 会被拒。
  2. id 与 tag 会在 update 后【分叉】—— 删除必须传同步到的 tag。
     传错 tag 返回 code:0 但静默不删, 必须读回确认。
  3. 笔记 update 必须显式带 tag / createDate / status(数字0)。
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import random
import re
import sqlite3
import sys
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, ".runtime")
AUTH = os.path.join(RUNTIME, "noteapi_auth.json")
sys.path.insert(0, HERE)
import mi_auth as _mi_auth

# 本地水位来源 —— HyperConnect 自己的库
SQLITE = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "MI", "ContinuityApp", "miclaw.sqlite")

HOST = "noteapi.micloud.xiaomi.net"
# ★ 域名发现/账号域 —— relocation 在这里, 不在 noteapi 域 (实测 noteapi 回 404)
INTERCONNECT_HOST = "g.interconnectapi.micloud.xiaomi.net"
BASE = "/mic/note/pc/v3.1/user"
TODO = "/mic/todo/pc/v1/user/records"

IV = b"0102030405060708"


# ══════════════════════════════════════════════════════════════════
# 密码学 —— 复用已确认的 ov.g 实现
# ══════════════════════════════════════════════════════════════════
def _aes(ssec: str, mode: int):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = base64.b64decode(ssec)
    assert len(key) == 16, f"aesKey len={len(key)} != 16"
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


def enc(v: Any, ssec: str) -> str:
    e = _aes(ssec, 1)
    return base64.b64encode(
        e.update(_pad(str(v).encode("utf-8"))) + e.finalize()).decode()


def dec(b64: str, ssec: str) -> str:
    d = _aes(ssec, 2)
    return _unpad(d.update(base64.b64decode(b64)) + d.finalize()).decode(
        "utf-8", "replace")


def sign(method: str, path: str, params: Dict[str, Any], ssec: str) -> str:
    """pn.b.n —— [METHOD, encodedPath, "k=v" 字典序, ssecurity] join '&' → b64(SHA1)"""
    parts = [method.upper(), urllib.parse.urlparse(path).path]
    for k in sorted(params.keys()):
        parts.append(f"{k}={params[k]}")
    parts.append(ssec)
    return base64.b64encode(
        hashlib.sha1("&".join(parts).encode("utf-8")).digest()).decode()


# ══════════════════════════════════════════════════════════════════
# 传输 —— 裸 socket (IP 钉住 + 正确 SNI), 完全复刻 mn.e.b
# ══════════════════════════════════════════════════════════════════
def _send_raw(req: bytes, ip: str, host: str) -> Tuple[str, str]:
    import socket
    import ssl
    ctx = ssl.create_default_context()
    s = socket.create_connection((ip, 443), timeout=25)
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


def _deframe(body: str) -> str:
    """小米自定义分帧解码 —— 返回拼接后的完整 base64 串

    ★ 真实格式 (实测 363KB 响应):
        <hexlen>\\r\\n<data of exactly that many bytes>\\r\\n
        <hexlen>\\r\\n<data>\\r\\n
        ...
        <hexlen>\\r\\n<data>\\r\\n
      长度是【十六进制 ASCII】, 且精确等于其后 data 段的字节数。
      小响应只有一帧 (如 guide/status 的 "98" = 0x98 = 152B);
      大响应多帧 (如 full: 3f37→10000→4000→…)。
      ★ "98"/"80"/"ac" 不是模式标识, 就是十六进制长度 —— 曾被误读为 E2EE 前缀。

    实现: 逐行扫描, 若某行是纯十六进制且下一行长度吻合, 则消费两行。
    """
    out: List[str] = []
    lines = body.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        if not ln:
            i += 1
            continue
        # 末尾 chunked 终止符 "0"
        if ln == "0":
            i += 1
            continue
        # 尝试当作 hex 长度
        try:
            n = int(ln, 16)
        except ValueError:
            out.append(ln)
            i += 1
            continue
        # 下一行是否正好 n 字节
        if i + 1 < len(lines) and len(lines[i + 1]) == n:
            out.append(lines[i + 1].strip())
            i += 2
            continue
        # 长度不吻合: 该行就是数据(或最后一个残余)
        out.append(ln)
        i += 1
    return "".join(out)


def _parse_e2ee(body: str, ssec: str) -> dict:
    """分帧 → base64 → AES 解密 → JSON

    响应类型:
      "@json:" 开头  → 明文 JSON
      其余           → 自定义分帧的 base64 密文
    """
    b = body.lstrip()
    if b.startswith("@json:"):
        return _json_or_raw(b[6:])
    b64 = _deframe(b)
    if b64.startswith("{") or b64.startswith("["):
        return _json_or_raw(b64)
    if not b64:
        return {"_raw": ""}
    try:
        return _json_or_raw(dec(b64, ssec))
    except Exception as e:
        return {"_raw": f"<decrypt failed {type(e).__name__}: {e}> {b64[:200]}"}


def _json_or_raw(s: str) -> dict:
    try:
        return json.loads(s)
    except Exception:
        return {"_raw": s[:800]}


class Client:
    """复刻 electron ServicesClient 的 get / postForm"""

    def __init__(self, auth: dict, ip: str = "", host: str = HOST,
                 auth_file: str = ""):
        self.ssec = auth["ssecurity"]
        self.tok = auth["token"]
        self.cid = auth.get("cUserId", "")
        self.host = host
        self.ip = ip or _resolve(host)
        self._count = 0
        # ★ 凭据来源文件：401 续约成功后回写这里，让下次启动直接用新 token。
        #   空串 = 不回写（如临时构造的 client）。
        self.auth_file = auth_file
        # ★ 额外自定义请求头 (CloudKit 的 appId 走 header, 见 25 号规格 §2.1)
        self.extra_headers: Dict[str, str] = {}

    def _common(self) -> Dict[str, Any]:
        self._count += 1
        return {
            "_apkversion": "4.3.5",
            "_apkversioncode": "43005",
            "_backend": "false",
            "_delta": "0",
            "_count": str(self._count),
        }

    def _cookies(self) -> str:
        return "; ".join(x for x in [
            f"serviceToken={self.tok}" if self.tok else "",
            f"cUserId={self.cid}" if self.cid else "",
        ] if x)

    def _try_refresh(self) -> bool:
        """Try to refresh credentials via mi_auth. Returns True if refreshed.

        ★ refresh_token() 内部读 .runtime/mi_auth.json（那里有 passToken，
          是续约的燃料），成功后 save_auth() 回写同一文件。
          本 Client 的 auth 来源可能不同（如 galleryapi_pc.load_auth() 读的是
          noteapi_auth.json），故刷新后必须把新凭据同步回「我们的」来源文件，
          否则下次进程启动又拿旧 token。
        """
        print("  [401] attempting token refresh...")
        auth = _mi_auth.refresh_token()
        if not auth:
            print("  [401] refresh failed")
            return False
        self.tok = auth["serviceToken"]
        self.ssec = auth["ssecurity"]
        self.cid = auth.get("cUserId", self.cid)
        print(f"  [401] refreshed, new token len={len(self.tok)}")
        self._persist_auth()
        return True

    def _persist_auth(self) -> None:
        """把当前凭据写回 self.auth_file（若有）。失败只告警，不影响请求。"""
        if not self.auth_file:
            return
        try:
            cur: Dict[str, Any] = {}
            if os.path.exists(self.auth_file):
                with open(self.auth_file, encoding="utf-8") as f:
                    cur = json.load(f)
            cur["token"] = self.tok
            cur["serviceToken"] = self.tok
            cur["ssecurity"] = self.ssec
            cur["cUserId"] = self.cid
            with open(self.auth_file, "w", encoding="utf-8") as f:
                json.dump(cur, f, ensure_ascii=False, indent=2)
            print(f"  [401] credentials persisted -> {self.auth_file}")
        except Exception as e:
            print(f"  [401] persist failed: {e}")

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> dict:
        r = self._get_once(path, params)
        if self._is_401(r) and self._try_refresh():
            r = self._get_once(path, params)      # 用新 token 重签重发
        return r

    def _get_once(self, path: str, params: Optional[Dict[str, Any]]) -> dict:
        p = self._common()
        for k, v in (params or {}).items():
            if v is None or v == "":
                continue
            p[k] = v if k.startswith("_") else enc(v, self.ssec)
        p["signature"] = sign("GET", path, p, self.ssec)
        qs = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                      for k, v in p.items())
        lines = [f"GET {path}?{qs} HTTP/1.1"] + _hdr_base(self, path)
        st, body = _send_raw(("\r\n".join(lines) + "\r\n\r\n").encode(),
                             self.ip, self.host)
        return {"status": st, "data": _parse_e2ee(body, self.ssec)}

    def post_form(self, path: str, params: Dict[str, Any]) -> dict:
        r = self._post_once(path, params)
        if self._is_401(r) and self._try_refresh():
            r = self._post_once(path, params)
        return r

    def _post_once(self, path: str, params: Dict[str, Any]) -> dict:
        p = self._common()
        for k, v in params.items():
            if v is None:
                continue
            p[k] = v if k.startswith("_") else enc(v, self.ssec)
        p["signature"] = sign("POST", path, p, self.ssec)
        body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                        for k, v in p.items())
        lines = ["POST " + path + " HTTP/1.1"] + _hdr_base(self, path) + [
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body.encode())}",
        ]
        st, rb = _send_raw(
            ("\r\n".join(lines) + "\r\n\r\n" + body).encode(),
            self.ip, self.host)
        return {"status": st, "data": _parse_e2ee(rb, self.ssec)}

    @staticmethod
    def _is_401(r: dict) -> bool:
        """响应是否鉴权失败。log_in_album 等接口会把 401 放在 status 字符串里。"""
        st = str(r.get("status", ""))
        return "401" in st or "Unauthorized" in st


# ══════════════════════════════════════════════════════════════════
# 写侧 —— NotesApi / TodoApi 门面 (严格复刻 electron 实现)
# ══════════════════════════════════════════════════════════════════
_SNOWFLAKE_KEYS = ("id", "tag", "folderId")
_SYNCID_RE = re.compile(r"^[1-9]\d*$")


def bigint_check(entry: dict) -> dict:
    """复刻 Qj() —— 对 id/tag/folderId 做 BigInt 语义校验

    官方用 json-bigint({useNativeBigInt:true}) 序列化, BigInt 会输出为
    **不带引号的裸数字**。Python 侧我们用字符串保存值, 序列化时再裸拼,
    这样既保留了精度, 又不会走 float 路径丢低位 (见 4.1: id > 2^53)。

    ★ 校验规则 (与 Qj 一致):
        number  → 允许 (转字符串, 但调用方不应传, 会丢精度)
        string  → 必须匹配 /^-?\\d+$/, 否则 INVALID_PARAM
        其他    → INVALID_PARAM
    """
    out = dict(entry)
    for k in _SNOWFLAKE_KEYS:
        v = out.get(k)
        if v is None:
            continue
        if isinstance(v, int) and not isinstance(v, bool):
            out[k] = str(v)
            continue
        if isinstance(v, str):
            if not re.fullmatch(r"-?\d+", v):
                raise ValueError(
                    f"INVALID_PARAM: envelope.{k} 非十进制整数字符串: {v!r}")
            continue
        raise ValueError(
            f"INVALID_PARAM: envelope.{k} 不支持的类型 {type(v).__name__}")
    return out


def check_syncid(sid: Any, what: str = "syncId") -> str:
    """复刻 nS() —— syncId 必须是正整数 Long 字符串"""
    s = str(sid) if not isinstance(sid, str) else sid
    if not _SYNCID_RE.match(s):
        raise ValueError(
            f"INVALID_PARAM: {what} must be a positive Long string, got {sid!r}")
    return s


def note_envelope(subject: str, content: str, folder_id: str = "0",
                  note_type: str = "mdNote", alert_date: int = 0,
                  color_id: int = 0, relation_type: str = "",
                  modify_date: Optional[int] = None) -> dict:
    """组装 createNote 的 entry —— 复刻 electron 的 CSe() + STi()

    官方 createNote 的实际入参是 noteService 组装出来的:
        {...CSe(row), content, snippet, folderId, createDate, setting, extraInfo}
    其中 CSe 提供 type/subject/modifyDate/alertDate/relationType/colorId。
    ★ 曾经的 10008 "type is unset" 就是因为漏了 CSe 的 type 字段
      (type 取 noteType 的值: "mdNote"/"mindMap"/"handNote"/"note")。
    ★ folderId 来自 DB 的 folderSyncId (无文件夹时是字符串 "0")。
    ★ extraInfo 必须是 JSON 字符串 (SSe(): {title:subject, clientUuid:uuid})
    ★ setting 必须是对象 (tq(): {stickyTime, data?, totalSize})
    """
    now = int(time.time() * 1000)
    md = modify_date if modify_date is not None else now
    ci = uuid.uuid4()
    return {
        "type": note_type,
        "subject": subject,
        "modifyDate": md,
        "alertDate": alert_date,
        "relationType": relation_type,
        "colorId": color_id,
        "content": content,
        "snippet": content.replace("\n", " ")[:200],
        "folderId": folder_id,
        "createDate": now,
        "setting": {"stickyTime": 0, "version": 0, "themeId": 0,
                    "totalSize": 0},
        "extraInfo": json.dumps({"title": subject,
                                 "clientUuid": str(ci)},
                                ensure_ascii=False),
    }


def note_update_envelope(nid: str, tag: str, subject: str, content: str,
                         create_date: int, folder_id: str = "0",
                         note_type: str = "mdNote") -> dict:
    """组装 updateNote 的 entry —— 复刻 electron 的 CTi()

    官方调用点 (pushService.drainQueue):
        updateNote(s.syncId, {...base, tag: s.syncTag, createDate: s.createDate,
                              status: rT.NORMAL /* 0 */, modifyDate: s.modifyDate})
    其中 base 同样来自 CSe()+内容字段。

    ★ 实测: 只给 {id, subject, content} 会被拒 (10008) —— 更新路径
      必须显式带上 **tag / createDate / status**, 且 tag 要与同步时的
      syncTag 一致 (服务端用它做版本比对)。
    ★ status 用**数字** rT.NORMAL = 0 (不是字符串 "normal")。
    """
    env = note_envelope(subject, content, folder_id=folder_id,
                        note_type=note_type)
    env["id"] = nid
    env["tag"] = tag
    env["createDate"] = create_date
    env["status"] = 0          # rT.NORMAL
    return env


def folder_envelope(name: str, fid: str = "",
                    modify_date: Optional[int] = None) -> dict:
    """组装 createFolder/updateFolder 的 entry

    ★★ 实测 (2026-10-08): 文件夹的**名字字段是 `subject`, 不是 `name`**。
       用 name 会被服务端拒: {"reason":"invalid subject","code":10008}。
       这与本地表 micloud_note_folders 的 `name` 列是**命名分歧** ——
       本地叫 name, 服务端叫 subject。字段映射必须显式做。
    ★ type 必须显式给 "folder" (sv.FOLDER), 否则 10008 "type is unset"。
    """
    now = int(time.time() * 1000)
    env: Dict[str, Any] = {
        "type": "folder",
        "subject": name,                     # ★ 不是 "name"
        "modifyDate": modify_date if modify_date is not None else now,
    }
    if fid:
        env["id"] = fid
        env["tag"] = fid                     # 更新时 tag 与 id 同源
    return env


class NotesApi:
    """复刻 electron NotesApi —— Dl = /mic/note/pc/v3.1/user"""

    def __init__(self, cli: "Client"):
        self.cli = cli

    # ── 读 ────────────────────────────────────────────────────────
    def list_full(self, sync_tag: str = "0", limit: int = 100,
                  sync_extra_info: str = "", filter_tag: str = "") -> dict:
        p: Dict[str, Any] = {"syncTag": str(sync_tag), "limit": str(limit)}
        if sync_extra_info:
            p["syncExtraInfo"] = sync_extra_info
        if filter_tag:
            p["filterTag"] = filter_tag
        return self.cli.get(f"{BASE}/full", p)

    def guide_status(self) -> dict:
        return self.cli.get(f"{BASE}/guide/status")

    def user_status(self) -> dict:
        return self.cli.get("/mic/note/v3/user/status")

    # ── 写 ────────────────────────────────────────────────────────
    def _entry_str(self, entry: dict) -> str:
        """Qj() + Jj.stringify() —— 雪花字段裸数字序列化"""
        obj = bigint_check(entry)
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        # 把 "id":"123" 还原成 "id":123 —— json-bigint 的行为
        for k in _SNOWFLAKE_KEYS:
            if isinstance(obj.get(k), str) and re.fullmatch(r"-?\d+", obj[k]):
                body = body.replace(f'"{k}":"{obj[k]}"', f'"{k}":{obj[k]}')
        return body

    def create_note(self, entry: dict) -> dict:
        """createNote(e) → POST {Dl}/note  {entry, ckey}"""
        return self.cli.post_form(f"{BASE}/note", {
            "entry": self._entry_str(entry),
            "ckey": str(uuid.uuid4()),
        })

    def update_note(self, nid: str, entry: dict) -> dict:
        """updateNote(id, e) → POST {Dl}/note/{id}  {entry, ckey}"""
        sid = check_syncid(nid, "note id")
        merged = dict(entry)
        merged["id"] = sid
        return self.cli.post_form(
            f"{BASE}/note/{urllib.parse.quote(sid, safe='')}", {
                "entry": self._entry_str(merged),
                "ckey": str(uuid.uuid4()),
            })

    def delete_entry(self, nid: str, tag: str) -> dict:
        """deleteEntry(id, tag) → POST {Dl}/full/{id}/delete  {tag, ckey}

        ★ tag 是**独立参数**, 不在 entry 里; 也必须是正整数 Long 字符串
        """
        sid = check_syncid(nid, "note id")
        return self.cli.post_form(
            f"{BASE}/full/{urllib.parse.quote(sid, safe='')}/delete", {
                "tag": check_syncid(tag, "note tag"),
                "ckey": str(uuid.uuid4()),
            })

    def purge_entry(self, nid: str, tag: str) -> dict:
        """purgeEntry(id, tag) → POST {Dl}/full/{id}/purge  {tag, ckey}"""
        sid = check_syncid(nid, "note id")
        return self.cli.post_form(
            f"{BASE}/full/{urllib.parse.quote(sid, safe='')}/purge", {
                "tag": check_syncid(tag, "note tag"),
                "ckey": str(uuid.uuid4()),
            })

    def restore_note(self, nid: str) -> dict:
        """restoreNote(id) → POST {Dl}/note/{id}/restore  {ckey}"""
        sid = check_syncid(nid, "note id")
        return self.cli.post_form(
            f"{BASE}/note/{urllib.parse.quote(sid, safe='')}/restore",
            {"ckey": str(uuid.uuid4())})

    def detail(self, nid: str) -> dict:
        """getNote(id) → GET {Dl}/full/{id}

        ★ 单条详情。id 必须正整数 Long 串 (check_syncid), 否则服务端 10008。
        """
        sid = check_syncid(nid, "note id")
        return self.cli.get(f"{BASE}/full/{urllib.parse.quote(sid, safe='')}")

    def list_deleted(self, limit: int = 50, sync_tag: str = "") -> dict:
        """listDeleted → GET {Dl}/full/deleted  {limit, syncTag?}

        ★ 回收站列表。响应带 **expireInterval**(保留天数) + maxIgnoreTag。
        ★ entries 与 folders **混流** —— 按 type=="folder" 分流。
        """
        p: Dict[str, Any] = {"limit": str(limit)}
        if sync_tag:
            p["syncTag"] = str(sync_tag)
        return self.cli.get(f"{BASE}/full/deleted", p)

    def create_folder(self, entry: dict) -> dict:
        """createFolder → POST {Dl}/folder  {entry, ckey}"""
        return self.cli.post_form(f"{BASE}/folder", {
            "entry": self._entry_str(entry),
            "ckey": str(uuid.uuid4()),
        })

    def update_folder(self, fid: str, entry: dict) -> dict:
        """updateFolder(id, e) → POST {Dl}/folder/{id}  {entry, ckey}"""
        sid = check_syncid(fid, "folder id")
        merged = dict(entry)
        merged["id"] = sid
        return self.cli.post_form(
            f"{BASE}/folder/{urllib.parse.quote(sid, safe='')}", {
                "entry": self._entry_str(merged),
                "ckey": str(uuid.uuid4()),
            })

    def restore_folder(self, fid: str) -> dict:
        """restoreFolder(id) → POST {Dl}/folder/{id}/restore  {ckey}"""
        sid = check_syncid(fid, "folder id")
        return self.cli.post_form(
            f"{BASE}/folder/{urllib.parse.quote(sid, safe='')}/restore",
            {"ckey": str(uuid.uuid4())})

    def mark_guide(self) -> dict:
        """markGuideUploaded → POST {Dl}/guide/status  {ckey}"""
        return self.cli.post_form(f"{BASE}/guide/status",
                                  {"ckey": str(uuid.uuid4())})


def _rc4(data: bytes, key: bytes) -> bytes:
    """复刻 electron xXt() —— KSS secure_key 的 RC4 加密 (标准 KSA+PRGA)"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for o in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[o] = data[o] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


BLOCK_SIZE = 4 * 1024 * 1024          # xl = 4 MiB


def split_blocks(data: bytes) -> tuple:
    """复刻 electron GVt() —— 分块 + 每块 sha1/md5/size + 整文件 sha1

    返回 (fileSha1, blockInfos, blocks)
    ★ 末块长度 = 总长 - (n-1)*4MiB (可能不足 4MiB, 可能为 0 长度的边界不会出现,
      因为块数 = max(1, ceil(size/BLOCK_SIZE)))。
    """
    n = max(1, -(-len(data) // BLOCK_SIZE))
    infos, blocks = [], []
    whole = hashlib.sha1()
    for h in range(n):
        b = data[h * BLOCK_SIZE:(h + 1) * BLOCK_SIZE]
        whole.update(b)
        infos.append({
            "sha1": hashlib.sha1(b).hexdigest(),
            "md5": hashlib.md5(b).hexdigest(),
            "size": len(b),
        })
        blocks.append(b)
    return whole.hexdigest(), infos, blocks


def guess_mime(name: str) -> str:
    """复刻 electron IKi() —— 扩展名 → MIME

    ★★ 实测 (2026-10-08): 服务端对 mimeType 有**白名单校验**,
       不在白名单的值一律 10008:
         {"reason":"bad mimeType for ico/note_img/note_rec","code":10008}
       `application/octet-stream` **被拒**!
       (electron 的 IKi 兜底就是 octet-stream —— 说明官方只走已知扩展名,
        未知类型会被服务端挡下。)
    ★ 所以这里兜底用 `application/octet-stream` 保持与官方一致,
      但调用方遇到 10008 应改传白名单内的具体类型。
    """
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return {
        "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
        "gif": "image/gif", "webp": "image/webp",
        "mp3": "audio/mpeg", "m4a": "audio/mp4", "aac": "audio/aac",
        "wav": "audio/wav",
    }.get(ext, "application/octet-stream")


class FileApi:
    """复刻 electron FileApi —— 笔记图片附件域

    ★ 域名与笔记主域 **不同**: fileapi.micloud.xiaomi.net
    ★ 分三步: request_upload(拿 kss URL) → PUT 块 → commit(落库)
      download 则是: request_download(拿 URL) → GET。
    ★ type 常量 RGi="note_img"。E2EE 附件要额外带 X-E2EE-STATUS 头。
    """

    HOST = "fileapi.micloud.xiaomi.net"
    TYPE_NOTE_IMG = "note_img"

    def __init__(self, cli: "Client"):
        self.cli = cli
        if self.cli.host != self.HOST:
            self.cli = Client({"ssecurity": cli.ssec, "token": cli.tok,
                               "cUserId": cli.cid}, host=self.HOST)

    def request_download(self, file_id: str,
                         ftype: str = TYPE_NOTE_IMG) -> dict:
        """requestDownload → GET /mic/file/v3/user/request_download"""
        return self.cli.get("/mic/file/v3/user/request_download",
                            {"fileId": str(file_id), "type": ftype})

    def request_upload(self, request: dict, kss: dict,
                       encrypt_info: Optional[dict] = None) -> dict:
        """requestUpload → POST /mic/file/v3/user/request_upload"""
        p: Dict[str, Any] = {
            "request": json.dumps(request, ensure_ascii=False,
                                  separators=(",", ":")),
            "kss": json.dumps(kss, ensure_ascii=False,
                              separators=(",", ":")),
        }
        if encrypt_info:
            p["encryptInfo"] = json.dumps(encrypt_info, ensure_ascii=False,
                                          separators=(",", ":"))
        return self.cli.post_form("/mic/file/v3/user/request_upload", p)

    def commit(self, commit: dict,
               encrypt_info: Optional[dict] = None) -> dict:
        """commit → POST /mic/file/v3/user/commit"""
        p: Dict[str, Any] = {
            "commit": json.dumps(commit, ensure_ascii=False,
                                 separators=(",", ":")),
        }
        if encrypt_info:
            p["encryptInfo"] = json.dumps(encrypt_info, ensure_ascii=False,
                                          separators=(",", ":"))
        return self.cli.post_form("/mic/file/v3/user/commit", p)

    def download_bytes(self, file_id: str) -> bytes:
        """★ 附件下载全链路 —— 复刻 request_download → 逐块 GET → RC4 解密

        ★★ 下载响应的 URL 藏在 `data.storage.kss.blocks[].urls[0]`，
           **不是** `data.url`。且块内容带 secure_key，**必须 RC4 解密**。
        实测 (2026-10-08): 密文 sha1 与声明的 sha1 不符，RC4 后吻合。
        """
        import urllib.request
        rd = self.request_download(file_id)
        kss = _dig(rd, "data", "data", "storage", "kss") or {}
        sk = kss.get("secure_key")
        key = bytes.fromhex(sk) if sk else None
        out = b""
        for b in (kss.get("blocks") or []):
            urls = b.get("urls") or []
            if not urls:
                continue
            raw = urllib.request.urlopen(urls[0], timeout=60).read()
            out += _rc4(raw, key) if key else raw
        return out

    # ── KSS 块上传 ────────────────────────────────────────────────
    @staticmethod
    def upload_block_chunk(node_url: str, file_meta: str, block_meta: str,
                           data: bytes, retries: int = 2) -> str:
        """复刻 electron jVt() —— 直传 KSS 节点, 拿 commit_meta

        ★★ 这是**唯一不走 micloud 签名**的一步:
           裸 HTTP POST 到 node_url(如 http://kssh2.xmssdn.micloud.mi.com/...)
           路径 /upload_block_chunk?chunk_pos=0&file_meta=…&block_meta=…
           Content-Type: application/x-www-form-urlencoded
           body = **裸二进制块** (不是表单编码!)
        ★ 失败重试 retries 次, 退避 attempt*1s。
        ★ 响应 JSON 里的 `commit_meta` 是要回传给 commit 的关键字段。
        """
        import urllib.request
        qs = urllib.parse.urlencode(
            {"chunk_pos": "0", "file_meta": file_meta, "block_meta": block_meta})
        url = f"{node_url}/upload_block_chunk?{qs}"
        last = None
        for c in range(1, retries + 1):
            try:
                req = urllib.request.Request(
                    url, data=data, method="POST",
                    headers={"Content-Type":
                             "application/x-www-form-urlencoded"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = resp.read()
                j = json.loads(body.decode("utf-8", "replace"))
                if "commit_meta" not in j:
                    raise RuntimeError(
                        f"upload_block_chunk response missing commit_meta: "
                        f"{str(j)[:200]}")
                return j["commit_meta"]
            except Exception as e:
                last = e
                if c < retries:
                    time.sleep(c * 1.0)
        raise RuntimeError(f"upload_block_chunk failed after {retries}: {last}")

    def upload_bytes(self, data: bytes, filename: str,
                     e2ee: Optional[bytes] = None) -> dict:
        """★ 附件上传全链路 —— 复刻 electron uploadAttachment → _doUpload

        步骤 (严格按 app.asar 的 _doUpload):
          1. GVt: 分块 + 算 sha1/md5  → (fileSha1, blockInfos)
          2. POST request_upload      {request:{storage,type:"note_img"},
                                       kss:{block_infos}}   X-E2EE-STATUS
          3a. 若响应含 `fileId` → 秒传命中, 直接返回 (跳过 3b/4)
          3b. 否则: 对每个 is_existed!=1 的块, RC4(secure_key) 后 POST 到
              node_urls[0] 的 /upload_block_chunk
          4. POST commit {storage:{uploadId,size,sha1,
                                   kss:{file_meta,commit_metas:[{commit_meta}]}}}
          返回 {fileId, digest, mimeType}

        ★ e2ee: 传 key 时对每块先 RC4 再加/解密 (本客户端只做明文路径,
          e2ee 路径留参数位)。
        """
        mime = guess_mime(filename)
        file_sha1, block_infos, blocks = split_blocks(data)
        req = {"storage": {"filename": filename, "size": len(data),
                           "sha1": file_sha1, "mimeType": mime},
               "type": self.TYPE_NOTE_IMG}
        r1 = self.request_upload(req, {"block_infos": block_infos})
        d1 = _dig(r1, "data", "data") or {}

        # 3a. 秒传命中
        if "fileId" in d1:
            return {"fileId": d1["fileId"], "digest": file_sha1,
                    "mimeType": mime, "instant": True}

        upload_id = d1.get("uploadId")
        kss = d1.get("kss") or {}
        node_urls = kss.get("node_urls") or []
        if not upload_id or not node_urls:
            raise RuntimeError(
                f"request_upload 缺 uploadId/node_urls: {str(d1)[:300]}")
        node = node_urls[0]
        file_meta = kss.get("file_meta")
        sk = kss.get("secure_key")
        secure_key = bytes.fromhex(sk) if sk else None
        metas = kss.get("block_metas") or []

        # 3b. 逐块上传
        commit_metas = []
        for h, bm in enumerate(metas):
            if bm.get("is_existed") == 1:
                commit_metas.append(bm.get("block_meta"))   # 服务端已有
                continue
            payload = blocks[h]
            if secure_key:
                payload = _rc4(payload, secure_key)
            cm = self.upload_block_chunk(node, file_meta,
                                         bm.get("block_meta"), payload)
            commit_metas.append(cm)

        # 4. commit
        commit = {"storage": {
            "uploadId": upload_id, "size": len(data), "sha1": file_sha1,
            "kss": {"file_meta": file_meta,
                    "commit_metas": [{"commit_meta": c} for c in commit_metas]},
        }}
        r4 = self.commit(commit)
        d4 = _dig(r4, "data", "data") or {}
        return {"fileId": d4.get("fileId"), "digest": file_sha1,
                "mimeType": mime, "instant": False,
                "_commit": d4, "_raw": r4}


class TodoApi:
    """复刻 electron TodoApi —— O4 = /mic/todo/pc/v1/user/records"""

    def __init__(self, cli: "Client"):
        self.cli = cli

    def sync(self, sync_token: str = "", limit: int = 100) -> dict:
        """sync → GET {O4}  {limit, syncToken?}

        ★★ 实测 (2026-10-08): `syncToken` 必须传**整个 token 对象的 JSON 串**,
           即 `json.dumps(resp["syncToken"])` → `'{"obj":"CwABAAAA…"}'`。
           传裸 `obj` 值会报: {"reason":"convert json to swift by base64 failed.",
                              "code":10008}
           (服务端要的是它自己下发的那个结构, 不是里头那一层 b64。)

        ★ 响应: {hasMore, syncToken:{obj}, records:[…]}
           `hasMore=false` + `records:[]` 表示已到水位末尾 (无新变更)。
        """
        p: Dict[str, Any] = {"limit": str(limit)}
        if sync_token:
            p["syncToken"] = sync_token
        return self.cli.get(TODO, p)

    @staticmethod
    def token_str(resp_data: dict) -> str:
        """从 sync 响应里取出可直接回传的 syncToken 串 (整体 JSON)"""
        tk = (resp_data or {}).get("syncToken")
        if isinstance(tk, dict):
            return json.dumps(tk, ensure_ascii=False, separators=(",", ":"))
        if isinstance(tk, str):
            return tk
        return ""

    @staticmethod
    def build_record(entity: dict, assets: Optional[list] = None) -> dict:
        """组装 TodoRecordEnvelope

        ★★ 实测最重要的契约: **收发非对称**
            - 发送 (create/update): entity 字段**扁平摊在 contentJson 下**
                 {"type":"entity","contentJson":{...entity字段..., "assets":[]}}
            - 接收 (sync 返回):    服务端**嵌套**包一层 entity
                 {"type":"entity","contentJson":{"entity":{...},"assets":[]}}

        证据: 嵌套发送 → 恒 10008 "entity content is empty";
              扁平发送 → code=0 创建成功, 且服务端回存为嵌套形状。
        坑: electron 源码里的 e9t() 生成的是**嵌套**形状, 但那只是
            服务端回包被复用/或该分支未被实际走到 —— 以实测为准。

        ★ eTag 乐观锁在【顶层 record】, 不在 entity 里
        ★ 官方 e9t 会无条件下发所有字段; 缺字段会触发服务端非空校验,
          故每个字段都补默认值。

        入参支持两种命名: 服务器名 (customSortId/createTime) 或
        DB 行名 (sortOrder/createdAt/entityId), 后者会被映射。
        """
        now = int(time.time() * 1000)

        def g(*names, default=None):
            for n in names:
                if n in entity and entity[n] is not None:
                    return entity[n]
            return default

        content = str(g("content", default=""))
        plain = str(g("plainText", default="")) or content
        list_type = int(g("listType", default=0))
        remind_time = int(g("remindTime", default=0) or 0)

        ent = {
            "listType": list_type,
            "content": content,
            "plainText": plain,
            "isFinish": int(g("isFinish", default=0) or 0),
            "markFinishTime": int(g("markFinishTime", "finishTime",
                                    default=0) or 0),
            "remindType": int(g("remindType",
                                default=(2 if remind_time else 0)) or 0),
            "remindRepeatType": int(g("remindRepeatType", "repeatType",
                                      default=0) or 0),
            "remindTime": remind_time,
            "firstRemindTime": int(g("firstRemindTime", default=0) or 0),
            "customSortId": int(g("customSortId", "sortOrder",
                                  default=1048576) or 0),
            "createTime": int(g("createTime", "createdAt", default=now) or 0),
            "lastModifiedTime": int(g("lastModifiedTime", "updatedAt",
                                      default=now) or 0),
            "inputType": int(g("inputType", default=0) or 0),
            "expireTime": int(g("expireTime", default=0) or 0),
            "hideType": int(g("hideType", default=0) or 0),
            "folderId": int(g("folderId", default=0) or 0),
            "colorLabel": int(g("colorLabel", default=0) or 0),
            "source": int(g("source", default=0) or 0),
            "localStatus": int(g("localStatus", default=0) or 0),
            "serverStatus": int(g("serverStatus", default=0) or 0),
            "audioFileField": str(g("audioFileField", default="")),
            "audioFileName": str(g("audioFileName", default="")),
            "audioFileSize": int(g("audioFileSize", default=0) or 0),
            "id": int(g("entityId", "entity_id", default=0) or 0),
        }
        return {"type": "entity", "contentJson": {**ent,
                                                 "assets": assets or []}}

    def create(self, record: dict) -> dict:
        """create(r) → POST {O4}  {record}  (无 ckey, 无 eTag)"""
        return self.cli.post_form(TODO, {
            "record": json.dumps(record, ensure_ascii=False,
                                 separators=(",", ":")),
        })

    def update(self, rid: str, e_tag: str, record: dict) -> dict:
        """update(id, eTag, r) → POST {O4}/{id}/update  {eTag, record}"""
        sid = check_syncid(rid, "todo id")
        return self.cli.post_form(
            f"{TODO}/{urllib.parse.quote(sid, safe='')}/update", {
                "eTag": check_syncid(e_tag, "todo eTag"),
                "record": json.dumps(record, ensure_ascii=False,
                                     separators=(",", ":")),
            })

    def delete(self, rid: str, e_tag: str) -> dict:
        """delete(id, eTag) → POST {O4}/{id}/delete  {eTag}"""
        sid = check_syncid(rid, "todo id")
        return self.cli.post_form(
            f"{TODO}/{urllib.parse.quote(sid, safe='')}/delete", {
                "eTag": check_syncid(e_tag, "todo eTag"),
            })


def _resolve(host: str) -> str:
    import socket
    try:
        return socket.gethostbyname(host)
    except Exception:
        return "161.117.96.24"


def _hdr_base(client: "Client", path: str) -> List[str]:
    """★ PC 端真实请求头集合 —— 复刻 bwi.buildHeaders()

    官方 bwi.buildHeaders() 只返回:
        { ...this.getHeaders(), "X-XIAOMI-SUPPORT-REDIRECT": "true" }
    而 noteapi 用的 client (createClient(defaultHost=NOTE)) 的 getHeaders() 回调
    只注入 E2EE (且默认 isEnabled=false → X-E2EE-STATUS:"false")。

    ★★ 实测决定: 绝不能发 X-E2EE: 1.0.0 + X-E2EE-STATUS: 0 (Android 那套)。
       一旦带 X-E2EE, 服务端切到 E2EE 封装分支 (响应前缀 "ac"),
       而对本账号该分支未开通 → 一律回 {"code":-1,"reason":"服务维护中,请等待"}。
       去掉后响应前缀为 "98", code=0 正常返回。

    ★ extra_headers: 额外自定义请求头 (CloudKit 的 appId 就走header,
       见 25 号规格 §2.1)。None 时行为与原来完全一致。
    """
    return [
        f"Host: {client.host}",
        f"Cookie: {client._cookies()}",
        "User-Agent: APP/Xiaomi miclaw APPV/0.0.1-beta.114+a3e3203f "
        "Chrome/144.0.7559.111",
        "X-XIAOMI-SUPPORT-REDIRECT: true",
        "Accept: */*",
        "Connection: close",
    ] + [f"{k}: {v}" for k, v in (client.extra_headers or {}).items()]


# ══════════════════════════════════════════════════════════════════
# 本地水位 (syncTag / syncExtraInfo / syncToken)
# ══════════════════════════════════════════════════════════════════
def read_watermarks() -> Dict[str, Dict[str, str]]:
    """从 HyperConnect 的 miclaw.sqlite 读同步游标"""
    out: Dict[str, Dict[str, str]] = {}
    if not os.path.exists(SQLITE):
        print(f"  ⚠ 水位库不存在: {SQLITE}")
        return out
    try:
        c = sqlite3.connect(f"file:{SQLITE}?mode=ro&immutable=1", uri=True)
        for mod, key, val in c.execute(
                "SELECT module, key, value FROM micloud_sync_watermark"):
            out.setdefault(mod, {})[key] = val
        c.close()
    except Exception as e:
        print(f"  ⚠ 读水位失败: {e}")
    return out


# ══════════════════════════════════════════════════════════════════
# 命令
# ══════════════════════════════════════════════════════════════════
def show(tag: str, r: dict) -> None:
    print(f"\n  ── {tag} ──")
    print(f"     {r['status']}")
    d = r["data"]
    s = json.dumps(d, ensure_ascii=False, indent=2)
    if len(s) > 1800:
        s = s[:1800] + "\n     … (截断)"
    print("     " + s.replace("\n", "\n     "))


def fetch_notes_all(cli: "Client", wm: dict, max_pages: int = 50) -> List[dict]:
    """★ 循环翻页拉取全部笔记, 直到 lastPage=true

    协议 (实测):
      GET {BASE}/full  params: syncTag, limit, syncExtraInfo?
      响应 data = { entries[], lastPage, syncTag, syncExtraInfo }
        lastPage=false → 用响应的 syncTag/syncExtraInfo 继续请求下一页
        lastPage=true  → 完结, 响应的 syncTag 即新水位
    ★ syncTag=0 表示"从头拉", 每页最多 limit 条(实测 100 生效)
    """
    n = wm.get("note", {})
    stag = "0"
    sinfo = ""
    all_entries: List[dict] = []
    for page in range(max_pages):
        params: Dict[str, Any] = {"syncTag": stag, "limit": "100"}
        if sinfo:
            params["syncExtraInfo"] = sinfo
        r = cli.get(f"{BASE}/full", params)
        d = (r["data"] or {}).get("data") or {}
        ent = d.get("entries") or []
        all_entries.extend(ent)
        last = d.get("lastPage")
        print(f"     第 {page+1} 页: {len(ent):3d} 条  lastPage={last}  "
              f"syncTag={d.get('syncTag')}")
        if last:
            break
        nstag = d.get("syncTag")
        if not nstag or str(nstag) == str(stag):
            print("     ⚠ syncTag 未推进, 中止翻页")
            break
        stag = str(nstag)
        sinfo = d.get("syncExtraInfo") or ""
    return all_entries


def cmd_notes(cli: Client, wm: dict) -> int:
    n = wm.get("note", {})
    stag = n.get("syncTag", "")
    sinfo = n.get("syncExtraInfo", "")
    print(f"\n  本地水位: syncTag={stag!r} syncExtraInfo={sinfo[:32]!r}…")
    show("guide/status", cli.get(f"{BASE}/guide/status"))
    show("user/status", cli.get("/mic/note/v3/user/status"))
    print("\n  ── full (翻页全量) ──")
    ents = fetch_notes_all(cli, wm)
    print(f"\n     合计 {len(ents)} 条笔记")
    # 落盘
    os.makedirs(RUNTIME, exist_ok=True)
    out = os.path.join(RUNTIME, "notes_pc_pull.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(ents, f, ensure_ascii=False, indent=2)
    print(f"     ✓ 已存 {out}")
    return 0


def cmd_todos(cli: Client, wm: dict) -> int:
    ta = TodoApi(cli)
    print(f"\n  ── records (全量首页) ──")
    r1 = ta.sync(limit=100)
    d1 = _payload(r1)
    print(f"     共 {len(d1.get('records') or [])} 条  "
          f"hasMore={d1.get('hasMore')}")
    for x in (d1.get("records") or []):
        e = _ent_of(x)
        fin = "✓" if e.get("isFinish") else " "
        rt = e.get("remindTime") or 0
        rts = (time.strftime("%m-%d %H:%M", time.localtime(rt / 1000))
               if rt else "")
        print(f"     [{fin}] id={x.get('id')} {str(e.get('plainText'))[:44]!r}"
              + (f"  ⏰{rts}" if rts else ""))
    # ★ 增量: 必须回传**整个 token 对象的 JSON 串**, 不是裸 obj。
    tok = TodoApi.token_str(d1)
    if tok:
        r2 = ta.sync(limit=100, sync_token=tok)
        d2 = _payload(r2)
        print(f"\n  ── records (增量) code={_dig(r2, 'data', 'code')} ──")
        print(f"     新变更 {len(d2.get('records') or [])} 条  "
              f"hasMore={d2.get('hasMore')} (空=已到水位末尾)")
    return 0


def cmd_all(cli: Client) -> int:
    wm = read_watermarks()
    print(f"\n  水位模块: {list(wm.keys())}")
    cmd_notes(cli, wm)
    cmd_todos(cli, wm)
    return 0


# ══════════════════════════════════════════════════════════════════
# 写侧命令 —— push(写一条) / watch(轮询发现) / daemon(常驻同步+写)
# ══════════════════════════════════════════════════════════════════
MARK = "__PROTOBE__"          # 本工具写入内容的统一标记, 便于识别与清理
STATE = os.path.join(RUNTIME, "noteapi_service_state.json")


def _load_state() -> dict:
    if os.path.exists(STATE):
        try:
            return json.load(open(STATE, encoding="utf-8"))
        except Exception:
            pass
    return {"seen_notes": [], "seen_todos": [], "written": []}


def _save_state(st: dict) -> None:
    os.makedirs(RUNTIME, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE)


def _dig(d: Any, *path: str) -> Any:
    """安全下钻 —— noteapi 响应层级不稳定, 逐层判类型"""
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _payload(r: dict) -> dict:
    """取业务层 data —— 响应形如 {status, data:{result, data:{…}, code}}"""
    return _dig(r, "data", "data") or {}


def _ent_of(rec: dict) -> dict:
    """取待办的实体 —— 兼容服务端两种形状 (嵌套 / 扁平)"""
    cj = rec.get("contentJson") or {}
    if isinstance(cj.get("entity"), dict):
        return cj["entity"]
    return cj


def cmd_push(cli: Client) -> int:
    """写一条带标记的笔记 + 一条带标记的待办, 然后立刻读回验证"""
    na, ta = NotesApi(cli), TodoApi(cli)
    stamp = time.strftime("%H:%M:%S")
    print(f"\n  ── 写入笔记 ({MARK}) ──")
    r = na.create_note(note_envelope(
        subject=f"{MARK} service-probe",
        content=f"由 noteapi_pc.py 于 {stamp} 写入\n本行用于验证 PC→云端→手机 的同步链路。",
    ))
    show("createNote", r)
    # ★ 响应形状: data.data.entry.{id,tag}  →  id == tag (创建时同值)
    #   (外层 data 来自 _parse_e2ee, 内层 data 是业务层)
    new_id = _dig(r, "data", "data", "entry", "id")
    new_tag = _dig(r, "data", "data", "entry", "tag")
    print(f"     → 新笔记 id={new_id} tag={new_tag}")

    if new_id:
        print(f"\n  ── 读回验证 (full) ──")
        got = _find_note(na, str(new_id))
        print(f"     {'✓ 命中' if got else '⚠ 未回读到'}"
              + (f": subject={got.get('subject')!r}" if got else
                 " (可能需要等一轮增量)"))

        print(f"\n  ── 更新验证 (updateNote) ──")
        ru = na.update_note(str(new_id), note_envelope(
            subject=f"{MARK} service-probe (updated)",
            content=f"更新于 {stamp}",
        ))
        show("updateNote", ru)

    print(f"\n  ── 写入待办 ({MARK}) ──")
    rec = TodoApi.build_record({
        "content": f"{MARK} 待办 {stamp}",
        "plainText": f"{MARK} 待办 {stamp}",
        "isFinish": 0,
        "listType": 0,
        "customSortId": 12582912,
    })
    rt = ta.create(rec)
    show("todo create", rt)

    print(f"\n  → 现在去手机上打开笔记/待办 App 看是否出现 {MARK} 条目")
    print(f"  → 用 --watch 观察云端变化; 用 --daemon 让它自己写自己同步")
    return 0


def _find_note(na: NotesApi, nid: str) -> Optional[dict]:
    r = na.list_full(sync_tag="0", limit=200)
    for e in _payload(r).get("entries") or []:
        if str(e.get("id")) == nid or str(e.get("tag")) == nid:
            return e
    return None


def cmd_watch(cli: Client, once: bool = False) -> int:
    """轮询 —— 打印云端笔记/待办的变化 (标出 MARK 条目)"""
    na, ta = NotesApi(cli), TodoApi(cli)
    st = _load_state()
    seen_n = set(st.get("seen_notes") or [])
    seen_t = set(st.get("seen_todos") or [])
    first = True
    while True:
        r = na.list_full(sync_tag="0", limit=200)
        entries = _payload(r).get("entries") or []
        cur_n = {str(e.get("id")) for e in entries}
        if first:
            print(f"\n  基线: {len(entries)} 条笔记")
            for e in entries:
                if MARK in (e.get("subject") or "") + (e.get("content") or ""):
                    print(f"     ★ 已有标记条目 id={e.get('id')} "
                          f"{e.get('subject')!r}")
        else:
            for e in entries:
                if str(e.get("id")) not in seen_n:
                    print(f"\n  ✚ 新笔记 id={e.get('id')} "
                          f"subject={e.get('subject')!r}")
                    print(f"     {str(e.get('snippet') or '')[:80]}")
        seen_n |= cur_n

        rt = ta.sync(limit=200)
        recs = _payload(rt).get("records") or []
        cur_t = {str(x.get("id")) for x in recs}
        if first:
            print(f"  基线: {len(recs)} 条待办")
        else:
            for x in recs:
                if str(x.get("id")) not in seen_t:
                    pt = _ent_of(x).get("plainText")
                    print(f"\n  ✚ 新待办 id={x.get('id')} {pt!r}")
        seen_t |= cur_t

        st.update({"seen_notes": sorted(seen_n), "seen_todos": sorted(seen_t)})
        _save_state(st)
        first = False
        if once:
            break
        time.sleep(5)
    return 0


def cmd_daemon(cli: Client, interval: int = 15) -> int:
    """常驻 —— 同步 + 周期性自写测试内容, 用于观察手机端是否跟随

    每个周期:
      1) 拉全量笔记/待办, 记录水位 (证明"能自己同步")
      2) 每 --write-every 周期写入一条 MARK 笔记 (证明"能自己写")
      3) 删除上一轮写入的旧 MARK 笔记, 避免堆积
    """
    na, ta = NotesApi(cli), TodoApi(cli)
    st = _load_state()
    written: List[str] = st.get("written") or []
    cycle = 0
    print("=" * 74)
    print(f"noteapi 同步服务 —— 每 {interval}s 一轮, Ctrl-C 退出")
    print(f"  写入标记: {MARK}   状态文件: {STATE}")
    print("=" * 74)
    while True:
        cycle += 1
        try:
            r = na.list_full(sync_tag="0", limit=200)
            entries = _payload(r).get("entries") or []
            water = _payload(r).get("syncTag")
            rt = ta.sync(limit=200)
            recs = _payload(rt).get("records") or []
            mark_n = [e for e in entries
                      if MARK in (e.get("subject") or "")
                      + (e.get("content") or "")]
            mark_t = [x for x in recs
                      if MARK in (_ent_of(x).get("plainText") or "")]
            print(f"\n[{time.strftime('%H:%M:%S')}] 第 {cycle} 轮  "
                  f"笔记 {len(entries)} 条 (标记 {len(mark_n)})  "
                  f"待办 {len(recs)} 条 (标记 {len(mark_t)})  "
                  f"水位 {water}")
            for e in mark_n:
                print(f"     ★ 笔记 {e.get('id')} "
                      f"{str(e.get('subject'))[:50]!r}")

            if cycle % 4 == 1:                      # 每 4 轮写一条
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                cr = na.create_note(note_envelope(
                    subject=f"{MARK} 自动同步 #{cycle}",
                    content=f"由 noteapi 服务于 {stamp} 自动写入。\n"
                            f"若手机端看到本条, 说明写链路已打通。",
                ))
                entry = _dig(cr, "data", "data", "entry") or {}
                nid = entry.get("id")
                print(f"     ✚ 已写入 id={nid} tag={entry.get('tag')}")
                if nid:
                    written.append(str(nid))
                if len(written) > 3:                # 只保留最近 3 条
                    old = written.pop(0)
                    # ★ 删除必须用同步下来的 tag, 不是 id ——
                    #   传 id 会得到 code:0 但实际不删 (静默失败)
                    oe = _find_note(na, old)
                    if oe:
                        de = na.delete_entry(str(oe["id"]), str(oe["tag"]))
                        got = _find_note(na, old)
                        print(f"     ✖ 删旧 {old} → code="
                              f"{_dig(de, 'data', 'code')} "
                              f"残留={'是' if got else '否'}")
                    else:
                        print(f"     ✖ 旧写入 {old} 已不在列表")

            st.update({"written": written})
            _save_state(st)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"     ⚠ 本轮异常: {type(e).__name__}: {e}")
        time.sleep(interval)


# ══════════════════════════════════════════════════════════════════
# 待办重复规则 —— 复刻 electron cDi() 的语义
# ══════════════════════════════════════════════════════════════════
REPEAT_NONE = 0
REPEAT_DAILY = 1        # 每天
REPEAT_WEEKLY = 2       # 每周 (对齐 firstRemindTime 的星期几)
REPEAT_WEEKDAY = 3      # 工作日 (周一~周五)
REPEAT_MONTHLY = 7      # 每月 (对齐 firstRemindTime 的"日")
REPEAT_YEARLY = 8       # 每年 (对齐 firstRemindTime 的月+日)

REPEAT_NAMES = {
    REPEAT_NONE: "不重复", REPEAT_DAILY: "每天", REPEAT_WEEKLY: "每周",
    REPEAT_WEEKDAY: "工作日", REPEAT_MONTHLY: "每月", REPEAT_YEARLY: "每年",
}


def _days_in_month(y: int, m: int) -> int:
    """复刻 JS 的 nq(): new Date(y, m+1, 0).getDate() —— m 是 0-based

    JS 利用 Date 的溢出归一化: 传"下个月的第 0 天"会回退到本月最后一天。
    C 没有这个捷径, 所以这里用显式表 + 闰年判断 —— 这也是 ESP32
    移植时必须自己实现的那部分。
    """
    if m == 1:                                   # 2 月
        leap = (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0)
        return 29 if leap else 28
    return [31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m]


def next_remind_time(remind_time: int, repeat_type: int,
                     first_remind_time: int = 0,
                     now_ms: Optional[int] = None) -> int:
    """复刻 cDi() —— 算出下一次触发时刻 (ms)

    ★ 语义与 electron 完全一致 (含 setHours 归零到秒级):
        i = firstRemindTime ?? remindTime       // 重复锚点
        把锚点的 年月日 搬到"max(remindTime, now)"那天 → 保留锚点的 时分秒
        若结果 <= now → 按 repeat_type 推进

    ★ 返回 0 表示不再重复。
    """
    i = first_remind_time or remind_time
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    a = max(remind_time, now)

    base = time.localtime(remind_time / 1000)
    anchor = time.localtime(i / 1000)
    cur = time.localtime(a / 1000)

    # u.setFullYear(o.y, o.m, o.d) + u.setHours(anchor.h, anchor.m, anchor.s, 0)
    dt = datetime.datetime(cur.tm_year, cur.tm_mon, cur.tm_mday,
                           anchor.tm_hour, anchor.tm_min, anchor.tm_sec)
    if dt.timestamp() * 1000 <= a:
        dt += datetime.timedelta(days=1)

    if repeat_type == REPEAT_DAILY:
        return int(dt.timestamp() * 1000)

    if repeat_type == REPEAT_WEEKLY:
        # 退到本周日 (weekday: Mon=0..Sun=6 → JS getDay: Sun=0..Sat=6)
        js_wd = (dt.weekday() + 1) % 7
        dt -= datetime.timedelta(days=js_wd)
        anchor_wd = (datetime.datetime.fromtimestamp(i / 1000).weekday() + 1) % 7
        dt += datetime.timedelta(days=anchor_wd)
        if dt.timestamp() * 1000 <= a:
            dt += datetime.timedelta(days=7)
        return int(dt.timestamp() * 1000)

    if repeat_type == REPEAT_WEEKDAY:
        while dt.weekday() >= 5:                 # 周六日跳过
            dt += datetime.timedelta(days=1)
        return int(dt.timestamp() * 1000)

    if repeat_type == REPEAT_MONTHLY:
        day = anchor.tm_mday
        dim = _days_in_month(dt.year, dt.month - 1)
        dt = dt.replace(day=min(day, dim))
        if dt.timestamp() * 1000 <= a:
            y, m = dt.year, dt.month + 1
            if m > 12:
                y, m = y + 1, 1
            dim = _days_in_month(y, m - 1)
            dt = dt.replace(year=y, month=m, day=min(day, dim))
        return int(dt.timestamp() * 1000)

    if repeat_type == REPEAT_YEARLY:
        y, m, day = anchor.tm_year, anchor.tm_mon, anchor.tm_mday
        dim = _days_in_month(dt.year, m - 1)
        dt = dt.replace(month=m, day=min(day, dim))
        if dt.timestamp() * 1000 <= a:
            dt = dt.replace(year=dt.year + 1, month=1, day=1)
            dim = _days_in_month(dt.year, m - 1)
            dt = dt.replace(month=m, day=min(day, dim))
        return int(dt.timestamp() * 1000)

    return 0


def build_alarm_todo(text: str, when: Optional[int] = None,
                     repeat: int = REPEAT_NONE,
                     first_when: Optional[int] = None) -> dict:
    """组装一条带闹钟的待办 entity

    ★ 关键契约 (已实测):
        remindType = 2 当且仅当 remindTime > 0 —— 它是【有无提醒】的开关,
                     不是枚举; 真正的重复语义在 remindRepeatType。
        firstRemindTime = 重复规则的对齐锚点。要"每周三提醒"就必须让它
                     落在一个周三上, 否则服务端算不出下一次。
                     未指定时默认 = remindTime (即"从这次开始重复")。
    """
    rt = when or 0
    ent: Dict[str, Any] = {
        "content": text,
        "plainText": text,
        "remindTime": rt,
        "remindRepeatType": repeat,
    }
    if rt > 0:
        ent["firstRemindTime"] = first_when if first_when is not None else rt
    return ent


def parse_when(s: str) -> int:
    """把人类可读的时间解析成 ms epoch

    支持:
      "2026-09-15 09:30"  绝对时间
      "+30m" / "+2h" / "+3d"   相对现在
      "09:30"             今天/明天 09:30 (已过则明天)
    """
    s = s.strip()
    now = datetime.datetime.now()
    m = re.fullmatch(r"\+(\d+)([mhd])", s)
    if m:
        n, u = int(m.group(1)), m.group(2)
        delta = {"m": datetime.timedelta(minutes=n),
                 "h": datetime.timedelta(hours=n),
                 "d": datetime.timedelta(days=n)}[u]
        return int((now + delta).timestamp() * 1000)
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", s)
    if m:
        hh, mm = int(m.group(1)), int(m.group(2))
        dt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if dt <= now:
            dt += datetime.timedelta(days=1)
        return int(dt.timestamp() * 1000)
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M",
                "%Y-%m-%d"):
        try:
            return int(datetime.datetime.strptime(s, fmt).timestamp() * 1000)
        except ValueError:
            continue
    raise ValueError(f"无法解析时间: {s!r}  (试 '2026-09-15 09:30' / '+2h' / '09:30')")


REPEAT_BY_NAME = {v: k for k, v in REPEAT_NAMES.items()}
REPEAT_BY_NAME.update({"none": 0, "no": 0, "off": 0, "daily": 1,
                       "weekly": 2, "weekday": 3, "monthly": 7,
                       "yearly": 8})


def cmd_send_todo(cli: Client, args: List[str]) -> int:
    """发一条待办 —— 可带闹钟提醒和重复规则

    用法:
      --send-todo "买牛奶"
      --send-todo "买牛奶" --at "09:30"
      --send-todo "例会" --at "2026-09-16 14:00" --repeat 每周
      --send-todo "喝水" --at "+2h" --repeat 每天
    """
    if not args or args[0].startswith("--"):
        print("  ✗ 用法: --send-todo \"内容\" [--at 时间] [--repeat 规则]")
        print("     规则: " + " / ".join(REPEAT_NAMES.values()))
        return 1
    text = args[0]
    at = ""
    repeat = REPEAT_NONE
    i = 1
    while i < len(args):
        if args[i] == "--at" and i + 1 < len(args):
            at = args[i + 1]
            i += 2
        elif args[i] == "--repeat" and i + 1 < len(args):
            key = args[i + 1]
            if key not in REPEAT_BY_NAME:
                print(f"  ✗ 未知重复规则 {key!r}; 可选: "
                      + " / ".join(REPEAT_NAMES.values()))
                return 1
            repeat = REPEAT_BY_NAME[key]
            i += 2
        else:
            i += 1

    when = parse_when(at) if at else 0
    ent = build_alarm_todo(text, when, repeat)
    if when > 0:
        print(f"  提醒: {time.strftime('%Y-%m-%d %H:%M', time.localtime(when/1000))}"
              f"  重复: {REPEAT_NAMES.get(repeat, repeat)}")
    ta = TodoApi(cli)
    r = ta.create(TodoApi.build_record(ent))
    rec = _dig(r, "data", "data", "record") or {}
    e = _ent_of(rec) if rec else {}
    print(f"  code={_dig(r, 'data', 'code')}  id={rec.get('id')} "
          f"eTag={rec.get('eTag')}")
    if e:
        print(f"  remindType={e.get('remindType')} "
              f"remindRepeatType={e.get('remindRepeatType')} "
              f"firstRemindTime={e.get('firstRemindTime')}")
    print("\n  → 去手机待办下拉同步; 到点应收到提醒")
    return 0


def cmd_send(cli: Client, args: List[str]) -> int:
    """直接发一条笔记到云端 —— 手机上会同步到

    用法:
      python noteapi_pc.py --send "标题" "正文"
      python noteapi_pc.py --send "只有正文"
    """
    if not args:
        print("  ✗ 用法: --send \"标题\" \"正文\"  (或 --send \"正文\")")
        return 1
    subject = args[0]
    content = args[1] if len(args) > 1 else args[0]
    na = NotesApi(cli)
    if len(args) == 1:
        subject = ""
    r = na.create_note(note_envelope(subject=subject, content=content))
    e = _dig(r, "data", "data", "entry") or {}
    print(f"\n  code={_dig(r, 'data', 'code')}  id={e.get('id')}")
    print(f"  subject={e.get('subject')!r}")
    print(f"  content={str(e.get('content'))[:100]!r}")
    print(f"\n  → 去手机小米笔记下拉同步即可看到")
    return 0


def fetch_deleted_all(cli: Client, max_pages: int = 30) -> dict:
    """★ 回收站翻页拉全量 —— 直到 lastPage=true

    实测 (2026-10-08): 回收站**同样分页**, 首页固定 20 条 (limit=50 也只给 20)。
    每页响应的 syncTag 是下一页游标, 必须原样回传, 否则拿不到旧条目。
    返回 {expireInterval, maxIgnoreTag, entries, folders, pages}
    """
    na = NotesApi(cli)
    stag, all_e, all_f = "0", [], []
    meta: Dict[str, Any] = {}
    for page in range(max_pages):
        p: Dict[str, Any] = {"limit": 50}
        if stag and stag != "0":
            p["sync_tag"] = stag
        r = na.list_deleted(**p)
        d = _payload(r)
        ents = d.get("entries") or []
        folds = d.get("folders") or []
        all_e.extend(ents)
        all_f.extend(folds)
        if not meta:
            meta = {k: d.get(k) for k in
                    ("expireInterval", "maxIgnoreTag")}
        print(f"     回收站第 {page+1} 页: {len(ents):3d} 条  "
              f"lastPage={d.get('lastPage')}  syncTag={d.get('syncTag')}")
        if d.get("lastPage"):
            break
        nstag = d.get("syncTag")
        if not nstag or str(nstag) == stag:
            break
        stag = str(nstag)
    meta.update({"entries": all_e, "folders": all_f,
                 "pages": page + 1})
    return meta


def cmd_recycle(cli: Client) -> int:
    """回收站 —— 翻页列表 / 恢复 / 彻底删除

    ★ 与相册回收站一致的 tag>0 硬约束: delete/purge 都要真实 tag。
    ★ 恢复 (restore) 是**唯一不需要 tag** 的写操作, 且恢复后服务端会
      **下发新 tag** (乐观锁版本号递增)。
    ★ 回收站**分页**: 首页 20 条, syncTag 续页 (实测 2026-10-08)。
    """
    d = fetch_deleted_all(cli)
    ents, folds = d["entries"], d["folders"]
    print(f"\n  ★ expireInterval = {d.get('expireInterval')} 天  "
          f"maxIgnoreTag = {d.get('maxIgnoreTag')}")
    print(f"  共 {len(ents)} 条笔记 + {len(folds)} 个文件夹 "
          f"({d.get('pages')} 页)")
    for e in ents:
        print(f"     note  id={e.get('id')} tag={e.get('tag')} "
              f"{str(e.get('subject'))[:40]!r}")
    for f in folds:
        print(f"     dir   id={f.get('id')} tag={f.get('tag')} "
              f"{str(f.get('name') or f.get('subject'))[:40]!r}")
    return 0


def cmd_folders(cli: Client) -> int:
    """文件夹 —— 从全量流里筛 type=="folder" (服务端无独立 list 接口)"""
    na = NotesApi(cli)
    r = na.list_full(sync_tag="0", limit=200)
    ents = _payload(r).get("entries") or []
    folds = [e for e in ents if e.get("type") == "folder"
             or e.get("noteType") == "folder"]
    print(f"\n  全量 {len(ents)} 条中, 文件夹 {len(folds)} 个:")
    for f in folds:
        print(f"     id={f.get('id')} tag={f.get('tag')} "
              f"name={f.get('name') or f.get('subject')!r}")
    return 0


def cmd_detail(cli: Client, nid: str) -> int:
    show(f"full/{nid}", NotesApi(cli).detail(nid))
    return 0


def cmd_attachment(cli: Client, file_id: str) -> int:
    """附件下载地址 —— 走 fileapi 域, type=note_img"""
    fa = FileApi(cli)
    show(f"request_download {file_id}", fa.request_download(file_id))
    return 0


def cmd_upload(cli: Client, args: List[str]) -> int:
    """★ 附件上传 —— 全链路 (request_upload → KSS 块 → commit)

    用法: --upload <本地文件> [--as <远端文件名>]
    """
    if not args or args[0].startswith("--"):
        print("  ✗ 用法: --upload <文件路径> [--as <远端名>]")
        return 1
    path = args[0]
    name = ""
    if "--as" in args:
        i = args.index("--as")
        if i + 1 < len(args):
            name = args[i + 1]
    if not name:
        name = os.path.basename(path)
    if not os.path.exists(path):
        print(f"  ✗ 文件不存在: {path}")
        return 1
    data = open(path, "rb").read()
    print(f"  上传 {path}  {len(data)} B  →  {name}")
    fa = FileApi(cli)
    r = fa.upload_bytes(data, name)
    print(f"  {'⚡ 秒传' if r.get('instant') else '↑ 全量上传'}  "
          f"fileId={r.get('fileId')}")
    print(f"  digest={r.get('digest')}  mime={r.get('mimeType')}")
    print(f"\n  → 该 fileId 可写进笔记的 attachment 字段")
    return 0


def cmd_download(cli: Client, args: List[str]) -> int:
    """★ 附件下载 —— 全链路 (request_download → 逐块 GET → RC4)

    用法: --download <fileId> [--out <本地路径>]
    """
    if not args or args[0].startswith("--"):
        print("  ✗ 用法: --download <fileId> [--out <路径>]")
        return 1
    fid = args[0]
    out = ""
    if "--out" in args:
        i = args.index("--out")
        if i + 1 < len(args):
            out = args[i + 1]
    fa = FileApi(cli)
    data = fa.download_bytes(fid)
    print(f"  下载 {fid}  →  {len(data)} B  "
          f"sha1={hashlib.sha1(data).hexdigest()}")
    if out:
        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
        with open(out, "wb") as f:
            f.write(data)
        print(f"  ✓ 已存 {out}")
    return 0


def main() -> int:
    a = sys.argv[1:]
    print("=" * 74)
    print("noteapi PC 客户端 —— 严格复刻 HyperConnect NotesApi/TodoApi")
    print("=" * 74)

    if "--login" in a:
        auth = _mi_auth.login_qr()
        if not auth:
            return 1
        # continue with normal flow using freshly saved credentials

    # Try mi_auth first, fall back to legacy AUTH file
    cred = _mi_auth.get_credentials()
    if cred:
        auth = {"token": cred["token"], "ssecurity": cred["ssecurity"],
                "cUserId": cred["cUserId"], "userId": cred["userId"]}
    elif os.path.exists(AUTH):
        auth = json.load(open(AUTH, encoding="utf-8"))
    else:
        print(f"  ✗ 无凭据 —— 先跑 --login")
        return 1
    cli = Client(auth)
    print(f"  host={cli.host} ip={cli.ip}")
    print(f"  token len={len(cli.tok)}  cUserId={cli.cid}")

    if "--notes" in a:
        return cmd_notes(cli, read_watermarks())
    if "--todos" in a:
        return cmd_todos(cli, read_watermarks())
    if "--status" in a:
        show("guide/status", cli.get(f"{BASE}/guide/status"))
        show("user/status", cli.get("/mic/note/v3/user/status"))
        return 0
    if "--recycle" in a:
        return cmd_recycle(cli)
    if "--folders" in a:
        return cmd_folders(cli)
    if "--detail" in a:
        i = a.index("--detail")
        if i + 1 >= len(a):
            print("  ✗ 用法: --detail <noteId>")
            return 1
        return cmd_detail(cli, a[i + 1])
    if "--attachment" in a:
        i = a.index("--attachment")
        if i + 1 >= len(a):
            print("  ✗ 用法: --attachment <fileId>")
            return 1
        return cmd_attachment(cli, a[i + 1])
    if "--upload" in a:
        i = a.index("--upload")
        return cmd_upload(cli, a[i + 1:])
    if "--download" in a:
        i = a.index("--download")
        return cmd_download(cli, a[i + 1:])
    if "--domains" in a:
        # ★ relocation 不在 noteapi 域, 在 g.interconnectapi 域 (实测 404)
        acct = Client({"ssecurity": cli.ssec, "token": cli.tok,
                       "cUserId": cli.cid}, host=INTERCONNECT_HOST)
        show("relocation", acct.get("/mic/redirect/v1/user/relocation"))
        return 0
    if "--daemon" in a:
        return cmd_daemon(cli)
    if "--push" in a:
        return cmd_push(cli)
    if "--watch" in a:
        return cmd_watch(cli)
    if "--send" in a:
        i = a.index("--send")
        return cmd_send(cli, a[i + 1:])
    if "--send-todo" in a:
        i = a.index("--send-todo")
        return cmd_send_todo(cli, a[i + 1:])
    return cmd_all(cli)


if __name__ == "__main__":
    sys.exit(main())
