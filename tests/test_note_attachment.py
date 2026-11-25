#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PC 可测：note 附件 fileId 下载闭环（findings §5.37）。

用法:
  python test_note_attachment.py              # live：扫 extraInfo + 历史/真实附件下载
  python test_note_attachment.py --upload     # 额外尝试 upload_bytes（mimeType 需 image/*）

权威契约（2026-10-26 live）：
  - 附件表在 **extraInfo JSON 字符串** 的 `attachments:[{fileId,mimeType,digest}]`
  - fileId = `{userId}.{22b64url}`，下载主键
  - digest = 文件 sha1 = content 里 `com.miui.notes/image/{digest}`
  - 下载：api.micloud `/mic/file/v2/user/full?fileId&type=note_img` → RC4
          或 FileApi.download_bytes（字节级一致）

sid=micloud，免 miclaw 额度 / 50102 可用。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 用你自己的 fileId 替换（从 .runtime/notes_pc_pull.json 的 attachments[] 取）。
# 示例格式: "<userId>.<22位b64url>"。切勿提交真实账号数据。
HIST_FID = os.environ.get("NOTE_TEST_FID", "")
FID_RE = re.compile(r"\d{6,}\.[A-Za-z0-9_-]{16,}")
IMG_RE = re.compile(r"com\.miui\.notes/image/([0-9a-f]{8,})")


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def _rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for by in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(by ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def file_v2_download(auth: dict, file_id: str, ftype: str = "note_img"):
    """api.micloud /mic/file/v2/user/full → (meta, 明文字节)。三层嵌套。"""
    from noteapi_pc import Client
    import urllib.request
    cli = Client(auth, host="api.micloud.xiaomi.net")
    r = cli.get("/mic/file/v2/user/full", {"fileId": str(file_id), "type": ftype})
    d = (((r.get("data") or {}).get("data") or {}).get("data") or {})
    sk = d.get("secure_key")
    key = bytes.fromhex(sk) if sk else None
    out = b""
    for b in (d.get("blocks") or []):
        urls = b.get("urls") or []
        if not urls:
            continue
        raw = urllib.request.urlopen(urls[0], timeout=60).read()
        out += _rc4(raw, key) if key else raw
    meta = {
        "fileId": d.get("fileId"),
        "secure_key": sk,
        "blocks": len(d.get("blocks") or []),
        "code": ((r.get("data") or {}).get("code")),
        "reason": ((r.get("data") or {}).get("reason")),
    }
    return meta, out


def parse_extra_attachments(entry: dict) -> list:
    extra = entry.get("extraInfo")
    obj = extra if isinstance(extra, dict) else None
    if obj is None and isinstance(extra, str) and extra.strip():
        try:
            obj = json.loads(extra)
        except Exception:
            obj = None
    if not isinstance(obj, dict):
        return []
    return [a for a in (obj.get("attachments") or []) if isinstance(a, dict)]


def main() -> int:
    do_upload = "--upload" in sys.argv
    from noteapi_pc import Client, NotesApi, FileApi, _payload
    from mi_auth import get_credentials

    cred = get_credentials()
    if not cred:
        print("FAIL: 无 micloud 凭据")
        return 1
    auth = {"token": cred["token"], "ssecurity": cred["ssecurity"],
            "cUserId": cred["cUserId"], "userId": cred["userId"]}
    cli = Client(auth)
    api = NotesApi(cli)
    fa = FileApi(cli)
    fails = []

    # 1) 全量扫 extraInfo.attachments
    print("== 1) 全量扫 extraInfo.attachments ==")
    entries, sync = [], "0"
    for _ in range(8):
        r = api.list_full(sync_tag=sync, limit=100)
        p = _payload(r)
        ents = p.get("entries") or []
        entries.extend(ents)
        if p.get("lastPage") in (True, 1, "1", "true") or not ents:
            break
        sync = str(p.get("syncTag") or "")
    print(f"entries={len(entries)}")
    all_att = []
    for e in entries:
        atts = parse_extra_attachments(e)
        if atts:
            all_att.append({
                "note_id": str(e.get("id")),
                "subject": str(e.get("subject") or "")[:40],
                "n": len(atts),
                "sample": atts[0],
            })
    print(f"notes_with_attachments={len(all_att)} total_atts={sum(x['n'] for x in all_att)}")
    for row in all_att[:5]:
        print(" ", json.dumps(row, ensure_ascii=False)[:240])
    if not all_att:
        fails.append("no attachments found in extraInfo")

    # 2) 历史 fileId（规格 24 金样，2026-10-08 上传）
    print("\n== 2) 历史 fileId /mic/file/v2 ==")
    try:
        meta, raw = file_v2_download(auth, HIST_FID)
        ok = meta.get("code") == 0 and len(raw) > 0
        print(f"code={meta.get('code')} len={len(raw)} sha1={_sha1(raw)} head={raw[:8].hex()}")
        if not ok:
            fails.append("hist download fail")
    except Exception as e:
        print(f"FAIL hist: {type(e).__name__}: {e}")
        fails.append(f"hist:{e}")

    # 3) 真实笔记附件：digest 对齐 + 双路径一致
    print("\n== 3) 真实笔记附件闭环 ==")
    if all_att:
        sample = all_att[0]["sample"]
        fid = sample.get("fileId")
        digest = sample.get("digest") or ""
        try:
            meta, raw = file_v2_download(auth, fid)
            sh = _sha1(raw)
            print(f"fileId={fid} digest={digest} sha1={sh} len={len(raw)} "
                  f"head={raw[:8].hex() if raw else ''}")
            print(f"  digest==sha1 ? {digest == sh}")
            raw2 = fa.download_bytes(fid)
            print(f"  FileApi.download_bytes eq ? {raw2 == raw} len={len(raw2)}")
            if digest and digest != sh:
                fails.append("digest != downloaded sha1")
            if raw2 != raw:
                fails.append("FileApi vs file/v2 mismatch")
            out = Path("../03-实测证据/exports") / f"note_att_{fid.split('.')[-1][:12]}.bin"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(raw)
            print(f"  saved {out} {out.stat().st_size}B")
        except Exception as e:
            print(f"FAIL real att: {type(e).__name__}: {e}")
            fails.append(f"real:{e}")
    else:
        fails.append("skip real att (none)")

    # 4) MCP 封装面（直接 import，不经 stdio）
    print("\n== 4) MCP 工具面 ==")
    try:
        import xiaoai_mcp as xm
        if all_att:
            nid = all_att[0]["note_id"]
            s1 = xm.xiaoai_note_attachments(nid)
            j1 = json.loads(s1)
            print("xiaoai_note_attachments ok=", j1.get("ok"), "count=", j1.get("count"))
            if not j1.get("ok") or not j1.get("count"):
                fails.append("mcp note_attachments")
            else:
                fid = j1["attachments"][0]["fileId"]
                s2 = xm.xiaoai_note_attachment_download(fid)
                j2 = json.loads(s2)
                print("xiaoai_note_attachment_download ok=", j2.get("ok"),
                      "size=", j2.get("size"), "sha1=", j2.get("sha1"))
                if not j2.get("ok"):
                    fails.append("mcp note_attachment_download")
        else:
            print("(skip mcp, no att)")
    except Exception as e:
        print(f"FAIL mcp: {type(e).__name__}: {e}")
        fails.append(f"mcp:{e}")

    # 5) 可选 upload（mimeType 必须 image/*，.txt 会 10008 bad mimeType）
    if do_upload:
        print("\n== 5) upload_bytes（可选）==")
        try:
            payload = b"\xff\xd8\xff\xe0" + b"NOTE-ATT-UP-20261026\n" + b"x" * 200
            up = fa.upload_bytes(payload, "probe_20261026.jpg")
            fid = up.get("fileId")
            print("upload fileId", fid, "digest", up.get("digest"))
            if fid:
                meta, raw = file_v2_download(auth, fid)
                print("roundtrip eq", raw == payload, "len", len(raw))
        except Exception as e:
            print(f"WARN upload: {type(e).__name__}: {e}")

    print("\n==== RESULT ====")
    if fails:
        print("FAIL:", fails)
        return 1
    print("PASS: note 附件 fileId 下载闭环 OK（extraInfo.attachments + file/v2 RC4）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
