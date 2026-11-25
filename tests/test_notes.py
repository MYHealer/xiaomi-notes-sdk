#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PC 可测：云笔记/待办 免费轨（findings §5.29）。

用法:
  python test_notes.py              # live：list + 取一条 detail + todo_list
  python test_notes.py "ESP"        # live：带关键词过滤

不烧 miclaw 额度、50102 可用。协议权威 noteapi_pc.py。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    kw = sys.argv[1] if len(sys.argv) > 1 else ""

    # 直接调 noteapi_pc（不经 MCP 进程，便于单测）
    from noteapi_pc import Client, NotesApi, TodoApi, _payload
    from mi_auth import get_credentials

    cred = get_credentials()
    if not cred:
        print("FAIL: 无 micloud 凭据")
        return 1
    auth = {"token": cred["token"], "ssecurity": cred["ssecurity"],
            "cUserId": cred["cUserId"], "userId": cred["userId"]}
    cli = Client(auth)
    api = NotesApi(cli)
    todo = TodoApi(cli)

    # 1) list
    r = api.list_full(limit=20)
    payload = _payload(r)
    entries = payload.get("entries") or []
    print(f"list status={r.get('status')} entries={len(entries)} "
          f"lastPage={payload.get('lastPage')}")
    if not entries:
        print("FAIL: 无笔记条目")
        print(json.dumps(r, ensure_ascii=False)[:500])
        return 1

    notes = entries
    if kw:
        notes = [e for e in entries
                 if kw.lower() in " ".join(str(e.get(k) or "") for k in
                                           ("subject", "snippet", "content")).lower()]
        print(f"filter {kw!r} -> {len(notes)}")
        if not notes:
            print("WARN: 关键词无命中，改用第一条验证 detail")

    e0 = notes[0] if notes else entries[0]
    nid = str(e0.get("id") or "")
    print(f"  sample id={nid} subject={str(e0.get('subject') or '')[:60]!r} "
          f"content_len={len(e0.get('content') or '')}")

    # 2) detail
    if not nid.isdigit():
        print(f"FAIL: id 非数字 {nid!r}")
        return 1
    d = api.detail(nid)
    dp = _payload(d)
    entry = dp.get("entry") or dp
    if isinstance(entry, dict) and "content" not in entry and "subject" not in entry:
        for k in ("data", "note", "result"):
            if isinstance(dp.get(k), dict):
                entry = dp[k]
                break
    content = entry.get("content") or ""
    subject = entry.get("subject") or ""
    print(f"detail status={d.get('status')} subject={subject[:60]!r} "
          f"content_len={len(content)}")
    detail_ok = bool(subject or content)

    # 3) todos
    tr = todo.sync(limit=10)
    tp = _payload(tr)
    recs = tp.get("records") or []
    print(f"todo status={tr.get('status')} records={len(recs)} "
          f"hasMore={tp.get('hasMore')}")
    for x in recs[:5]:
        cj = x.get("contentJson") or {}
        ent = cj.get("entity") if isinstance(cj.get("entity"), dict) else cj
        print(f"  [ {'✓' if ent.get('isFinish') else ' '} ] "
              f"{str(ent.get('plainText') or '')[:50]!r}")

    ok = bool(entries) and detail_ok

    # 4) gallery（同套 micloud 凭据）
    try:
        from galleryapi_pc import GalleryApi, HOST
        g = GalleryApi(Client(auth, host=HOST))
        q = g.quota()
        qp = _payload(q) if False else ((q.get("data") or {}).get("data") or {})
        # quota 结构：data.data 是业务体
        if not qp:
            qp = (q.get("data") or {})
            if isinstance(qp.get("data"), dict):
                qp = qp["data"]
        total = qp.get("total") or 0
        print(f"gallery quota status={q.get('status')} total={total} "
              f"vip={qp.get('vipLevel')}")
        gr = g.list_all(sync_tag="0", limit=3)
        gp = (gr.get("data") or {}).get("data") or {}
        photos = gp.get("content") or []
        print(f"gallery list status={gr.get('status')} photos={len(photos)}")
        if photos:
            print(f"  photo0 id={photos[0].get('id')} "
                  f"name={str(photos[0].get('fileName') or '')[:40]!r}")
        gallery_ok = bool(total) and (gr.get("status", "").find("200") >= 0 or photos)
        ok = ok and gallery_ok
    except Exception as e:
        print(f"gallery section FAIL: {type(e).__name__}: {e}")
        # 笔记已 PASS 时相册失败不整体否决，但标记
        print("WARN: gallery 未通过（笔记结果仍有效）")

    print("TEST_NOTES:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
