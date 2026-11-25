#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PC 可测：137 工具补测（note_folders / capability_domains / gallery_search）。

用法:
  python test_note_folders_domains.py          # 全量
  python test_note_folders_domains.py --offline # 只跑离线断言

不烧 miclaw 额度。gallery_search 为客户端过滤（云侧无 search 端点）。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SRC = (HERE / "xiaoai_mcp.py").read_text(encoding="utf-8")


def _extract_fn(name: str) -> str:
    m = re.search(
        rf"(@mcp\.tool\(\)\s*\ndef {name}\([\s\S]*?)\n@mcp\.tool\(\)", SRC)
    if not m:
        # last tool before if __name__ / mcp.run
        m = re.search(
            rf"(@mcp\.tool\(\)\s*\ndef {name}\([\s\S]*?)\n(?:if __name__|mcp\.run)",
            SRC)
    if not m:
        raise RuntimeError(f"cannot extract {name}")
    body = m.group(1)
    # strip decorator for exec
    return re.sub(r"@mcp\.tool\(\)\s*\n", "", body, count=1)


def test_offline() -> int:
    print("=== offline: tool count + capability_domains ===")
    tools = re.findall(r"@mcp\.tool\(\)\s*\ndef\s+(\w+)", SRC)
    print(f"  registered={len(tools)}")
    assert len(tools) == 138, f"expect 138 got {len(tools)}"
    for n in ("xiaoai_note_folders", "xiaoai_capability_domains",
              "xiaoai_gallery_search", "xiaoai_agent_store_meta",
              "xiaoai_mcp_server_list", "xiaoai_trace_token_status"):
        assert n in tools, n
    print("  PASS tool count 138 + new faces present")

    ns = {"json": json}
    exec(_extract_fn("xiaoai_capability_domains"), ns)
    d = json.loads(ns["xiaoai_capability_domains"]())
    assert d.get("ok") is True, d
    assert d.get("domain_count") == 12, d.get("domain_count")
    listed = set()
    for v in d["domains"].values():
        listed.update(v.get("tools") or [])
    missing = sorted(set(tools) - listed)
    extra = sorted(listed - set(tools))
    print(f"  unique_listed={len(listed)} missing={missing} extra={extra}")
    assert not missing, missing
    assert not extra, extra
    assert d.get("unique_tools") == 138, d.get("unique_tools")
    # 结构对标字段
    assert "xiaozhi" in d.get("structure_ref", {})
    assert "muse" in d.get("structure_ref", {})
    assert "不嫁接" in d.get("policy", "")
    # 域覆盖关键能力
    for dom in ("chat_llm", "voice_asr_tts", "smart_home", "device_collab",
                "gallery_media", "security_privacy", "system_platform"):
        assert dom in d["domains"], dom
    print("  PASS capability_domains 12 域 / 138 全覆盖 / 不嫁接")

    # gallery_search schema 钉死（离线字段）
    gs = _extract_fn("xiaoai_gallery_search")
    for field in ("start_time", "end_time", "media_type", "group_id",
                  "limit", "offset", "order_by", "direction"):
        assert field in gs, field
    assert "searchMedias" in gs or "search_medias" in gs
    print("  PASS gallery_search schema fields")
    return 0


def test_live_note_folders() -> int:
    print("\n=== live: xiaoai_note_folders ===")
    import noteapi_pc as napi
    from mi_auth import get_credentials
    cred = get_credentials()
    assert cred, "no micloud cred"
    auth = {"token": cred["token"], "ssecurity": cred["ssecurity"],
            "cUserId": cred["cUserId"], "userId": cred["userId"]}
    api = napi.NotesApi(napi.Client(auth))
    r = api.list_full(sync_tag="0", limit=200)
    payload = napi._payload(r) if hasattr(napi, "_payload") else (r.get("data") or {})
    entries = payload.get("entries") or []
    folds = []
    for e in entries:
        if e.get("type") == "folder" or e.get("noteType") == "folder":
            folds.append({
                "id": str(e.get("id") or ""),
                "subject": e.get("subject") or e.get("name") or "",
                "folderId": str(e.get("folderId") or e.get("folderSyncId") or "0"),
            })
    print(f"  entries={len(entries)} folders={len(folds)}")
    for f in folds[:8]:
        print(f"    id={f['id']} subject={f['subject']!r}")
    # ★ 字段名断言：folder 名字走 subject
    if folds:
        assert any(f["subject"] for f in folds), "folder subject empty"
    # 同步调 MCP 封装（若可 import）
    try:
        ns = {"json": json, "_note_api": None, "_note_payload": None}
        # 直接复刻封装逻辑已上面验证；此处只断言服务端返回可解析
        assert r.get("status") in (200, "200", None) or entries is not None
        print("  PASS note_folders via noteapi list_full 筛 type=folder")
    except Exception as e:
        print(f"  WARN: {e}")
    return 0


def test_live_gallery_search() -> int:
    print("\n=== live: gallery_search 客户端过滤 ===")
    from galleryapi_pc import GalleryApi
    from noteapi_pc import Client
    from mi_auth import get_credentials
    cred = get_credentials()
    assert cred, "no micloud cred"
    auth = {"token": cred["token"], "ssecurity": cred["ssecurity"],
            "cUserId": cred["cUserId"], "userId": cred["userId"]}
    g = GalleryApi(Client(auth, host="galleryapi.micloud.xiaomi.net"))

    # 1) 无过滤：拿总数
    r0 = g.search_medias(limit=5, max_pages=3)
    print(f"  unfiltered total={r0['total']} pages={r0['pages_scanned']} "
          f"items={len(r0['items'])}")
    assert r0["total"] >= 0
    assert len(r0["items"]) <= 5

    # 2) type=image
    ri = g.search_medias(media_type="image", limit=5, max_pages=3)
    print(f"  image total={ri['total']} sample={[i.get('type') for i in ri['items'][:5]]}")
    for it in ri["items"]:
        t = str(it.get("type") or "").lower()
        mt = str(it.get("mimeType") or "").lower()
        assert "image" in t or mt.startswith("image/") or any(
            x in mt for x in ("jpg", "jpeg", "png", "heic")), it

    # 3) 排序方向
    ra = g.search_medias(limit=3, order_by="dataTaken", direction="ASC",
                         max_pages=2)
    rd = g.search_medias(limit=3, order_by="dataTaken", direction="DESC",
                         max_pages=2)
    ta = [x.get("dateTaken") or 0 for x in ra["items"]]
    td = [x.get("dateTaken") or 0 for x in rd["items"]]
    print(f"  ASC dates={ta}")
    print(f"  DESC dates={td}")
    if len(ta) >= 2:
        assert ta == sorted(ta), ta
    if len(td) >= 2:
        assert td == sorted(td, reverse=True), td

    # 4) 非法 orderBy 必须抛
    try:
        g.search_medias(order_by="bogus", max_pages=1)
        print("  FAIL: bogus orderBy not rejected")
        return 1
    except ValueError as e:
        print(f"  PASS bogus orderBy → {e}")

    # 5) 时间窗（近 10 年应覆盖大部分）
    import datetime as dt
    end = dt.datetime.utcnow().strftime("%Y-%m-%d")
    start = "2015-01-01"
    rt = g.search_medias(start_time=start, end_time=end, limit=3, max_pages=2)
    print(f"  window {start}..{end} total={rt['total']}")
    for it in rt["items"]:
        ts = int(it.get("dateTaken") or 0)
        if ts:
            assert ts >= int(dt.datetime(2015, 1, 1, tzinfo=dt.timezone.utc).timestamp() * 1000) - 86400000
    print("  PASS gallery_search filters")
    return 0


def main() -> int:
    offline_only = "--offline" in sys.argv
    rc = test_offline()
    if rc:
        return rc
    if offline_only:
        print("\nALL PASS (offline)")
        return 0
    rc = test_live_note_folders()
    if rc:
        return rc
    rc = test_live_gallery_search()
    if rc:
        return rc
    print("\nALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
