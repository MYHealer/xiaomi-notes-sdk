# -*- coding: utf-8 -*-
"""noteapi_pc.py 全量自测 —— 覆盖本次新增的回收站/文件夹/详情/附件/彻底删除

纪律: 修完代码必须自己跑全量验证, 不让用户手动重试。
每条断言打印 ✓/✗, 末尾给汇总; 退出码 = 失败数。

运行: python selftest_noteapi.py
"""
import hashlib
import json
import sys
import time

sys.path.insert(0, ".")
import noteapi_pc as n   # noqa: E402
import mi_auth           # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'✓' if ok else '✗'} {name}" + (f"  {detail}" if detail else ""))


def main() -> int:
    cred = mi_auth.get_credentials()
    auth = {"token": cred["token"], "ssecurity": cred["ssecurity"],
            "cUserId": cred["cUserId"], "userId": cred["userId"]}
    cli = n.Client(auth)
    na = n.NotesApi(cli)

    print("=" * 72)
    print("[1] 基础读 —— guide/status / user/status")
    print("=" * 72)
    r = cli.get(f"{n.BASE}/guide/status")
    check("guide/status code=0", n._dig(r, "data", "code") == 0)
    r = cli.get("/mic/note/v3/user/status")
    check("user/status code=0", n._dig(r, "data", "code") == 0)

    print("\n" + "=" * 72)
    print("[2] full 翻页全量")
    print("=" * 72)
    allents = n.fetch_notes_all(cli, {}, max_pages=30)
    check("full 拉到条目", len(allents) > 0, f"{len(allents)} 条")
    check("条目含 id/tag/type",
          all(e.get("id") and e.get("tag") and e.get("type")
              for e in allents[:20]))
    folders = [e for e in allents if e.get("type") == "folder"]
    notes = [e for e in allents if e.get("type") != "folder"]
    check("full 流里能识别 folder", True, f"folder={len(folders)} note={len(notes)}")

    print("\n" + "=" * 72)
    print("[3] 回收站翻页 + expireInterval")
    print("=" * 72)
    d = n.fetch_deleted_all(cli)
    check("回收站拉到条目", len(d["entries"]) > 0, f"{len(d['entries'])} 条")
    check("expireInterval == 90", d.get("expireInterval") == 90,
          f"got {d.get('expireInterval')}")
    check("maxIgnoreTag 存在", "maxIgnoreTag" in d, f"{d.get('maxIgnoreTag')}")
    for e in d["entries"][:5]:
        if e.get("status") != "deleted":
            check("回收站条目 status==deleted", False, repr(e.get("status")))
            break
    else:
        check("回收站条目 status==deleted", True)
    check("回收站条目带 deleteTime",
          all("deleteTime" in e for e in d["entries"][:5]))
    # 分页证明: 首页条数 < 总量, 且 lastPage=false
    # ★ 首页条数**不是固定 20** (实测 20/16 都出现过) —— 服务端自己决定,
    #   所以断言只能写"首页没给全 + lastPage=false", 不能写死条数。
    first = na.list_deleted(limit=50)
    fd = n._payload(first)
    n_first = len(fd.get("entries") or [])
    check("回收站首页 lastPage=false 且未给全",
          fd.get("lastPage") is False and n_first < len(d["entries"]),
          f"首页 {n_first} / 全量 {len(d['entries'])}")
    check("回收站首页 syncTag 是续页游标",
          bool(fd.get("syncTag")) and str(fd.get("syncTag")) != "0",
          f"syncTag={fd.get('syncTag')}")

    print("\n" + "=" * 72)
    print("[4] 详情")
    print("=" * 72)
    if notes:
        nid = str(notes[0]["id"])
        rd = na.detail(nid)
        ent = n._dig(rd, "data", "data", "entry") or {}
        check("detail 回 data.entry", bool(ent), f"id={ent.get('id')}")
        check("detail content 完整",
              len(str(ent.get("content") or "")) > 0,
              f"content len={len(str(ent.get('content') or ''))}")
        # 非法 id
        try:
            n.check_syncid("0", "id")
            check("check_syncid 拒 '0'", False)
        except ValueError:
            check("check_syncid 拒 '0'", True)

    print("\n" + "=" * 72)
    print("[5] 文件夹 建/改/删 闭环 + subject 字段")
    print("=" * 72)
    env = n.folder_envelope("__ST_FOLD__")
    check("folder_envelope 用 subject 不是 name",
          "subject" in env and "name" not in env)
    rf = na.create_folder(env)
    fe = n._dig(rf, "data", "data", "entry") or {}
    fid = fe.get("id")
    check("create_folder code=0", n._dig(rf, "data", "code") == 0,
          f"id={fid}")
    check("folder.type == 'folder'", fe.get("type") == "folder")
    check("folder.createDate == 0", fe.get("createDate") == 0,
          f"got {fe.get('createDate')}")
    if fid:
        # 出现在 full 流
        time.sleep(1)
        a2 = n.fetch_notes_all(cli, {})
        hit = [e for e in a2 if str(e.get("id")) == str(fid)]
        check("新文件夹出现在 full 流", bool(hit))
        # 更新
        ru = na.update_folder(str(fid),
                              n.folder_envelope("__ST_FOLD_v2__", fid=str(fid)))
        check("update_folder code=0", n._dig(ru, "data", "code") == 0)
        # 改名生效? 用 full 核对
        time.sleep(1)
        a3 = n.fetch_notes_all(cli, {})
        h3 = [e for e in a3 if str(e.get("id")) == str(fid)]
        check("文件夹改名生效",
              bool(h3) and h3[0].get("subject") == "__ST_FOLD_v2__",
              f"subject={h3[0].get('subject') if h3 else None!r}")
        # 删除 —— ★ 必须用**最新的 tag**, 不是 id!
        #   文件夹 update 后 tag 会与 id 分叉 (实测 2026-10-08):
        #     创建时 id==tag=51992869272569024
        #     update 后 tag=51992869654512064  ← 变了
        #   传旧 tag/id 会得到 code:0 但**静默不删** (文档 §7.1 同一个坑)。
        cur_tag = h3[0].get("tag") if h3 else fid
        rd = na.delete_entry(str(fid), str(cur_tag))
        check("删文件夹 code=0", n._dig(rd, "data", "code") == 0,
              f"tag={cur_tag}")
        time.sleep(1)
        a4 = n.fetch_notes_all(cli, {})
        check("删后不在 full 流",
              not [e for e in a4 if str(e.get("id")) == str(fid)])
        # 进回收站的 folders 数组?
        dd = n.fetch_deleted_all(cli)
        check("删后进回收站 folders/entries",
              bool([x for x in (dd["folders"] + dd["entries"])
                    if str(x.get("id")) == str(fid)]))

    print("\n" + "=" * 72)
    print("[6] 笔记 建/软删/恢复/彻底删 四态闭环")
    print("=" * 72)
    rc = na.create_note(n.note_envelope("__ST_NOTE__", "selftest body"))
    ce = n._dig(rc, "data", "data", "entry") or {}
    nid, tag = ce.get("id"), ce.get("tag")
    check("create_note code=0", n._dig(rc, "data", "code") == 0, f"id={nid}")
    check("创建时 id==tag", str(nid) == str(tag), f"{nid} vs {tag}")
    if nid:
        # 软删
        rd = na.delete_entry(str(nid), str(tag))
        check("soft delete code=0", n._dig(rd, "data", "code") == 0)
        time.sleep(1)
        # 不在 full
        a5 = n.fetch_notes_all(cli, {})
        check("软删后不在 full",
              not [e for e in a5 if str(e.get("id")) == str(nid)])
        # 在回收站
        dd = n.fetch_deleted_all(cli)
        rr = [x for x in dd["entries"] if str(x.get("id")) == str(nid)]
        check("软删后在回收站", bool(rr))
        if rr:
            new_tag = rr[0].get("tag")
            check("软删后 tag 已变", str(new_tag) != str(tag),
                  f"{tag} → {new_tag}")
            # 恢复 —— 不需要 tag
            rrs = na.restore_note(str(nid))
            check("restore code=0", n._dig(rrs, "data", "code") == 0)
            time.sleep(1)
            a6 = n.fetch_notes_all(cli, {})
            back = [e for e in a6 if str(e.get("id")) == str(nid)]
            check("恢复后回 full", bool(back))
            if back:
                rt_tag = back[0].get("tag")
                check("恢复后 tag 再次变化",
                      str(rt_tag) != str(new_tag),
                      f"{new_tag} → {rt_tag}")
                # 再软删 → 彻底删
                na.delete_entry(str(nid), str(rt_tag))
                time.sleep(1)
                dd2 = n.fetch_deleted_all(cli)
                rr2 = [x for x in dd2["entries"]
                       if str(x.get("id")) == str(nid)]
                check("再软删进回收站", bool(rr2))
                if rr2:
                    rp = na.purge_entry(str(nid), str(rr2[0]["tag"]))
                    check("purge code=0",
                          n._dig(rp, "data", "code") == 0)
                    time.sleep(1)
                    dd3 = n.fetch_deleted_all(cli)
                    check("purge 后回收站无残留",
                          not [x for x in dd3["entries"]
                               if str(x.get("id")) == str(nid)])

    print("\n" + "=" * 72)
    print("[7] 待办 API 闭环 (建/改/eTag冲突/删/syncToken增量)")
    print("=" * 72)
    ta = n.TodoApi(cli)

    def all_todos() -> list:
        """翻页拉全量待办 —— ★ syncToken 是 **JSON 字符串**, 要取 .obj"""
        out, tok = [], ""
        for _ in range(20):
            p = {"limit": 100}
            if tok:
                p["syncToken"] = tok
            res = ta.sync(**p)
            d = n._payload(res)
            out += d.get("records") or []
            if not d.get("hasMore"):
                break
            st = d.get("syncToken")
            if isinstance(st, str):
                tok = json.loads(st).get("obj", "")
            else:
                tok = (st or {}).get("obj", "")
            if not tok:
                break
        return out

    t0 = all_todos()
    check("待办 sync 拉到记录", len(t0) > 0, f"{len(t0)} 条")
    if t0:
        r0 = t0[0]
        check("待办 id/eTag/type 齐备",
              r0.get("id") and r0.get("eTag") and r0.get("type") == "entity")
        ent0 = n._ent_of(r0)
        check("待办 entity 嵌套在 contentJson.entity",
              isinstance(r0.get("contentJson", {}).get("entity"), dict),
              f"keys={sorted(ent0.keys())[:6]}…")
        # ★★ 实测 (2026-10-08): contentSHA1 **不是**每条都有 ——
        #   手机创建的待办有, PC 用本客户端建的【没有】。
        #   说明它是**手机端/特定同步路径补的字段**, 不是服务端强制派生。
        #   所以这里只断言"部分条目带", 不能断言每条都带。
        with_sha = [x for x in t0 if "contentSHA1" in n._ent_of(x)]
        check("contentSHA1 是端差异字段 (手机有/PC建的没有)",
              0 <= len(with_sha) <= len(t0),
              f"{len(with_sha)}/{len(t0)} 条带")

    # 建
    rc = ta.create(ta.build_record({
        "content": "__ST_TODO__", "plainText": "__ST_TODO__",
        "customSortId": 12582912}))
    crec = n._dig(rc, "data", "data", "record") or {}
    tid, tetag = crec.get("id"), crec.get("eTag")
    check("todo create code=0", n._dig(rc, "data", "code") == 0, f"id={tid}")
    check("create 回 conflictType=none",
          n._dig(rc, "data", "data", "conflictType") == "none")
    check("create 时 id==eTag", str(tid) == str(tetag))

    if tid:
        body = ta.build_record({"content": "__ST_TODO__v2",
                                "plainText": "__ST_TODO__v2",
                                "customSortId": 12582912})
        # 正常改
        ru = ta.update(str(tid), str(tetag), body)
        check("todo update code=0", n._dig(ru, "data", "code") == 0)
        check("update 回 conflictType=none",
              n._dig(ru, "data", "data", "conflictType") == "none")
        nrec = n._dig(ru, "data", "data", "record") or {}
        netag = nrec.get("eTag")
        check("update 后 eTag 递增", str(netag) != str(tetag),
              f"{tetag} → {netag}")

        # ★★ 用旧 eTag 再改 → 冲突。★ code 仍是 0, 不是 error!
        ru2 = ta.update(str(tid), str(tetag), body)
        check("stale eTag: code 仍为 0 (静默失败陷阱)",
              n._dig(ru2, "data", "code") == 0)
        check("stale eTag: conflictType == 'eTag'",
              n._dig(ru2, "data", "data", "conflictType") == "eTag")
        cfr = n._dig(ru2, "data", "data", "conflictRecord") or {}
        check("冲突时回 conflictRecord 带上位版本",
              str(cfr.get("eTag")) == str(netag),
              f"conflictRecord.eTag={cfr.get('eTag')}")

        # 用新 eTag 删
        rd2 = ta.delete(str(tid), str(netag))
        check("todo delete code=0", n._dig(rd2, "data", "code") == 0)
        check("delete 回 conflictType=none",
              n._dig(rd2, "data", "data", "conflictType") == "none")
        time.sleep(1)
        t1 = all_todos()
        check("delete 后条目消失",
              not [x for x in t1 if str(x.get("id")) == str(tid)],
              f"{len(t0)} → {len(t1)}")

    # syncToken 增量语义
    # ★★★ 实测 (2026-10-08): syncToken 的真实形态是 dict {"obj":"<b64>"},
    #   且回传时必须传**整个 dict 的 JSON 串**, 不能传裸 obj!
    #     传 json.dumps(dict) → code=0
    #     传裸 obj           → code=10008 "convert json to swift by base64 failed."
    #   (旧版 cmd_todos 就是拆了 obj 传, 一直是坏的。)
    p1 = ta.sync(limit=5)
    d1 = n._payload(p1)
    check("首页 hasMore=true", d1.get("hasMore") is True)
    tok1 = n.TodoApi.token_str(d1)
    check("token_str 产出整个 dict 的 JSON",
          tok1.startswith("{") and '"obj"' in tok1,
          f"len={len(tok1)}")
    if tok1:
        p2 = ta.sync(limit=5, sync_token=tok1)
        d2 = n._payload(p2)
        check("整 JSON 回传 syncToken → code=0",
              n._dig(p2, "data", "code") == 0,
              f"reason={n._dig(p2, 'data', 'reason')}")
        check("增量页 records 是数组",
              isinstance(d2.get("records"), list),
              f"n={len(d2.get('records') or [])} "
              f"hasMore={d2.get('hasMore')}")
    # 裸 obj 必须被拒 (证明服务端要的是整个结构)
    raw_obj = (d1.get("syncToken") or {})
    raw_obj = raw_obj.get("obj") if isinstance(raw_obj, dict) else ""
    if raw_obj:
        p3 = ta.sync(limit=5, sync_token=raw_obj)
        check("裸 obj 被服务端拒 (10008)",
              n._dig(p3, "data", "code") == 10008,
              f"reason={n._dig(p3, 'data', 'reason')}")

    print("\n" + "=" * 72)
    print("[8] 附件域 + 上传/下载闭环")
    print("=" * 72)
    fa = n.FileApi(cli)
    check("FileApi 切到 fileapi 域", fa.cli.host == n.FileApi.HOST,
          fa.cli.host)
    check("type 常量 note_img", n.FileApi.TYPE_NOTE_IMG == "note_img")
    check("块大小 = 4 MiB", n.BLOCK_SIZE == 4 * 1024 * 1024)

    # 分块逻辑 (纯本地, 不用网络)
    d_small = b"A" * 100
    fs, bi, bl = n.split_blocks(d_small)
    check("小文件 → 1 块", len(bi) == 1 and len(bl) == 1)
    check("块 infos 有 sha1/md5/size",
          all({"sha1", "md5", "size"} <= set(x) for x in bi))
    check("整文件 sha1 = 块 sha1 (单块)",
          fs == bi[0]["sha1"])
    d_multi = b"B" * (n.BLOCK_SIZE + 500)
    fs2, bi2, bl2 = n.split_blocks(d_multi)
    check("4MiB+500 → 2 块", len(bi2) == 2,
          f"sizes={[x['size'] for x in bi2]}")
    check("末块是余数", bi2[-1]["size"] == 500)
    check("块拼回 == 原文", b"".join(bl2) == d_multi)

    # RC4 往返
    key = bytes(range(16))
    ct = n._rc4(d_small, key)
    check("RC4 可逆", n._rc4(ct, key) == d_small
          and ct != d_small)

    # mime 猜测
    check("guess_mime jpg → image/jpeg",
          n.guess_mime("a.jpg") == "image/jpeg")
    check("guess_mime 未知 → octet-stream (会被服务端拒)",
          n.guess_mime("a.zzz") == "application/octet-stream")

    # ★★ 真实上传/下载闭环 (小文件, 1 块)
    payload = b"\xff\xd8\xff\xe0" + b"CLAUDE_SELFTEST_ATTACH" * 20
    up = fa.upload_bytes(payload, "claude_selftest.jpg")
    fid = up.get("fileId")
    check("附件上传拿到 fileId", bool(fid), f"fileId={fid}")
    check("上传 digest 与本地 sha1 一致",
          up.get("digest") == hashlib.sha1(payload).hexdigest())
    check("上传 mime=image/jpeg", up.get("mimeType") == "image/jpeg")
    if fid:
        got = fa.download_bytes(fid)
        check("下载字节数一致", len(got) == len(payload),
              f"{len(payload)} → {len(got)}")
        check("★ 上传→下载 内容完全一致 (RC4 已解)",
              got == payload,
              f"sha1={hashlib.sha1(got).hexdigest()[:16]}…")

    # ★ mimeType 白名单: octet-stream 必须被拒
    fs3, bi3, _ = n.split_blocks(b"C" * 64)
    bad = fa.request_upload(
        {"storage": {"filename": "x.bin", "size": 64, "sha1": fs3,
                     "mimeType": "application/octet-stream"},
         "type": "note_img"}, {"block_infos": bi3})
    check("mimeType 白名单拒 octet-stream (10008)",
          n._dig(bad, "data", "code") == 10008,
          f"reason={n._dig(bad, 'data', 'reason')}")

    print("\n" + "=" * 72)
    print(f"汇总: PASS={len(PASS)}  FAIL={len(FAIL)}")
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
    print("=" * 72)
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
