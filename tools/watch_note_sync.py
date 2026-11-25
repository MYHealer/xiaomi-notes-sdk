"""
笔记同步请求哨兵 —— 持续监视 hyperConnect 内存, 捕捉【真实的】noteapi 请求报文

为什么用这个方法:
  之前用「读规范 → 自己拼请求 → 打过去」的方式, 全部 401。
  但 PC 端互联服务【此刻正在成功同步笔记】(本地 102 篇就是它同步来的),
  所以真实报文必然存在于进程内存中。抓它, 而不是猜它。

监视目标（全部是 noteapi 请求的特征）:
  1. 完整 HTTP 头块, 含 Cookie: userId=...; serviceToken=...
  2. X-XIAOMI-SUPPORT-REDIRECT / X-Request-Id
  3. noteapi 的完整 URL（含加密后的 query 参数）
  4. 任何形式的 Authorization 头（Basic / Bearer）

哨兵模式:
  持续轮询, 一旦某段内存里同时出现「noteapi URL」+「serviceToken」,
  就说明捕捉到了一次真实请求, 立即完整落盘。

用法:
  python watch_note_sync.py --watch [秒数]    # 持续监视（默认 180s）
  python watch_note_sync.py --snapshot        # 单次快照
"""

from __future__ import annotations

import ctypes
import io
import json
import os
import re
import sys
import time
from typing import Dict, List, Set, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "pnl", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "probe_notes_live.py"))
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)

RUNTIME = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".runtime")

# ══════════════════════════════════════════════════════════════════
# ★ 捕捉模式：请求报文的关键结构
# ══════════════════════════════════════════════════════════════════
PATS = {
    # 完整 noteapi URL（含 query，暴露参数结构）
    "note_url":   re.compile(rb"noteapi\.micloud\.xiaomi\.net[\x21-\x7e]{0,300}"),
    # HTTP 头块（连续的 Header: value 行）
    "hdr_block":  re.compile(
        rb"(?:[A-Za-z][A-Za-z0-9\-]{2,30}:\s*[\x20-\x7e]{1,400}\r?\n){2,25}"),
    # cookie 组合（服务端下发的完整形态）
    "setcookie":  re.compile(rb"Set-Cookie:\s*([^\r\n]{5,400})", re.I),
    # 认证头
    "authz":      re.compile(rb"(?:Authorization|authorization):\s*([\x20-\x7e]{8,600})"),
    # 加密后的参数（base64 长串 + signature）
    "signature":  re.compile(rb"signature=([A-Za-z0-9+/=_\-]{20,120})"),
    # 加密参数样本
    "enc_param":  re.compile(rb"(syncTag|limit|entry|ckey|filterTag)=([A-Za-z0-9+/=_\-]{16,400})"),
}

#: 判定「这是一次真实 noteapi 请求」的联合条件
def is_note_request(blob: str) -> bool:
    low = blob.lower()
    return ("noteapi.micloud.xiaomi.net" in low
            and ("servicetoken" in low or "signature" in low))


def snapshot() -> Dict[str, Set[str]]:
    """扫一遍全部进程, 返回命中的模式"""
    out: Dict[str, Set[str]] = {k: set() for k in PATS}
    for pid, name in m.find_pids():
        h = m.k32.OpenProcess(0x0400 | 0x0010, False, pid)
        if not h:
            continue
        try:
            for base, size in m.enum_regions(h):
                data = m.read_block(h, base, size)
                if not data:
                    continue
                # 快速预筛：只有含 noteapi 的块才细看
                if b"noteapi" not in data and b"serviceToken" not in data:
                    continue
                for k, rx in PATS.items():
                    for mm in rx.finditer(data):
                        try:
                            t = (mm.group(1) if mm.groups() else mm.group(0))
                            s = t.decode("utf-8", "replace")
                        except Exception:
                            continue
                        out[k].add(s)
        finally:
            m.k32.CloseHandle(h)
    return out


def redact(s: str) -> str:
    """脱敏：保留结构, 抹掉凭据本体"""
    s = re.sub(r"(serviceToken=)[A-Za-z0-9+/=_\-\.%]{12,}", r"\1<TOKEN>", s)
    s = re.sub(r"(cUserId=)[A-Za-z0-9+/=_\-]{8,}", r"\1<CID>", s)
    s = re.sub(r"(userId=)\d+", r"\1<UID>", s)
    s = re.sub(r"(Authorization:\s*)(\S+)\s+([A-Za-z0-9+/=_\-.%]{12,})",
               r"\1\2 <CRED>", s, flags=re.I)
    return s


def report(hits: Dict[str, Set[str]], label: str) -> int:
    note_reqs = [t for t in hits["hdr_block"] if is_note_request(t)]
    print(f"\n{'='*72}")
    print(f"  [{label}] 命中统计")
    print(f"{'='*72}")
    for k, v in hits.items():
        print(f"    {k:12s} {len(v):4d}")
    print(f"    ★ 真实 noteapi 请求头块: {len(note_reqs)}")

    if hits["note_url"]:
        print("\n  ── noteapi URL（参数结构）──")
        for u in sorted(hits["note_url"])[:8]:
            print(f"     {u[:230]}")

    if note_reqs:
        print("\n  ★★ 真实 noteapi 请求头块（已脱敏）:")
        for i, b in enumerate(note_reqs[:5]):
            print(f"\n  ┌─ [{i}] " + "─" * 60)
            for line in redact(b).splitlines():
                print(f"  │ {line[:200]}")
            print("  └" + "─" * 64)

    if hits["authz"]:
        print("\n  ── Authorization 头 ──")
        for a in sorted(hits["authz"])[:6]:
            print(f"     {redact(a)[:190]}")

    if hits["signature"]:
        print("\n  ── signature 样本 ──")
        for s in sorted(hits["signature"])[:5]:
            print(f"     len={len(s):4d} {s[:70]}")

    if hits["enc_param"]:
        print("\n  ── 加密参数样本（看密文长度分布）──")
        by = {}
        for p in hits["enc_param"]:
            k = p.split("=", 1)[0]
            v = p.split("=", 1)[1] if "=" in p else ""
            by.setdefault(k, set()).add(len(v))
        for k, lens in sorted(by.items()):
            print(f"     {k:12s} 密文长度分布 {sorted(lens)}")

    return len(note_reqs)


def main() -> int:
    os.makedirs(RUNTIME, exist_ok=True)
    if "--snapshot" in sys.argv:
        hits = snapshot()
        report(hits, "snapshot")
        return 0

    secs = 180
    if "--watch" in sys.argv:
        i = sys.argv.index("--watch")
        if i + 1 < len(sys.argv):
            try:
                secs = int(sys.argv[i + 1])
            except ValueError:
                pass

    print(f"★ 哨兵启动，监视 {secs}s")
    print("  → 现在请到「小米互联服务」里写一篇笔记（内容随便，标记用）")
    print("  → 写完保存，会触发向 noteapi 的同步请求")
    print()

    best: Dict[str, Set[str]] = {k: set() for k in PATS}
    t0 = time.time()
    rounds = 0
    found_at = None
    while time.time() - t0 < secs:
        rounds += 1
        hits = snapshot()
        for k in best:
            best[k] |= hits[k]
        n = len([t for t in best["hdr_block"] if is_note_request(t)])
        el = int(time.time() - t0)
        print(f"  [{el:3d}s] 轮次#{rounds}  noteapi请求={n}  URL={len(best['note_url'])}  "
              f"sig={len(best['signature'])}  enc={len(best['enc_param'])}", flush=True)
        if n and found_at is None:
            found_at = el
            print(f"  ★★★★★ {el}s 捕捉到真实 noteapi 请求！继续收集 20s 以取全 …")
        if found_at is not None and el - found_at >= 20:
            break
        time.sleep(6)

    report(best, f"watch {int(time.time()-t0)}s / {rounds} 轮")

    dump = {k: sorted(v) for k, v in best.items()}
    p = os.path.join(RUNTIME, "note_sync_capture.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(dump, f, ensure_ascii=False, indent=2)
    print(f"\n  ✓ 原始捕获（未脱敏, 含活凭据）→ {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
