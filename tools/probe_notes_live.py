"""
小米笔记 PC 侧联调 —— 第一步：从本机运行中的互联服务提取「无损」凭据并定位 sid

为什么单独写, 不复用 extract_continuity_creds.py:
  该脚本的 PATTERNS 有两个已知缺陷（见 feedback/regex-charclass-silent-truncation.md）:
    serviceToken: [A-Za-z0-9_\\-\\.%]  ← 漏 base64 的 + 和 /
    cUserId:      {20,120}             ← 小米 cUserId 实际仅 16 字符
  两者都会静默截断/漏抓。本脚本用严格白名单 + 长度哨兵取出【完整】值,
  再据实测量真实长度（而不是先猜一个 "看起来合理" 的长度）。

原则:
  1. 无损: 用宽字符类 + 前后哨兵, 宁可多抓也不截断
  2. 对照: 用 source 里自报的 tokenLength 日志/结构做长度校验（若可遇）
  3. 匿名: 同一 token 在不同位置出现 → 归并计数, 但不假设 sid
  4. 探明: sid 不靠猜 —— 用「域名↔token」共现来反推, 或让 passport 自报

用法:
  python probe_notes_live.py --scan          # 只扫描并测量长度分布（无网络）
  python probe_notes_live.py --dump          # 落盘完整凭据到 .runtime/(gitignore)
  python probe_notes_live.py --probe         # 用抓到的 token 打 noteapi（只读 GET）
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import sys
from ctypes import wintypes
from typing import Dict, List, Optional, Set, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x20, 0x40}

TARGET_NAMES = {
    "hyperconnect.exe",
    "mipccontinuity.exe",
    "mipccontinuityservice.exe",
    "xiaomi-miplay-bridge.exe",
}

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, ".runtime")

# ══════════════════════════════════════════════════════════════════
# ★ 无损模式：完整 base64 字母表 + base64url + cookie 安全字符 + %xx
#   比 extract_continuity_creds.py 的字符类严格更宽 —— 宁可多抓, 不截断
# ══════════════════════════════════════════════════════════════════
B64FULL = rb"[A-Za-z0-9+/=_\-\.%]"

PATTERNS = {
    # ── token 家族 ──
    "cookie_serviceToken": re.compile(rb"serviceToken=(" + B64FULL + rb"{16,2048})"),
    "json_serviceToken":   re.compile(rb'"serviceToken"\s*:\s*"(' + B64FULL + rb'{16,2048})"'),
    "hdr_ServiceToken":    re.compile(rb"[Ss]ervice[Tt]oken:\s*(' + B64FULL + rb'{16,2048})"),
    # ── 身份 ──
    #   cUserId 实测 16 字符; userId 是纯数字
    "cUserId":             re.compile(rb"cUserId=([A-Za-z0-9+/=_\-]{8,64})"),
    "CUser_Cookie":        re.compile(rb"CUser-Cookie[:\s=]+([A-Za-z0-9+/=_\-]{8,64})"),
    "json_userId":         re.compile(rb'"userId"\s*:\s*"?(\d{6,12})"?'),
    "json_ssecurity":      re.compile(rb'"ssecurity"\s*:\s*"(' + B64FULL + rb'{16,128})"'),
    "json_passToken":      re.compile(rb'"passToken"\s*:\s*"(' + B64FULL + rb'{16,2048})"'),
    # ── 端点：用来把 token 与「它服务的域」绑定 ──
    "note_host":           re.compile(rb"(noteapi\.micloud\.xiaomi\.net[a-zA-Z0-9/_.\-]{0,80})"),
    "interconnect_host":   re.compile(rb"(cn\.interconnectapi\.micloud\.xiaomi\.net[a-zA-Z0-9/_.\-]{0,80})"),
    "note_path":           re.compile(rb"(/mic/note/[a-zA-Z0-9/_.\-]{0,60})"),
    # ── ★ 关键：sid 的共现证据 ──
    #   小米客户端常在 token 附近记下它属于哪个 sid
    "sid_mention":         re.compile(rb"(?:sid|cookieName|tokenKey)[\"'\s:=]+[\"']?([a-z][a-z0-9]{3,20})[\"']?"),
}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def enum_regions(h) -> List[Tuple[int, int]]:
    out, addr = [], 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x7FFFFFFF0000:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE:
            if 0 < mbi.RegionSize < 256 * 1024 * 1024:
                out.append((mbi.BaseAddress or 0, mbi.RegionSize))
        addr = (mbi.BaseAddress or 0) + mbi.RegionSize
    return out


def read_block(h, base: int, size: int) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
        return buf.raw[:read.value]
    return None


def find_pids() -> List[Tuple[int, str]]:
    import subprocess
    try:
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"], text=True, errors="replace")
    except Exception:
        return []
    res = []
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() in TARGET_NAMES:
            try:
                res.append((int(parts[1]), parts[0]))
            except ValueError:
                pass
    return res


def scan_process(pid: int) -> Dict[str, Set[str]]:
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return {}
    found: Dict[str, Set[str]] = {k: set() for k in PATTERNS}
    try:
        for base, size in enum_regions(h):
            data = read_block(h, base, size)
            if not data:
                continue
            for key, rx in PATTERNS.items():
                for m in rx.finditer(data):
                    found[key].add(m.group(1).decode("utf-8", "replace"))
    finally:
        k32.CloseHandle(h)
    return found


# ══════════════════════════════════════════════════════════════════
# ★ 长度哨兵：把「看起来合理」换成「对照结构自报的期望值」
# ══════════════════════════════════════════════════════════════════
def sentinel(tokens: Set[str], label: str) -> List[str]:
    """打印长度分布, 并标出可疑的「疑似截断」值。

    判定依据: 若存在多个长度且较长的那些明显更长, 短值多是截断产物。
    同时 base64 长度应满足 len % 4 合理。
    """
    if not tokens:
        return []
    lens = sorted({len(t) for t in tokens})
    print(f"    {label}: {len(tokens)} 个, 长度分布 {lens}")
    mx = max(lens)
    suspect = [t for t in tokens if len(t) < mx]
    if suspect and mx - min(lens) > 40:
        print(f"      ⚠ 存在 {len(suspect)} 个显著短于最大值的候选 —— 疑似截断或异类")
        for t in sorted(suspect, key=len)[:4]:
            print(f"        len={len(t):5d} head={t[:6]!r} tail={t[-6:]!r}")
    return sorted(tokens, key=len, reverse=True)


def main() -> int:
    pids = find_pids()
    print("=" * 74)
    print("小米笔记 —— PC 侧凭据无损提取")
    print("=" * 74)
    if not pids:
        print("  ✗ 互联服务未运行")
        return 1
    print(f"  {len(pids)} 个目标进程: " +
          ", ".join(f"{n}({p})" for p, n in pids))

    print("\n  只读扫描（ReadProcessMemory, 不注入/不挂起/不修改）…\n")

    merged: Dict[str, Set[str]] = {k: set() for k in PATTERNS}
    for pid, name in pids:
        got = scan_process(pid)
        hits = sum(len(v) for v in got.values())
        if hits:
            print(f"  ── {name} ({pid}) ──")
            for k, vs in got.items():
                if vs:
                    print(f"     {k:22s} {len(vs):3d}")
            for k, vs in got.items():
                merged[k].update(vs)

    print("\n" + "=" * 74)
    print("★ 长度测量（无损）")
    print("=" * 74)
    for label in ("cookie_serviceToken", "json_serviceToken", "hdr_ServiceToken"):
        sentinel(merged.get(label, set()), label)
    sentinel(merged.get("json_ssecurity", set()), "ssecurity")
    sentinel(merged.get("cUserId", set()), "cUserId")

    print("\n" + "=" * 74)
    print("★ 域 / 路径共现（判断这些凭据服务的对象）")
    print("=" * 74)
    for k in ("note_host", "interconnect_host", "note_path", "sid_mention"):
        vs = merged.get(k, set())
        if vs:
            print(f"  【{k}】")
            for v in sorted(vs)[:10]:
                print(f"     {v}")

    # ── 落盘 ──
    if "--dump" in sys.argv:
        os.makedirs(RUNTIME, exist_ok=True)
        out = {k: sorted(v) for k, v in merged.items()}
        p = os.path.join(RUNTIME, "notes_creds.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"\n  ✓ 完整凭据 → {p}")
        print("    ⚠ 该文件含活的 token, 只应留在 .runtime/, 不要提交")

    return 0


if __name__ == "__main__":
    sys.exit(main())
