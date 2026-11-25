# Xiaomi Notes API SDK

小米云笔记相关私有 API 的 Python 实现逆向整理。包含扫码登录、凭据管理、
签名/加密链以及笔记/待办/文件夹/附件的读写端点。

> 仅供个人学习与自有账号数据访问研究使用。所有凭据均保存在本地 `.runtime/`，
> **严禁提交任何 token / ssecurity / passToken / cookie / 用户数据**。

## 模块

| 文件 | 说明 |
|---|---|
| `mi_auth.py` | ★扫码登录 + 凭据持久化 + 自动续登（passToken → serviceToken） |
| `noteapi_auth.py` | serviceToken/ssecurity 获取与签名链（AES-CBC + SHA1）逆向 |
| `noteapi_pc.py` | PC 端 noteapi v3.1 客户端（notes/todos/folders/附件） |
| `notes_client.py` | 云笔记客户端封装 |
| `notes_client_android.py` | Android 侧 noteapi 签名/加密实现参考 |
| `ainote_pc.py` | AI 笔记端点（摘要/翻译/纠错/录音转写） |

`tools/` — 进程内存凭据探测、端点探测、同步监控工具。
`tests/` — 端点自测脚本（需先登录并填入自己的附件 fileId）。

## 快速开始：扫码登录获取 token

唯一受支持的登录方式是扫码（无需抓包、无需手工填写 token）：

```bash
python mi_auth.py                 # 终端打印登录链接 + 等待扫码（300s）
python mi_auth.py --refresh       # 用 passToken 静默续登 serviceToken
python mi_auth.py --status        # 查看当前凭据状态
python mi_auth.py --ensure        # 凭据过期则自动续登
```

流程（见 `mi_auth.py:login_qr`）：

1. `GET account.xiaomi.com/longPolling/loginUrl?sid=micloud`
   拿到 `loginUrl` 和长轮询 `lp`。
2. 手机米家 App 扫 `loginUrl` 的二维码并确认。
3. 长轮询 `lp` 返回 `{passToken, ssecurity, userId, cUserId, location}`。
4. 请求 `location` 从 Set-Cookie 取 `serviceToken`（失败则回退用 passToken）。
5. 生成 deviceId，写入 `.runtime/mi_auth.json`（被 .gitignore 排除）。

## 拉取笔记 / 待办（都已实现）

两条拉取链路都在 `noteapi_pc.py`：

| 数据 | API | 端点 |
|---|---|---|
| 笔记（含文件夹/附件） | `NotesApi(cli).list_full(sync_tag, limit)` | `GET /mic/note/pc/v3.1/user/full` |
| 待办事项 | `TodoApi(cli).sync(sync_token, limit)` | `GET /mic/todo/pc/v1/user/records` |
| 已删除笔记 | `cmd_recycle` / `NotesApi.list_deleted` | `GET .../full`（回收站标志） |
| 文件夹 | `cmd_folders` | 同上 full 流里筛 folder |

CLI 一键拉取（无需写代码）：

```bash
python noteapi_pc.py --login     # 首次扫码登录（或单独跑 mi_auth.py）
python noteapi_pc.py --notes     # 拉取全部笔记 → 落盘 .runtime/notes_pc_pull.json
python noteapi_pc.py --todos     # 拉取全部待办
python noteapi_pc.py --recycle   # 拉取回收站
python noteapi_pc.py --folders   # 列出文件夹
python noteapi_pc.py             # 默认 = --notes + --todos 全量
```

翻页契约：笔记用 `syncTag`（从响应 `syncToken` 取，逐个翻到 `hasMore=false`）；
待办用 `syncToken`，**必须回传整个 token 对象的 JSON 串**（`TodoApi.token_str(resp)`），
传裸 `obj` 值会报 `code=10008`。

## 调用示例

```python
import noteapi_pc as n
import mi_auth

creds = mi_auth.get_credentials()          # 读 .runtime/mi_auth.json
auth = {"token": creds["token"], "ssecurity": creds["ssecurity"],
        "cUserId": creds["cUserId"], "userId": creds["userId"]}
cli = n.Client(auth)

notes = n.NotesApi(cli).list_full()        # 笔记原始响应（dict）
todos = n.TodoApi(cli).sync()              # 待办原始响应（dict）
tk = n.TodoApi.token_str(todos)            # 下一页 syncToken（JSON 串）
todos_page2 = n.TodoApi(cli).sync(tk)      # 继续翻页
```

## 安全

- `.runtime/` 整个目录已被 `.gitignore` 排除，凭据文件绝不入库。
- 测试脚本中的附件 fileId 由环境变量 `NOTE_TEST_FID` 提供，无硬编码账号数据。
- 若发现任何真实凭据被提交，请立即撤销/重置该 token 并清理历史。
