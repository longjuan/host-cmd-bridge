---
name: hostcmd-bridge-client
description: 用于 AI 在容器内发起宿主机命令执行/查询命令执行状态。
---

# HostCmd 执行技能

本技能用于在容器内提交宿主机命令执行请求，以及查询请求结果。

## 触发条件

- 用户要求“在宿主机执行某条命令”
- 用户要求“查询某个 request_id 的结果”
- 用户要求“模拟 AI 调用流程”

## 不触发条件

- 仅要求在当前工作目录直接执行本地命令

## 你必须遵守

- 把该流程视为宿主机高风险操作。
- 每次新提交都使用唯一 `request_id`（推荐 `--request-id auto`）。
- 严禁同一个 `request_id` 对应不同 payload（command/args/reason/timeout）。
- 参数逐个传递，一个 token 一个 `--arg`。
- 对于以 `-` 开头的参数，使用 `--arg=<value>`（例如 `--arg=-al`）。

## 连接约定

- 默认连接“本技能目录中的内置 socket 文件”。
- 除非用户明确要求，不要让用户提供 socket 路径。
- 仅在需要覆盖时使用环境变量 `HOSTCMD_SOCKET` 或参数 `--socket`。

## 协议要点

`submit` 必填：
- `request_id`
- `command`
- `args`
- `reason`
- `timeout_sec`

`query` 必填：
- `request_id`

## AI 执行流程

1. 默认使用 Python 客户端。
2. `submit` 后阻塞等待返回。
3. 若提交连接中断或用户后续追问状态，执行 `query`。
4. 回复中至少包含：`request_id`, `status`, `exit_code`, `stdout`, `stderr`, `error_reason`。

## 错误分支处理

- 包含 `has already been used ... use action=query`：
  立即 `query`，不要重复 `submit`。
- 包含 `already used by a different request payload`：
  这是 ID 冲突，必须换新 `request_id` 后重提。
- 命中策略/安全拒绝：
  直接返回拒绝原因，不重试原请求。

## 命令模板

Python（推荐）：

```bash
python3 ./skills/hostcmd-bridge-client/scripts/hostcmd_client.py submit \
  --request-id auto \
  --command ls \
  --arg=-al \
  --reason "排查目录权限" \
  --timeout-sec 30
```

Python 查询：

```bash
python3 ./skills/hostcmd-bridge-client/scripts/hostcmd_client.py query \
  --request-id req-123
```

Node 提交：

```bash
node ./skills/hostcmd-bridge-client/scripts/hostcmd_client.mjs submit \
  --request-id auto \
  --command ls \
  --arg=-al \
  --reason "排查目录权限" \
  --timeout-sec 30
```
