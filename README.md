# host-cmd-bridge

用于容器内 AI 调用宿主机命令的审批执行桥接服务。

- AI 通过 **Unix socket JSONL** 调用代理。
- 代理调用 **企业微信审批 API** 发起审批。
- 代理通过 HTTP 接收 **企业微信回调**，并做验签与解密。
- 仅允许“审批通过且未被篡改”的命令在宿主机执行。

## 二进制部署（推荐）

目标机器不需要安装 Go。只要把编译好的二进制和配置文件拷贝过去即可。

### 1) 在构建机打包

构建机（CI 或开发机）执行：

```bash
make package VERSION=v1.0.0
```

产物在 `dist/packages/`，包含：

- `host-cmd-bridge-linux-amd64.tar.gz`
- `host-cmd-bridge-linux-arm64.tar.gz`
- `SHA256SUMS`

每个压缩包内部目录固定为：

```text
host-cmd-bridge-linux-<arch>/
├── host-cmd-bridge
├── config.example.yaml
├── policy.example.yaml
└── containerskill/
    └── host-cmd-bridge/
        ├── SKILL.md
        ├── agents/openai.yaml
        └── scripts/
            ├── hostcmd_client.py
            └── hostcmd_client.mjs
```

### 2) 在目标机解压并配置

1. 解压对应平台包：

```bash
tar -xzf host-cmd-bridge-linux-amd64.tar.gz -C /opt
cd /opt/host-cmd-bridge-linux-amd64
```

2. 准备配置并填写真实企业微信参数：

```bash
cp ./config.example.yaml ./config.yaml
cp ./policy.example.yaml ./policy.yaml
```

3. 修改 `config.yaml`：

- `socket.path`（可留默认：`<exe_dir>/containerskill/host-cmd-bridge/hostcmd.sock`）
- `socket.file_mode`（默认 `0666`；如需收紧可改 `0660` 并配置同组权限）
- `store.sqlite_path`
- `exec.max_concurrent`
- `exec.max_timeout_sec`（全局最大执行超时）
- `approval.timeout_sec`
- `http.callback_path_prefix`（企业微信回调路径前缀，例如 `/wecom-app`）
- `wecom.*`（企业 ID、密钥、模板、回调 token/aes key）

### 3) 启动二进制

```bash
./host-cmd-bridge -config ./config.yaml
```

查看版本：

```bash
./host-cmd-bridge -version
```

## 本地源码运行（开发调试）

```bash
go run ./cmd/agent -config ./config.yaml
```

## 企业微信审批接入（逐步配置）

下面步骤是按当前代码实现写的，建议严格按顺序执行。

### 第 1 步：准备企业微信应用与凭据

1. 在企业微信管理后台创建可调用审批接口的应用（自建应用）。
2. 记录以下参数：
- `CorpID` 对应 `wecom.corp_id`
- 应用 `Secret` 对应 `wecom.corp_secret`
3. 确认该应用对审批相关接口有权限，并且创建人（`creator_user_id`）在企业通讯录中存在。

### 第 2 步：创建审批模板（最关键）

代码发起审批时会写入 6 个业务字段：

- 请求ID
- 执行命令
- 命令参数
- 执行原因
- 超时时间(秒)
- 命令摘要

当前程序会在运行时调用 `gettemplatedetail`，按 `config.yaml` 里的 `wecom.field_titles.*`（中文控件名）自动匹配控件 ID。  
如果名称不匹配，会导致提交审批失败（常见 `301025`）。

模板 ID 填到 `wecom.template_id`。

### 第 3 步：配置审批人策略

当前实现支持两种方式：

1. 使用模板内审批人：`wecom.approver_user_ids` 置空数组
2. 代码指定审批人：`wecom.approver_user_ids` 填用户 ID 列表（例如 `["lisi"]`）

建议先用“模板内审批人”打通，再切换成代码指定审批人。

### 第 4 步：配置回调地址与回调加密参数

服务只提供审批回调接口：

- `GET {callback_path_prefix}`（企业微信验证 URL）
- `POST {callback_path_prefix}`（审批状态回调）

示例：如果服务外网地址是 `https://bridge.example.com`，并且 `http.callback_path_prefix=/wecom-app`，则回调 URL 填：

`https://bridge.example.com/wecom-app`

同时在企业微信后台回调配置里生成并记录：

- `Token` 对应 `wecom.token`
- `EncodingAESKey` 对应 `wecom.encoding_aes_key`（43 位）

注意：`wecom.corp_id` 必须与回调解密后消息中的企业 ID 一致，否则会报 `corp id mismatch`。

### 第 5 步：填写 config.yaml 对照表

按以下映射填写：

- `wecom.corp_id` = 企业 ID
- `wecom.corp_secret` = 应用 Secret
- `wecom.template_id` = 审批模板 ID
- `wecom.creator_user_id` = 审批单发起人用户 ID
- `wecom.approver_user_ids` = 审批人（可空）
- `wecom.token` = 回调 Token
- `wecom.encoding_aes_key` = 回调 AESKey
- `wecom.api_base_url` = `https://qyapi.weixin.qq.com`（默认即可）
- `http.callback_path_prefix` = 回调路径前缀（例如 `/wecom-app`）
- `wecom.field_titles.*` = 模板里对应控件“中文名称”（用于自动匹配控件 ID）

补充：

- `approval.timeout_sec`：审批超时窗口（超过则直接失败，不执行）
- `approval.callback_window_sec`：回调验签时间窗（默认 300 秒）

### 第 6 步：启动与连通性检查

1. 启动服务：`go run ./cmd/agent -config ./config.yaml`
2. 确保企业微信能访问你的回调 URL（公网或内网穿透）。
3. 当企业微信进行 URL 验证时，服务会处理 `GET {callback_path_prefix}`；验证通过后才会推送审批事件。

### 第 7 步：端到端联调

1. 通过 Unix socket 发送 `submit` 请求。
2. 在企业微信审批中心同意或拒绝。
3. 服务收到回调后：
- 同意：进入二次校验并执行命令
- 拒绝/撤回/超时：直接终态，不执行命令
4. 通过 `query` 或阻塞返回查看最终执行结果。

### 常见问题排查

- 报 `signature mismatch`：检查回调 URL、`token`、`encoding_aes_key` 是否与企业微信后台一致。
- 报 `corp id mismatch`：`wecom.corp_id` 配置错误，或用了其他企业的回调参数。
- 审批单创建失败：优先检查 `template_id`，以及 `wecom.field_titles.*` 是否与模板控件中文名称完全一致。
- 请求长期 pending：企业微信回调没到服务，先检查网络可达和网关转发路径。
- 容器侧报 `PermissionError: [Errno 13] Permission denied`：检查 `socket.file_mode`、socket 目录权限和容器用户组；默认建议先用 `0666` 验证链路。

## Socket 协议（JSONL）

### submit 请求

```json
{"action":"submit","request_id":"req-1","command":"/bin/echo","args":["hello"],"reason":"debug","timeout_sec":30}
```

### query 请求

```json
{"action":"query","request_id":"req-1"}
```

### 响应示例

```json
{
  "request_id":"req-1",
  "status":"SUCCEEDED",
  "exit_code":0,
  "stdout":"hello\n",
  "stderr":"",
  "started_at":"2026-03-20T12:00:00Z",
  "ended_at":"2026-03-20T12:00:00Z",
  "timed_out":false
}
```

失败、等待或异常响应会通过 `message` 返回可读说明；`SUCCEEDED` 响应不包含 `message`。

## HTTP 回调

仅暴露以下接口（用于企业微信审批）：

- `GET {callback_path_prefix}`（回调 URL 验证）
- `POST {callback_path_prefix}`（审批结果回调）

两者都使用企业微信回调参数：`msg_signature`、`timestamp`、`nonce`。

## 状态流转

`PENDING_APPROVAL -> APPROVED -> EXECUTING -> SUCCEEDED|FAILED|EXEC_TIMEOUT`

不会进入执行的终态：

- `REJECTED`
- `WITHDRAWN`
- `APPROVAL_TIMEOUT`

## 安全控制

- 白名单模板校验（`policy.yaml`）
- 命令与参数黑名单正则拦截
- 参数字符集与长度校验
- 执行前 digest 防篡改校验
- 审批时效校验
- 同一 `request_id` 仅允许执行一次

策略执行语义：

- 白名单命中 + `auto_approve_whitelist=true`：自动通过（仍会推送审批消息，第三行显示“已自动通过，无需审批”）
- 黑名单命中：直接拒绝，不执行
- 非白名单且未命中黑名单：进入人工审批，审批通过后执行

## 测试

```bash
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```
