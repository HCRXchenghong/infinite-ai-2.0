# Infinite AI 2.0

Infinite AI 2.0 是一个统一产品仓库，目标是把网页 Chat、桌面 Agent、兼容 API 网关、账号池、邀请、设备授权、计费、审计和部署运维收束到同一个 Go 后端与 PostgreSQL 产品域里。

## 仓库结构

- `friendgate/`：统一 Go 后端。包含管理后台、用户 Portal、邀请页、指南页、API 网关、PostgreSQL 迁移、SQLite 离线导入、备份恢复、钱包账本、平台路由和兼容上游。
- `infinite-ai/`：Infinite AI 桌面客户端、Agent GUI、Tauri/Rust 服务、前端组件和本机代理能力。
- `INFINITE_AI_2_0_FUSION_PLAN.md`：融合实施基线和阶段状态。它是当前产品边界、验收口径和未完成项的详细说明。
- `releases/`：经过确认的发行包归档。新的大体积构建产物应优先通过 GitHub Releases 或制品仓库发布，不直接作为普通 Git blob 提交。

## 当前已闭环

- PostgreSQL 平台域：租户、管理员、用户、邀请、会话、设备、Agent 项目、本地子 Key、平台模型、产品发布、路由池、路由目标、上游连接、上游账号、钱包、额度桶、账本、用量记录和平台审计。
- SQLite 到 PostgreSQL 离线迁移：`go run ./cmd/migrate` 预检，停服后用 `go run ./cmd/migrate --apply` 导入。导入覆盖账号、密钥、邀请、设备、调用记录、审计、封禁和加密字段重加密。
- 新公共网关开关：`LITE_PLATFORM_GATEWAY_ENABLED=true` 后，`/v1` 只接受 PostgreSQL API Key；旧 SQLite Key 不会被静默兼容到新产品域。
- 多协议兼容上游：
  - OpenAI 兼容：`/v1/responses`、`/v1/chat/completions`
  - Anthropic 兼容：`/v1/messages`
  - Gemini 兼容：`/v1beta/models/{model}:generateContent`、`/v1beta/models/{model}:streamGenerateContent`
- 模型 alias 隔离：用户、Agent 和外部 API 只看到后台发布的平台模型别名；私有上游模型 ID 只存在于管理端路由目标中。
- Chat 产品：PostgreSQL 用户注册/登录、邀请制、会话列表、新建/读取/改名/删除、消息落库、继续发送、模型选择、Markdown 渲染和 Chat 钱包扣费。
- Agent 产品：PostgreSQL 设备授权、Ed25519 签名、请求体摘要、Nonce 防重放、MAC 辅助绑定、设备撤销立即取消在途请求、本地子 Key 管理和 Agent 钱包扣费。
- 外部 API：平台 API Key 创建/复制/停用/删除、Key Scope、IP/设备策略、路由池边界、请求预留额度、可信 usage 结算、失败释放额度和在途请求撤销。
- PostgreSQL 平台备份：平台开关开启时导出 `FGLTPG01` 加密负载，恢复时取消在途平台请求、清空瞬态会话/Nonce/本地子 Key，并把平台密文重加密到目标 Master Key。
- 支付控制面骨架：后台可查看支付商户配置和订单、加密保存待验证商户配置、显式保持停用；真实支付没有通过商户验收前不会在用户端出现充值入口。

## 快速启动

后端开发：

```bash
cd friendgate/lite
go test ./...
go run ./cmd/server
```

带 PostgreSQL 的统一产品域需要配置：

```bash
export LITE_ADMIN_PASSWORD='replace-with-a-long-random-password'
export LITE_MASTER_KEY='replace-with-32-random-bytes-in-base64url'
export LITE_DATABASE_URL='postgres://infinite_ai:password@localhost:5432/infinite_ai?sslmode=disable'
export LITE_PLATFORM_GATEWAY_ENABLED=false
```

切换生产公共网关前，必须先完成：

1. `go run ./cmd/migrate` 预检通过。
2. 停止旧服务写入后执行 `go run ./cmd/migrate --apply`。
3. 在后台核对用户、Key、钱包、模型发布、路由目标和上游账号。
4. 给 External API 钱包发放 `monthly` 与 `rolling_5h` 两个可用额度桶，或确认只由管理员手工充值。
5. 再把 `LITE_PLATFORM_GATEWAY_ENABLED=true` 打开。

桌面端开发：

```bash
cd infinite-ai
pnpm install
pnpm --dir crates/agent-gui dev
```

Linux 桌面端也可以用 `infinite-ai/scripts/run-linux.sh` 启动。脚本优先运行当前源码构建的 `target/release/infinite-ai`，并为 WebKitGTK 设置 IBus/XIM 输入法环境，解决中文组合输入无法提交的问题。

## 验证状态

最近一次本地验证：

- `go test ./...` 通过。
- `node --check friendgate/lite/internal/app/web/admin.js` 通过。
- `go test ./internal/app -run TestPlatformGatewayPostgresNativeProtocolIntegration -count=1 -v` 编译通过；当前机器未设置 `INFINITE_AI_TEST_POSTGRES_URL`，PostgreSQL opt-in 集成测试按预期跳过。

需要真实 PostgreSQL 验收时：

```bash
export INFINITE_AI_TEST_POSTGRES_URL='postgres://user:password@localhost:5432/infinite_ai_test?sslmode=disable'
cd friendgate/lite
go test ./internal/app -run 'Postgres|Platform' -count=1 -v
```

## 还没闭环的内容

这些能力不能在生产里标成已可用，也不能给用户显示假入口。

### 1. 真实支付闭环

已完成：支付表、备份覆盖、后台只读列表、商户配置加密保存、强制停用状态。

未完成细节：

- 支付总开关与用户端充值入口。
- 商品/套餐购买页和订单创建。
- 支付跳转、收款码或 SDK 参数生成。
- 异步回调验签，包括商户号、订单号、金额、币种、交易状态和重放保护。
- 主动查单、超时关单、退款、退款回调和对账。
- 支付成功后在同一 PostgreSQL 事务里完成订单状态、钱包入账和不可变账本流水。
- 支付失败、重复回调、部分退款、商户配置轮换和异常订单后台处理。

启用前必须取得：真实商户号、签名/验签密钥、HTTPS 回调域名、测试订单、退款/对账测试材料。

### 2. 官方 OAuth 连接器

已完成：旧 ChatGPT/OpenAI OAuth 仍在旧账号体系里可用；PostgreSQL 平台已能保存 `oauth` 类型连接草稿并在未实现时明确拒绝通用探测。

未完成细节：

- PostgreSQL 平台原生的 ChatGPT OAuth 账号生命周期。
- Claude 官方 OAuth 或官方允许的服务器侧授权流程。
- Gemini 官方 OAuth / 服务账号授权策略与额度同步。
- Antigravity、xAI、Kiro 的官方授权条件、Scope、回调和刷新流程。
- 每个供应商的重新授权、撤销、Token 轮换、账号唯一性、代理绑定、额度同步、模型快照和健康检查。
- OAuth State/PKCE/Nonce 的跨重启持久化、一次性消费、错误回调和重放测试。

启用前必须取得：官方应用凭证、允许的 Scope、回调 URL、真实测试账号、供应商条款确认和端到端验收记录。

### 3. 跨协议转换

已完成：原生协议直通。OpenAI 请求走 OpenAI 兼容上游，Anthropic Messages 请求走 Anthropic 兼容上游，Gemini GenerateContent 请求走 Gemini 兼容上游。

未完成细节：

- OpenAI Responses 转 Anthropic Messages。
- OpenAI Chat Completions 转 Anthropic Messages。
- OpenAI Responses/Chat 转 Gemini GenerateContent。
- Anthropic Messages 转 OpenAI 或 Gemini。
- Gemini GenerateContent 转 OpenAI 或 Anthropic。
- 工具调用、content block、function call、reasoning、stop reason、安全字段、文件引用、多模态输入和流事件的明确 IR 映射。
- 能力不兼容时的降级策略、错误码和后台能力矩阵。

当前规则：没有同协议路由目标时，请求返回不可用，不做隐式跨协议猜测。

### 4. 真实供应商验收

已完成：本地单元测试和 httptest 上游覆盖多协议网关、usage 解析、模型 alias 隔离和撤销边界。

未完成细节：

- 用真实 OpenAI/Anthropic/Gemini 兼容服务跑模型同步、非流式、流式、工具调用和错误映射。
- 用真实账号验证额度、限流、重置窗口、模型可见性和异常响应。
- 用真实网络环境验证 SSRF 策略、反向代理、TLS、可信代理和公网 Cookie 设置。
- 使用 `INFINITE_AI_TEST_POSTGRES_URL` 跑 PostgreSQL opt-in 集成测试矩阵。

### 5. 生产切换

已完成：迁移工具、备份、导入、平台网关开关和新产品域代码。

未完成细节：

- 生产停服窗口。
- 旧 SQLite 全量预检和正式导入。
- 导入后账号、Key、邀请、设备、钱包、模型、路由和用量核对。
- 切换 `LITE_PLATFORM_GATEWAY_ENABLED=true`。
- 切换后回滚预案、备份恢复演练和新旧入口封锁确认。

## 安全边界

- 不提交生产密钥、OAuth Refresh Token、商户密钥、管理员密码、测试账号或真实用户数据。
- 普通用户不能配置供应商、Base URL、上游 API Key、OAuth 凭证、代理或系统提示词。
- 原始请求/响应正文默认不保存；用量、审计和安全事件只保存脱敏元数据。
- Chat、Agent、External API 三类钱包分账，不能互相扣额度。
- 未通过验收的 OAuth、支付和跨协议转换必须保持“未配置/不可用”。

## 发行包

当前仓库内保留的 Linux 兼容归档：

```text
releases/linux/Infinite-AI-1.3.0-dev.0-ubuntu20.04-22.04-amd64.deb
releases/linux/Infinite-AI-1.3.0-dev.0-ubuntu22.04-amd64.deb
```

新构建的 `.deb`、`.AppImage`、Docker target 和本地参考代码不直接提交到 Git；请通过 GitHub Releases 或制品仓库发布，并在 release notes 中标注校验和。
