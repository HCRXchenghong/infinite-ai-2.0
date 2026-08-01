# FriendGate Lite

FriendGate Lite 是面向 ChatGPT Codex 账号的独立轻量网关。系统会加密保存上游账号凭证，并提供与 OpenAI Responses 兼容的接口，同时将 API、管理后台、邀请页面和配置指南分开运行。

## 功能

- 管理 ChatGPT OAuth `auth.json` 账号，自动刷新凭证并同步额度。
- 每个外发 Key 固定绑定一个上游账号和会话命名空间，避免不同用户之间串台。
- API Key 只保存不可逆哈希；管理员需要复制时，通过 AES-GCM 密文安全还原。
- 邀请制发放 Key，支持 IPv4、IPv6 双栈记录、设备凭证绑定、一次性领取和海报凭证。
- 完整透传 Responses、SSE、WebSocket、工具 JSON、流式事件和生图相关参数。
- 同步上游模型目录，支持按照可用模型进行调用。
- 实时仪表盘、调用与 Token 记录、审计日志、安全防护、IP 封禁和加密备份。
- 单 Go 进程配合 SQLite WAL，适合 1 核 2 GB 内存服务器运行。

## 启动服务

复制配置文件并填写管理员密码、主密钥和公开访问地址：

```bash
cp deploy/lite/.env.example deploy/lite/.env
docker compose --env-file deploy/lite/.env \
  -f deploy/lite/docker-compose.yml up -d --build
```

在没有任何依赖的空服务器上，可以直接执行一键安装脚本：

```bash
sudo bash deploy/lite/install.sh
```

安装脚本会输出管理员初始凭据和各服务访问地址。完整的端口说明、配置项、迁移备份和安全边界请参阅 [FRIENDGATE_CN.md](FRIENDGATE_CN.md)。

## 本地开发

```bash
cd lite
go test ./...
go run ./cmd/server
```

Lite 运行时不需要 PostgreSQL、Redis、Node 常驻进程或第三方模型凭证，只读取 `LITE_*` 环境变量。

## 目录说明

| 路径 | 用途 |
| --- | --- |
| `lite/` | FriendGate Lite 应用和内嵌网页 |
| `deploy/lite/` | Docker Compose 配置和空服务器安装脚本 |
| `Dockerfile.lite` | Lite 最小化镜像构建文件 |
| `FRIENDGATE_CN.md` | 中文部署与运维指南 |

## 安全提示

请勿将 `auth.json`、API Key、设备凭证、数据库文件、主密钥或备份口令提交到 Git。发现运行问题或安全问题时，请通过项目的问题跟踪渠道反馈，并避免在公开内容中泄露真实凭证。
