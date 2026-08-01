# FriendGate Lite

FriendGate Lite 是独立的轻量化 ChatGPT Codex 网关：账号凭证加密保存，API、后台、邀请页和配置指南分端口运行，面向少量受邀用户提供稳定的 Responses 兼容接口。

## 功能

- ChatGPT OAuth `auth.json` 账号管理、自动刷新和额度同步。
- 每个 Key 的账号与会话隔离；Key 只存哈希，管理员复制时使用 AES-GCM 密文。
- 邀请制 Key、IPv4/IPv6 双栈授权、设备凭证绑定、一次性领取和海报凭证。
- Responses/SSE/WebSocket、工具 JSON、生图参数和流式事件透传。
- 实时仪表盘、模型目录、Token/调用记录、审计、安全防护、封禁和加密备份。
- 单 Go 进程 + SQLite WAL，适合 1H2G 服务器。

## 启动

```bash
cp deploy/lite/.env.example deploy/lite/.env
# 在 .env 中设置管理员密码、LITE_MASTER_KEY 和公开 URL
docker compose --env-file deploy/lite/.env \
  -f deploy/lite/docker-compose.yml up -d --build
```

空服务器可直接执行：

```bash
sudo bash deploy/lite/install.sh
```

详细配置、端口、迁移备份和安全边界请参阅 [FRIENDGATE_CN.md](FRIENDGATE_CN.md)。

## 本地开发

```bash
cd lite
go test ./...
go run ./cmd/server
```

Lite 运行时不需要 PostgreSQL、Redis、Node 常驻进程或第三方模型凭证。请勿把 `auth.json`、API Key、设备凭证、数据库、主密钥或备份口令提交到 Git。
