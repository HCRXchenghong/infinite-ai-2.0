# FriendGate Lite 开发指南

## 项目结构

| 路径 | 内容 |
| --- | --- |
| `lite/` | 主程序、SQLite 存储、网关和嵌入式网页 |
| `deploy/lite/` | Docker Compose、Nginx 只读挂载和空服务器安装脚本 |
| `Dockerfile.lite` | 仅构建 `lite/` 的最小镜像 |

## 本地运行

```bash
cd lite
go test ./...
go run ./cmd/server
```

必须设置 `LITE_ADMIN_PASSWORD`；生产环境还应固定 `LITE_MASTER_KEY` 和公开 URL。测试数据放在临时目录，不要把 `lite/data/`、凭证、数据库或备份提交到仓库。

## 变更要求

- API Key 只保存哈希，账号访问/刷新凭证只保存加密密文。
- 所有管理、邀请、指南和网关接口都必须保留鉴权、来源校验和审计。
- 修改网关转发时，保持工具 JSON、图片输入、生图参数、SSE 和 WebSocket 负载原样。
- 修改前端后至少检查嵌入文件、未授权响应、停用 Key 即时生效和 IPv4/IPv6 绑定。
- 提交前执行 `go test ./...`；无 Go 工具链时使用 `Dockerfile.lite` 的构建环境验证。
