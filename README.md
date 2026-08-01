# Infinite AI 2.0

Infinite AI 2.0 是一个统一仓库，包含：

- `friendgate/`：受控的 API 网关、账号管理和邀请授权服务。
- `infinite-ai/`：Infinite AI 桌面客户端与远程 Gateway，支持 Linux、Windows 和 macOS 构建。
- `releases/`：经过校验的桌面端发行包归档。

当前仓库正在进行品牌、账号隔离、远程协作和多平台发布流程的统一改造。桌面端的内部协议命名会在兼容迁移完成后再逐步升级，避免破坏已有会话和网关数据。

Linux 桌面端可以用 `infinite-ai/scripts/run-linux.sh` 启动。脚本会为 WebKitGTK 设置 IBus/XIM 输入法环境，解决 AppImage 中中文组合输入无法提交的问题；也可以直接从桌面启动器运行重新打包后的 AppImage。

## 开发环境

进入 `infinite-ai/` 后，使用仓库内的 `mise.toml` 管理 Go、Node.js、pnpm、Protobuf、buf 和 lint 工具链。网关代码位于 `infinite-ai/crates/agent-gateway/`，桌面端位于 `infinite-ai/crates/agent-gui/`。

## 目录约定

源代码统一由本仓库根目录管理；构建输出、运行时缓存和本机下载文件不提交到 Git。生产部署前请单独配置密钥、OAuth 凭证和数据库路径。

旧版 Windows、macOS 和 Linux 包位于 `releases/`，仅作为兼容归档使用；请查看其中的校验和及说明。
