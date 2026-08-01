# FriendGate Lite

FriendGate Lite 是独立的轻量化 ChatGPT/Codex 网关。它只管理 ChatGPT `auth.json` 账号，只服务少于 10 个邀请制 API Key，并把管理端、邀请端、API 链路和配置指南放在四个独立监听端口上。

## 已实现的边界

| 能力 | 实现 |
|---|---|
| ChatGPT 账号 | 只接受 Codex `auth.json`，支持 access/refresh token 自动刷新、停用和永久删除 |
| 额度自动化 | 添加后立即同步，并默认每 5 分钟读取 5h/7d 额度、重置时间、套餐和重置次数 |
| Codex 协议 | `/v1/*` 与 `/backend-api/codex/*` 的 HTTP/SSE，以及 `/responses` 的 WebSocket 链路 |
| 模型同步 | 启动时、新账号添加后、每 30 分钟及管理员手动按账号同步官方模型快照 |
| 账号池调度 | 全部 Key 共享可用账号池；按 Key + 会话粘连账号，新会话按负载分配 |
| 多人隔离 | `session_id`、`conversation_id` 混入 Key 的不可逆命名空间，粘连记录也按 Key 隔离 |
| Key 安全 | SHA-256 哈希用于查询鉴权；AES-256-GCM 密文仅供管理员审计后复制 |
| 邀请领取 | 角色、邀请链接、识别码、IPv4/IPv6 探测、设备备注、生成 Key、60 秒失效并跳转 Bing |
| IP 防护 | Key + 精确 IP 双鉴权；双栈地址成组加入白名单、自动封禁和联动解封 |
| 后台安全 | 首次一次性创建管理员并强制绑定 Microsoft Authenticator；密码修改要求 2FA 并注销全部会话 |
| 主动防护 | 404/502 独立阈值、临时/永久 IP 黑名单、可验证健康检查和 Nginx SHA-256 基线告警 |
| 可配置额度 | 按请求次数配置，`0` 表示无限；不额外设置 RPM/TPM 限速 |
| 日志 | 使用记录、安全事件、自动封禁、管理员操作审计分开保存 |
| 迁移备份 | 后台导出口令加密的 `.fgbackup`，可导入到使用不同主密钥的新安装 |
| 低配置 | 单 Go 进程 + SQLite WAL，无 PostgreSQL、Redis、Node 常驻进程 |

## 透传与隔离的真实边界

HTTP 请求体会在限制内完整读取（大于 128 KiB 时使用权限 `0600` 的临时文件），用于识别模型后按原字节重放。因此 function/tool JSON、图片 URL、输入图片 Base64 和生图参数不会被 JSON 重组。HTTP 响应体与 SSE 事件按字节流式转发；响应尾部窗口只解析 token 用量，不记录提示词、工具参数或图片数据。

`GET /v1/responses` （也接受 `/responses`）的 WebSocket 升级会在首个 JSON 帧中识别模型并选定账号，之后文本帧和二进制帧的 payload 原样转发。后续 `response.create` / `session.update` 如要切换模型，只能切到当前粘连账号已同步的模型，不会为了切模型悄然换账号。工具调用事件和生图 Base64 结果也遵守这一转发规则。

这里的“原样”指应用负载，不指整个 HTTP 报文。网关会必要地替换 `Authorization`，设置 `ChatGPT-Account-ID` 和 Codex 身份头，过滤 Cookie/代理头，并对 `Session_ID` / `Conversation_ID` 做按 Key 的不可逆命名空间处理。`/models` 也是明确的例外：它返回本地已成功同步的官方快照合并结果，而不是把某个账号的实时响应盲转发。

账号路由不是“每个 Key 固定一个账号”。系统依次使用客户端的 `session_id`、`conversation_id`、正文 `prompt_cache_key` 和 Codex installation ID 识别会话，再把 `Key + 会话` 的不可逆哈希粘到账号池中的一个账号，默认保存 1 小时：

- 同一个 Key、同一个会话始终回到原账号，避免 `previous_response_id` 等上游状态跨账号失效。
- 同一个 Key 的新会话会分配到当前粘连负载较低的可用账号，因此可使用整个账号池的官方额度。
- 不同 Key 即使提交完全相同的客户端会话值，数据库粘连和发往上游的会话头也互不相同。
- 上游账号返回 `429` 后会按 `Retry-After`（缺省 5 分钟）进入冷却；已有会话不会暗中换号，新会话会选择其他账号。
- 管理员主动停用或永久删除账号时，其旧粘连才会在下次请求重新分配。没有任何会话信号的非标准客户端按 Key 保守粘连，避免随机跳号。

可通过 `LITE_STICKY_SESSION_TTL` 调整粘连时间，通过 `LITE_ACCOUNT_COOLDOWN` 调整上游未返回 `Retry-After` 时的默认冷却时间。

账号添加成功后会立刻请求 ChatGPT `/backend-api/wham/usage` 和 `/rate-limit-reset-credits`，后台展示套餐、5 小时/7 天进度条、各窗口重置倒计时、同步错误及可用重置次数。默认每 5 分钟自动刷新，可用 `LITE_QUOTA_SYNC_INTERVAL` 调整；后台也可以手动刷新，或确认后消耗 1 次重置额度。账号到达官方窗口上限时会自动进入冷却，新会话不再分给该账号。

模型目录与额度是两套独立同步。模型会在进程启动、新账号添加后、管理员点击“获取模型列表”以及每 30 分钟自动获取。`GET /v1/models` 合并所有启用账号最后一次成功快照中的官方模型对象，并保留未知的官方能力字段。带 `model` 的请求只会被路由到已宣告该模型的账号；没有任何成功快照时返回 `503`，请求未同步的模型时返回 `400`。单个账号同步失败时保留其最后成功快照并在后台显示错误；账号停用后不再进入合并，永久删除还会删除其 OAuth 凭据、模型快照和会话粘连并中断在途请求，仅保留无凭据的历史关联标识。

## 端口

- `8080`：Codex API，仅 Key + 已授权 IP 可访问；`/health` 例外用于容器健康检查。
- `8081`：单管理员账号密码 + Microsoft 2FA 后台。
- `8082`：一次性邀请领取页。
- `8083`：私有 Codex 配置指南；必须输入有效 Key 或上传带隐藏签名的凭证海报。

正式使用建议为四个端口配置独立 HTTPS 域名，模板见 `deploy/lite/Caddyfile.example`。邀请端还需要两个同样反代到 `8082` 的探测域名：IPv4 探测域名只配置 DNS A，IPv6 探测域名只配置 DNS AAAA。一个普通双栈域名不能保证浏览器分别建立两种连接，因此不能可靠获取两个地址。

```text
api.example.com      -> 8080
admin.example.com    -> 8081
invite.example.com   -> 8082（领取页）
guide.example.com    -> 8083（配置指南）
invite4.example.com  -> 8082（仅 A）
invite6.example.com  -> 8082（仅 AAAA）
```

将后两个完整地址分别写入 `LITE_PUBLIC_IPV4_PROBE_URL` 和 `LITE_PUBLIC_IPV6_PROBE_URL`。使用反向代理时，必须把代理来源 CIDR 写入 `LITE_TRUSTED_PROXIES`，否则系统会把代理地址当成领取 IP；不要写 `0.0.0.0/0`。

Compose 端口映射故意不指定 host IP，Docker 会发布到守护进程支持的全部 IPv4/IPv6 宿主地址。IPv6 是否真实可达仍取决于服务器是否分配公网 IPv6、Docker/反向代理是否启用 IPv6，以及安全组和宿主防火墙是否放行对应端口。如果只想让反向代理访问容器端口，应使用额外 Compose 覆盖或防火墙做明确限制，不要依赖应用内 IP 鉴权代替网络边界。

## Docker 启动

```bash
cd deploy/lite
cp .env.example .env
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
# 把生成值及管理员密码、公开 URL 写进 .env
docker compose --env-file .env up -d --build
```

如果宿主机已安装 Nginx，并且需要后台完整性监控，改用只读挂载覆盖：

```bash
docker compose --env-file .env \
  -f docker-compose.yml -f docker-compose.nginx.yml \
  up -d --build
```

只有宿主的 `LITE_NGINX_HOST_PATH` 真实存在时才应启用该覆盖；一键安装脚本会自动判断。

容器默认限制为 512 MiB 内存、1 CPU，`/tmp` 是上限 128 MiB 的 tmpfs。由于大于 128 KiB 的请求体会存入已解链的临时文件以保持原字节重放，`TMPFS_SIZE` 必须大于单个 `LITE_MAX_BODY_MIB`；如允许多个大型工具/图片请求并发，还要同时增加 `TMPFS_SIZE` 和 `MEMORY_LIMIT`。tmpfs 只在实际写入时占用内存，默认上限不代表启动即预占 128 MiB。Docker 日志默认限制为 3 个、每个 10 MiB；停止容器时保留 30 秒宽限，使应用有时间执行最长 15 秒的在途请求排空。

数据存放在 Docker 卷 `friendgate_data`。直接复制 SQLite 卷属于“原机密钥备份”：要在停止写入的一致状态下复制，并且必须一起保存当前 `LITE_MASTER_KEY`。跨环境迁移应使用下面的加密可迁移备份，不需要把旧环境主密钥发到新服务器。

## 加密可迁移备份

后台“系统与记录”可直接导出 `.fgbackup` 并导入到另一个 FriendGate Lite 环境。这是业务数据全量迁移：包含管理员账号与 TOTP、ChatGPT OAuth 凭据、账号额度与模型快照、API Key、邀请、IP 授权/封禁、安全配置、使用记录和审计记录；不包含临时的后台登录 Session。

- 导出口令必须为 12–4096 字节。文件通过 PBKDF2-HMAC-SHA256（600,000 次）派生密钥，再用 AES-256-GCM 分块认证加密；口令本身不会被服务器保存。
- 在备份文件中，源环境主密钥只存在加密负载内。导入时会解密每个受保护字段，再用目标环境自己的 `LITE_MASTER_KEY` 重新加密，所以新服务器可以使用全新主密钥。
- 导入会先验证文件认证标签、SQLite 完整性、外键、管理员密码/TOTP 和安全配置，然后在事务中替换数据；校验失败不提交。如果备份中的全局封禁会立即锁住当前导入管理员 IP，系统会拒绝导入。
- 成功导入前会停止新请求并排空/取消在途请求；导入后所有后台 Session 失效，需要用备份中的管理员凭据重新登录。

建议在相同或更新的 FriendGate Lite 版本中导入，导入前先为目标环境再导出一份可回退备份。备份文件和解密口令应分开保管。

## 空服务器 Bash 一键安装

脚本支持 Debian/Ubuntu、RHEL 系、Alpine，自动安装 Docker、Compose、curl、git、openssl，生成管理员密码与主密钥并构建启动。缺少发行版 Compose 包时，脚本内置的官方 Compose 二进制回退支持 `x86_64` 和 `aarch64`：

```bash
sudo bash deploy/lite/install.sh
```

从 GitHub 原始链接管道安装时，需要显式告诉脚本你的 fork，避免把代码装错仓库：

```bash
curl -fsSL https://raw.githubusercontent.com/YOU/REPO/main/deploy/lite/install.sh \
  | sudo env FRIENDGATE_REPO_URL=https://github.com/YOU/REPO.git \
      FRIENDGATE_PUBLIC_HOST=你的服务器IP bash
```

如果该仓库的 `FriendGate Lite` Actions 已经发布 GHCR 镜像，可在同一条管道安装命令中指定它，脚本将拉取多架构镜像而不在 1H2G 服务器上编译：

```bash
curl -fsSL https://raw.githubusercontent.com/YOU/REPO/main/deploy/lite/install.sh \
  | sudo env FRIENDGATE_REPO_URL=https://github.com/YOU/REPO.git \
      FRIENDGATE_IMAGE=ghcr.io/you/friendgate:friendgate-v1.0.0 \
      FRIENDGATE_PUBLIC_HOST=你的服务器IP bash
```

镜像必须由你信任的仓库发布；私有 GHCR 包需要在执行脚本前先登录 `ghcr.io`。

脚本会尽力自动探测服务器公网 IPv4/IPv6，并为直连 HTTP 安装写入两个探测 URL；也可显式传入 `FRIENDGATE_PUBLIC_IPV4_HOST`、`FRIENDGATE_PUBLIC_IPV6_HOST`。切换到 HTTPS 后必须改用上面的 A-only/AAAA-only 域名，避免浏览器混合内容拦截。

首次安装会在终端显示随机初始化口令。第一次打开后台时输入该口令，创建最终管理员账号密码并扫描 Microsoft Authenticator 二维码；动态验证码验证成功后，管理员创建接口会从数据库状态上永久关闭。管道安装默认把配置写入 `/opt/friendgate/deploy/lite/.env`；在已检出仓库内直接运行脚本时，则写入当前仓库的 `deploy/lite/.env`。新建配置权限受 `umask 077` 保护。

Nginx 完整性保护会对配置文件路径、权限、符号链接和内容计算 SHA-256。裸机运行默认检查 `/etc/nginx/nginx.conf`、`conf.d`、`sites-enabled`；一键 Docker 安装会先检查宿主 `/etc/nginx`，存在时通过 `docker-compose.nginx.yml` 只读挂载到 `/host-nginx`。宿主未安装时后台显示“不适用（N/A）”，不计为异常；已配置但无权读取才显示监控错误。

## Codex 配置

领取页会给出 Base URL 和 Key。将 Base URL 与 Key 写入 Codex 配置：

`~/.codex/config.toml`：

```toml
model_provider = "friendgate"
model = "REPLACE_WITH_SYNCED_MODEL_ID"

[model_providers.friendgate]
name = "FriendGate"
base_url = "https://api.example.com/v1"
env_key = "FRIENDGATE_API_KEY"
wire_api = "responses"
supports_websockets = true

[features]
responses_websockets_v2 = true
```

终端环境变量：

```bash
export FRIENDGATE_API_KEY='sk-fg_领取到的Key'
codex
```

先在后台完成模型同步，再把 `REPLACE_WITH_SYNCED_MODEL_ID` 替换为后台目录或 `GET /v1/models` 中真实存在的 ID；文档不硬编码一个可能已过期或当前账号无权使用的模型名。

配置指南端口 `8083` 使用独立的 `web/guide` 根目录。页面不会被搜索引擎收录，也不会在未验证前渲染配置内容。输入活动 Key，或上传领取页生成的 PNG 海报即可进入；海报最后一行 RGB 的最低有效位包含 FriendGate 签名标记，服务端会校验签名、Key 状态和停用/删除边界。海报中的 IPv4、IPv6、设备凭证和指南地址均来自领取会话记录；如果探测到双栈，会完整列出两个地址。

指南错误认证按来源 IP 独立计数：24 小时内超过 5 次进入 24 小时指南封禁，32 小时内超过 10 次进入永久指南封禁。封禁写入 SQLite，并由后台的封禁 IP 页面解除；指南封禁不会悄然改变 API Key 的正常 IP/设备授权。

## GitHub 构建

`.github/workflows/friendgate-lite.yml` 会执行竞态测试、Go 静态检查、Bash 语法检查和两套 Compose 配置展开验证，通过后构建 `linux/amd64`、`linux/arm64` 镜像到：

```text
ghcr.io/<仓库所有者>/friendgate:latest
```

可以在 GitHub Actions 中手动运行 `FriendGate Lite`，或推送 `friendgate-v*` 标签发布版本镜像。

如果希望在 1H2G 服务器上避免本地 Go 编译，可在生成 `.env` 后使用 Actions 已发布的多架构镜像（把 `<owner>` 换成小写的仓库所有者）：

```bash
cd deploy/lite
FRIENDGATE_IMAGE=ghcr.io/<owner>/friendgate:latest \
  docker compose --env-file .env pull friendgate
FRIENDGATE_IMAGE=ghcr.io/<owner>/friendgate:latest \
  docker compose --env-file .env up -d --no-build
```

私有 GHCR 包需要先用有 `read:packages` 权限的 Token 执行 `docker login ghcr.io`。正式发布建议使用 `friendgate-v*` 的不变版本标签或镜像 digest，而不是长期追随 `latest`。

## 真实上游验收边界

仓库测试和 GitHub Actions 可以在可控的模拟上游上验证鉴权、账号/会话路由、模型过滤、HTTP/SSE/WebSocket 负载转发、生命周期撤销和加密备份。这些测试不等于某台服务器已经与 ChatGPT 真实上游成功交互。

上线前必须在目标服务器上完成一次真实验收：确认 DNS/TLS 可访问 `chatgpt.com`，使用本人有权管理的 `auth.json` 完成 OAuth 刷新，手动同步额度与模型且后台无错误，然后用领取的 Key 分别发起文本、工具、SSE、WebSocket 及（如账号/模型有权限）生图请求。生图能力来自上游账号和模型，FriendGate 只转发请求与结果，不会为无权账号创造额外权限。

ChatGPT Codex 订阅 OAuth 端点和线上能力可能由上游变更；当官方新增必需请求头、新传输协议或改变授权规则时，仍需要更新和重新验收网关。因此“未知 JSON 字段原样透传”不应被理解为对任何未来官方功能的永久兼容保证。

## 安全注意事项

- 邀请识别码不会明文保存；新建后只显示一次，请与链接分开发送。
- 邀请验证会话同时绑定浏览器 HttpOnly Cookie 和探测到的公网 IPv4/IPv6；设备备注完成前不能生成 Key。
- 双栈地址使用同一设备组加入 Key 白名单；其中一个地址触发自动封禁或由管理员解封时，另一个地址同步处理。
- Key 生成后只有同一领取会话能在 60 秒内再次查看；倒计时结束会清除领取 Cookie、跳转到 Bing，之后邀请页面直接返回 HTTP 410。
- 管理员 Cookie 绑定登录 IP，写操作要求 SameSite Cookie、同源校验和 CSRF Token。
- 管理员 TOTP 密钥以 AES-256-GCM 密文保存，验证码时间片不能重复使用；修改密码会注销全部后台会话。
- 停用/删除 API Key、删除 Key 的 IP 授权、停用/删除 ChatGPT 账号时，数据库状态会先变更以拒绝新请求，再取消已登记的 HTTP/SSE/WebSocket 在途请求。如果 15 秒内未排空，后台会如实返回超时，但密钥/凭据销毁或停用状态不会回滚。
- 404/502、无效 Key 和邀请滥用触发的自动黑名单只拦 API 与邀请端，指南认证失败只拦配置指南端，避免攻击流量反向锁死管理员；管理员手动封禁作用于全部四个监听端口，需从未被封禁的管理员来源进入后台解封，支持临时和永久模式。
- 管理页不会展示 ChatGPT token；请求正文、工具参数和提示词不会写入日志。
- 多人共用同一个 ChatGPT 订阅账号仍可能触发上游官方额度/风控。这里的“不限速”指网关不施加额外 RPM/TPM，不代表能绕过 ChatGPT 官方限制。
- 使用 ChatGPT 订阅凭证做代理可能受 OpenAI 服务条款约束，请仅在你有权管理的账号和用户范围内使用。
