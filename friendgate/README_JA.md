# FriendGate Lite

FriendGate Lite は、ChatGPT Codex アカウント向けの独立した軽量ゲートウェイです。認証情報を暗号化して保存し、API、管理画面、招待ページ、設定ガイドを別ポートで提供します。

## 主な機能

- ChatGPT OAuth `auth.json` の管理、トークン更新、利用量同期。
- API キーごとのアカウント／セッション分離、ハッシュ認証、即時無効化。
- 招待制キー、IPv4/IPv6、デバイス資格情報、ワンタイム発行、ポスター資格情報。
- Responses、SSE、WebSocket、ツール JSON、生画像パラメータの透過。
- リアルタイムの使用量、モデル、監査、セキュリティ、バックアップ管理。
- Go 1 プロセス + SQLite WAL。1 vCPU / 2 GB のサーバー向け。

## 起動

```bash
cp deploy/lite/.env.example deploy/lite/.env
# .env に管理者パスワード、LITE_MASTER_KEY、公開 URL を設定
docker compose --env-file deploy/lite/.env \
  -f deploy/lite/docker-compose.yml up -d --build
```

空のサーバーでは次を実行できます。

```bash
sudo bash deploy/lite/install.sh
```

詳細は [FRIENDGATE_CN.md](FRIENDGATE_CN.md) を参照してください。
