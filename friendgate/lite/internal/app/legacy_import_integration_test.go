package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestLegacyImportPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("INFINITE_AI_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("INFINITE_AI_TEST_POSTGRES_URL is not configured")
	}
	bootstrap, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close()
	schema := "import_" + strings.ReplaceAll(newPlatformID(), "-", "")
	if _, err := bootstrap.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create temporary PostgreSQL schema: %v", err)
	}
	defer func() { _, _ = bootstrap.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) }()
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	dsn += separator + "search_path=" + schema

	key := bytes.Repeat([]byte{0x63}, 32)
	vault, err := NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DatabasePath:        filepath.Join(t.TempDir(), "legacy.db"),
		PlatformDatabaseURL: dsn,
		PlatformDBMaxOpen:   4,
		PlatformDBMaxIdle:   2,
		PlatformDBMaxLife:   time.Minute,
		AdminUsername:       "admin",
		AdminPassword:       "correct-horse-battery-staple",
		MasterKey:           key,
	}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	accountID, err := store.CreateAccount(ctx, Account{
		Name: "migration account", AccessToken: "access-for-import", RefreshToken: "refresh-for-import",
		ChatGPTAccountID: "migration-account-id", ClientID: "migration-client", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO account_models(account_id,model_id,model_json,model_object,owned_by,updated_at) VALUES(?,?,?,?,?,?)`, accountID, "gpt-5.6", `{"id":"gpt-5.6"}`, "model", "openai", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	inviteToken := "migration-invite-token-which-is-long-enough"
	if _, err := store.CreateInvitation(ctx, "Imported User", inviteToken, "225588", accountID, 30, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	claim := "migration-claim-token-which-is-long-enough"
	if _, err := store.VerifyInvitation(ctx, inviteToken, "225588", "203.0.113.10", claim, "migration-probe-token-which-is-long-enough"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInviteDevice(ctx, inviteToken, claim, "203.0.113.10", "migration device"); err != nil {
		t.Fatal(err)
	}
	legacyKey, _, err := store.GenerateInvitedKey(ctx, inviteToken, claim, "203.0.113.10", "sk-migration-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateDesktopUser(ctx, "migration@example.test", "Migration User", "migration-password-which-is-long")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE desktop_users SET api_key_id=? WHERE id=?`, legacyKey.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x09}, 32))
	macEnc, err := vault.Encrypt("02:42:ac:11:00:99", "desktop-device-mac")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO desktop_devices(user_id,public_key,name,platform,mac_hash,mac_enc,registered_ip,last_ip,status,last_seen_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, user.ID, publicKey, "Import workstation", "linux", tokenHash("02:42:ac:11:00:99"), macEnc, "203.0.113.10", "203.0.113.10", "active", time.Now().Unix(), time.Now().Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := store.LogUsage(ctx, legacyKey.ID, accountID, UsageLog{IP: "203.0.113.10", Method: "POST", Path: "/v1/responses", Model: "gpt-5.6", Status: 200, InputTokens: 10, OutputTokens: 20, TotalTokens: 30, RequestID: "legacy-request"}); err != nil {
		t.Fatal(err)
	}
	store.Audit(ctx, "admin", "migration.test", "import", "203.0.113.10", nil)
	if err := store.BanIP(ctx, "198.51.100.10", "migration test", 0, true); err != nil {
		t.Fatal(err)
	}

	dryRun, err := store.ImportLegacyToPlatform(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if !dryRun.Verified || dryRun.Tables["api_keys"].Source != 1 || dryRun.Tables["devices"].Source != 1 {
		t.Fatalf("unexpected dry-run report: %+v", dryRun)
	}
	report, err := store.ImportLegacyToPlatform(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified || report.Tables["usage"].Destination < 1 || report.Tables["users"].Destination < 1 {
		t.Fatalf("unexpected applied report: %+v", report)
	}
	platform := store.Platform()
	var keyPlain, accountSecret, deviceSecret string
	if err := platform.db.QueryRowContext(ctx, `SELECT key_enc FROM api_keys_v2 WHERE id=$1`, legacyPlatformID("api_key", legacyKey.ID)).Scan(&keyPlain); err != nil {
		t.Fatal(err)
	}
	if keyPlain == "" {
		t.Fatal("imported API key ciphertext is unexpectedly empty")
	}
	if value, err := platform.decryptPlatformSecret(keyPlain, "platform-api-key"); err != nil || value != "sk-migration-key" {
		t.Fatalf("imported API key cannot be decrypted: value=%q err=%v", value, err)
	}
	if err := platform.db.QueryRowContext(ctx, `SELECT credential_enc FROM upstream_accounts WHERE id=$1`, legacyPlatformID("upstream_account", accountID)).Scan(&accountSecret); err != nil {
		t.Fatal(err)
	}
	if value, err := platform.decryptPlatformSecret(accountSecret, "platform-upstream-account-credential"); err != nil || !strings.Contains(value, "access-for-import") {
		t.Fatalf("imported upstream credential cannot be decrypted: err=%v", err)
	}
	if err := platform.db.QueryRowContext(ctx, `SELECT mac_enc FROM user_devices WHERE id=$1`, legacyPlatformID("device", 1)).Scan(&deviceSecret); err != nil {
		t.Fatal(err)
	}
	if value, err := platform.decryptPlatformSecret(deviceSecret, "platform-device-mac"); err != nil || value != "02:42:ac:11:00:99" {
		t.Fatalf("imported device MAC cannot be decrypted: value=%q err=%v", value, err)
	}
}
