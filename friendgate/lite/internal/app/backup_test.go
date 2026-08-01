package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const portableTestPassphrase = "portable-backup-password-2026"

type portableTestSystem struct {
	server *Server
	store  *Store
	vault  *Vault
	cfg    Config
}

type portableSeed struct {
	accountID       int64
	keyID           int64
	pendingInviteID int64
	plainKey        string
	pendingToken    string
	adminPassword   string
	totpSecret      string
}

type portableFailingResponseWriter struct {
	header    http.Header
	status    int
	remaining int
	written   int
}

func (w *portableFailingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *portableFailingResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *portableFailingResponseWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.remaining <= 0 {
		return 0, io.ErrClosedPipe
	}
	if len(value) <= w.remaining {
		w.remaining -= len(value)
		w.written += len(value)
		return len(value), nil
	}
	written := w.remaining
	w.remaining = 0
	w.written += written
	return written, io.ErrClosedPipe
}

func newPortableTestSystem(t *testing.T, keyByte byte) *portableTestSystem {
	t.Helper()
	directory := t.TempDir()
	key := bytes.Repeat([]byte{keyByte}, 32)
	vault, err := NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DataDir: directory, DatabasePath: filepath.Join(directory, "friendgate.db"),
		AdminUsername: "bootstrap-admin", AdminPassword: "bootstrap-password-2026", MasterKey: key,
		BanThreshold: 3, BanWindow: time.Minute, BanDuration: time.Hour,
		MaxBodyBytes: 4 << 20, RevealTTL: time.Minute, SessionTTL: time.Hour,
		StickyTTL: time.Hour, AccountCooldown: time.Minute, QuotaSyncInterval: time.Hour,
		UpstreamBaseURL: "https://chatgpt.invalid/backend-api/codex",
	}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &portableTestSystem{server: NewServer(cfg, store, vault), store: store, vault: vault, cfg: cfg}
}

func seedPortableSource(t *testing.T, system *portableTestSystem) portableSeed {
	t.Helper()
	ctx := context.Background()
	seed := portableSeed{
		plainKey:      "sk-fg_portable-source-secret-key",
		pendingToken:  "portable-pending-invitation-token",
		adminPassword: "restored-administrator-password",
		totpSecret:    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
	}
	adminHash, err := passwordHash(seed.adminPassword, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	encryptedTOTP, err := system.vault.Encrypt(seed.totpSecret, "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	if err := system.store.CompleteAdminSetup(ctx, "restored-admin", adminHash, encryptedTOTP, -1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := system.store.NewAdminSession(ctx, "203.0.113.200", time.Hour); err != nil {
		t.Fatal(err)
	}

	seed.accountID, err = system.store.CreateAccount(ctx, Account{
		Name: "portable-account", AccessToken: "portable-access-secret", RefreshToken: "portable-refresh-secret",
		ChatGPTAccountID: "acct-portable", ClientID: "portable-client", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := system.store.db.ExecContext(ctx, `UPDATE accounts SET plan_type='pro',quota_5h_used=41.5,quota_5h_reset_at=?,quota_7d_used=12.25,quota_7d_reset_at=?,quota_updated_at=?,reset_credits=2,reset_credit_times='["2026-08-01T00:00:00Z"]' WHERE id=?`, now+1800, now+86400, now, seed.accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO account_model_snapshots(account_id,manifest_json,updated_at,error) VALUES(?,?,?,'')`, seed.accountID, `{"object":"list","data":[{"id":"gpt-5.2-codex"}]}`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO account_models(account_id,model_id,model_json,model_object,owned_by,updated_at) VALUES(?,?,?,?,?,?)`, seed.accountID, "gpt-5.2-codex", `{"id":"gpt-5.2-codex","object":"model","owned_by":"openai"}`, "model", "openai", now); err != nil {
		t.Fatal(err)
	}

	claimToken := "portable-claimed-invitation-token"
	claimID, err := system.store.CreateInvitation(ctx, "portable-friend", claimToken, "384921", seed.accountID, 100, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	claimSession := "portable-claim-session-token"
	if _, err := system.store.VerifyInvitation(ctx, claimToken, "384921", "203.0.113.31", claimSession, "portable-probe-token"); err != nil {
		t.Fatal(err)
	}
	if err := system.store.SaveInviteDevice(ctx, claimToken, claimSession, "203.0.113.31", "portable workstation"); err != nil {
		t.Fatal(err)
	}
	key, _, err := system.store.GenerateInvitedKey(ctx, claimToken, claimSession, "203.0.113.31", seed.plainKey, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	seed.keyID = key.ID
	if err := system.store.AddKeyIP(ctx, seed.keyID, "2001:db8::31", "portable workstation IPv6"); err != nil {
		t.Fatal(err)
	}
	seed.pendingInviteID, err = system.store.CreateInvitation(ctx, "pending-friend", seed.pendingToken, "917264", seed.accountID, 77, now+7200)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO invitation_ips(invitation_id,ip,family,created_at) VALUES(?,?,?,?)`, seed.pendingInviteID, "2001:db8::99", "ipv6", now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO session_affinities(key_id,session_hash,account_id,expires_at,last_used_at,created_at) VALUES(?,?,?,?,?,?)`, seed.keyID, "portable-session-hash", seed.accountID, now+3600, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO usage_logs(id,key_id,account_id,ip,method,path,model,status,duration_ms,input_tokens,output_tokens,total_tokens,request_id,error,created_at) VALUES(71,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, seed.keyID, seed.accountID, "203.0.113.31", "POST", "/v1/responses", "gpt-5.2-codex", 200, 321, 11, 7, 18, "req-portable", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,target,ip,detail,created_at) VALUES(72,'admin','portable.audit','target','203.0.113.200','{}',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO security_events(id,ip,kind,path,detail,created_at) VALUES(73,'198.51.100.73','portable_event','/probe','detail',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO ip_failures(ip,window_start,attempts,last_attempt) VALUES('198.51.100.74',?,4,?)`, now-10, now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO status_failures(ip,status,window_start,attempts,last_attempt) VALUES('198.51.100.75',404,?,5,?)`, now-10, now); err != nil {
		t.Fatal(err)
	}
	if _, err := system.store.db.ExecContext(ctx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope) VALUES('198.51.100.76','portable ban',5,?,0,'portable-group','all')`, now); err != nil {
		t.Fatal(err)
	}
	if err := system.store.SaveSecurityConfig(ctx, SecurityConfig{ProtectionEnabled: true, NginxProtection: true, Threshold404: 9, Threshold502: 13, WindowMinutes: 7, BanHours: 48}); err != nil {
		t.Fatal(err)
	}
	if err := system.store.SetSetting(ctx, "portable_custom_setting", "portable-value"); err != nil {
		t.Fatal(err)
	}
	var claimed int64
	if err := system.store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM invitations WHERE id=? AND status='claimed'", claimID).Scan(&claimed); err != nil || claimed != 1 {
		t.Fatalf("claimed invitation=%d err=%v", claimed, err)
	}
	return seed
}

func createPortableBackup(t *testing.T, system *portableTestSystem) (string, []byte) {
	t.Helper()
	path, size, err := system.store.createPortableBackupFile(context.Background(), portableTestPassphrase, filepath.Dir(system.cfg.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) != size {
		t.Fatalf("backup bytes=%d reported=%d", len(body), size)
	}
	return path, body
}

func createUncheckedPortableBackup(t *testing.T, system *portableTestSystem) string {
	t.Helper()
	snapshotPath, err := system.store.createSessionFreeSQLiteSnapshot(context.Background(), filepath.Dir(system.cfg.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(snapshotPath)
	path := filepath.Join(t.TempDir(), "unchecked.fgbackup")
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePortableBackupEnvelope(output, snapshotPath, system.cfg.MasterKey, portableTestPassphrase); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedPortableTargetSentinel(t *testing.T, system *portableTestSystem) (int64, int64, string) {
	t.Helper()
	ctx := context.Background()
	accountID, key := createTestAccountAndKey(t, system.store, "target-sentinel", "sk-fg_target-sentinel", "203.0.113.220")
	if err := system.store.SetSetting(ctx, "target_sentinel", "must-survive-failed-restore"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := system.store.NewAdminSession(ctx, "203.0.113.220", time.Hour); err != nil {
		t.Fatal(err)
	}
	return accountID, key.ID, "sk-fg_target-sentinel"
}

func assertPortableTargetSentinel(t *testing.T, system *portableTestSystem, accountID, keyID int64, plainKey string) {
	t.Helper()
	var setting string
	if err := system.store.db.QueryRow(`SELECT value FROM settings WHERE key='target_sentinel'`).Scan(&setting); err != nil || setting != "must-survive-failed-restore" {
		t.Fatalf("target setting=%q err=%v", setting, err)
	}
	if copied, err := system.store.CopyAPIKey(context.Background(), keyID); err != nil || copied != plainKey {
		t.Fatalf("target key=%q err=%v", copied, err)
	}
	if _, err := system.store.GetAccount(context.Background(), accountID); err != nil {
		t.Fatalf("target account disappeared: %v", err)
	}
}

func TestPortableBackupMigratesAllDataAcrossVaultKeys(t *testing.T) {
	source := newPortableTestSystem(t, 0x31)
	seed := seedPortableSource(t, source)
	backupPath, backupBody := createPortableBackup(t, source)
	for name, secret := range map[string][]byte{
		"source master key": source.cfg.MasterKey,
		"API key":           []byte(seed.plainKey),
		"invite token":      []byte(seed.pendingToken),
		"access token":      []byte("portable-access-secret"),
		"passphrase":        []byte(portableTestPassphrase),
	} {
		if bytes.Contains(backupBody, secret) {
			t.Fatalf("encrypted backup exposes %s", name)
		}
	}

	// The decrypted SQLite snapshot itself must already be session-free, not
	// merely rely on the target restore deleting sessions later.
	snapshotPath, sourceKey, err := decryptPortableBackupFile(backupPath, portableTestPassphrase, filepath.Dir(source.cfg.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(snapshotPath)
	defer zeroPortableBytes(sourceKey)
	snapshotDB, err := openPortableSQLite(snapshotPath, true)
	if err != nil {
		t.Fatal(err)
	}
	var snapshotSessions int
	if err := snapshotDB.QueryRow(`SELECT COUNT(*) FROM admin_sessions`).Scan(&snapshotSessions); err != nil {
		t.Fatal(err)
	}
	_ = snapshotDB.Close()
	if snapshotSessions != 0 {
		t.Fatalf("snapshot retained %d administrator sessions", snapshotSessions)
	}

	target := newPortableTestSystem(t, 0x72)
	oldAccount, _, _ := seedPortableTargetSentinel(t, target)
	summary, err := target.server.restorePortableBackupFile(context.Background(), backupPath, portableTestPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Tables != len(portableTableSpecs) || summary.Rows == 0 || summary.CancelledRequests != 0 || summary.CacheDegraded {
		t.Fatalf("restore summary=%+v", summary)
	}
	if _, err := target.store.GetAccount(context.Background(), oldAccount); err == nil && oldAccount != seed.accountID {
		t.Fatal("target-only account survived successful replacement")
	}

	account, err := target.store.GetAccount(context.Background(), seed.accountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.AccessToken != "portable-access-secret" || account.RefreshToken != "portable-refresh-secret" || account.PlanType != "pro" || account.Quota5HUsed != 41.5 || account.ResetCredits != 2 {
		t.Fatalf("restored account=%+v", account)
	}
	if copied, err := target.store.CopyAPIKey(context.Background(), seed.keyID); err != nil || copied != seed.plainKey {
		t.Fatalf("copied key=%q err=%v", copied, err)
	}
	if key, err := target.store.AuthorizeKey(context.Background(), seed.plainKey, "203.0.113.31"); err != nil || key.ID != seed.keyID {
		t.Fatalf("authorize restored key=%+v err=%v", key, err)
	}
	if _, err := target.store.AuthorizeKey(context.Background(), seed.plainKey, "2001:db8::31"); err != nil {
		t.Fatalf("authorize restored IPv6: %v", err)
	}
	var boundAccount int64
	if err := target.store.db.QueryRow(`SELECT account_id FROM api_keys WHERE id=?`, seed.keyID).Scan(&boundAccount); err != nil || boundAccount != seed.accountID {
		t.Fatalf("key account=%d err=%v", boundAccount, err)
	}

	invitations, err := target.store.ListInvitations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foundPending := false
	for _, invitation := range invitations {
		if invitation.ID == seed.pendingInviteID {
			foundPending = invitation.Status == "pending" && invitation.Token == seed.pendingToken && len(invitation.ObservedIPs) == 1
		}
	}
	if !foundPending {
		t.Fatalf("pending invitation was not decryptable after restore: %+v", invitations)
	}
	if target.store.AdminUsername(context.Background()) != "restored-admin" || !target.store.VerifyAdmin(context.Background(), "restored-admin", seed.adminPassword) {
		t.Fatal("administrator username/password were not restored")
	}
	if err := target.store.CheckAdminTOTP(context.Background()); err != nil {
		t.Fatalf("restored TOTP is unusable: %v", err)
	}
	var sessions int
	if err := target.store.db.QueryRow(`SELECT COUNT(*) FROM admin_sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("target sessions=%d err=%v", sessions, err)
	}
	for query, want := range map[string]int{
		`SELECT COUNT(*) FROM account_models WHERE account_id=1 AND model_id='gpt-5.2-codex'`:                      1,
		`SELECT COUNT(*) FROM account_model_snapshots WHERE account_id=1 AND manifest_json LIKE '%gpt-5.2-codex%'`: 1,
		`SELECT COUNT(*) FROM session_affinities WHERE session_hash='portable-session-hash'`:                       1,
		`SELECT COUNT(*) FROM usage_logs WHERE id=71 AND total_tokens=18`:                                          1,
		`SELECT COUNT(*) FROM audit_logs WHERE id=72 AND action='portable.audit'`:                                  1,
		`SELECT COUNT(*) FROM security_events WHERE id=73 AND kind='portable_event'`:                               1,
		`SELECT COUNT(*) FROM ip_failures WHERE ip='198.51.100.74' AND attempts=4`:                                 1,
		`SELECT COUNT(*) FROM status_failures WHERE ip='198.51.100.75' AND status=404 AND attempts=5`:              1,
		`SELECT COUNT(*) FROM banned_ips WHERE ip='198.51.100.76' AND scope='all'`:                                 1,
	} {
		var got int
		if err := target.store.db.QueryRow(query).Scan(&got); err != nil || got != want {
			t.Fatalf("query %q got=%d want=%d err=%v", query, got, want, err)
		}
	}
	if got := target.store.SecurityConfig(context.Background()); !got.ProtectionEnabled || got.Threshold404 != 9 || got.Threshold502 != 13 {
		t.Fatalf("security config=%+v", got)
	}
	if !target.server.isBannedCached("198.51.100.76", "api") {
		t.Fatal("ban cache was not refreshed from restored rows")
	}
	var sourceCipher, targetCipher string
	if err := source.store.db.QueryRow(`SELECT access_token_enc FROM accounts WHERE id=?`, seed.accountID).Scan(&sourceCipher); err != nil {
		t.Fatal(err)
	}
	if err := target.store.db.QueryRow(`SELECT access_token_enc FROM accounts WHERE id=?`, seed.accountID).Scan(&targetCipher); err != nil {
		t.Fatal(err)
	}
	if sourceCipher == targetCipher {
		t.Fatal("account ciphertext was copied instead of re-encrypted")
	}
}

func TestPortableBackupRejectsWrongPassphraseAndTamperingAtomically(t *testing.T) {
	source := newPortableTestSystem(t, 0x24)
	seedPortableSource(t, source)
	backupPath, backupBody := createPortableBackup(t, source)

	t.Run("wrong passphrase", func(t *testing.T) {
		target := newPortableTestSystem(t, 0x25)
		accountID, keyID, key := seedPortableTargetSentinel(t, target)
		if _, err := target.server.restorePortableBackupFile(context.Background(), backupPath, "wrong-portable-password"); !errors.Is(err, errInvalidPortableBackup) {
			t.Fatalf("error=%v", err)
		}
		assertPortableTargetSentinel(t, target, accountID, keyID, key)
	})

	t.Run("authenticated ciphertext tamper", func(t *testing.T) {
		target := newPortableTestSystem(t, 0x26)
		accountID, keyID, key := seedPortableTargetSentinel(t, target)
		tampered := append([]byte(nil), backupBody...)
		tampered[len(tampered)-17] ^= 0x80
		path := filepath.Join(t.TempDir(), "tampered.fgbackup")
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := target.server.restorePortableBackupFile(context.Background(), path, portableTestPassphrase); !errors.Is(err, errInvalidPortableBackup) {
			t.Fatalf("error=%v", err)
		}
		assertPortableTargetSentinel(t, target, accountID, keyID, key)
	})
}

func TestPortableBackupCorruptSourceVaultValueRollsBackTarget(t *testing.T) {
	source := newPortableTestSystem(t, 0x41)
	seed := seedPortableSource(t, source)
	if _, err := source.store.db.Exec(`UPDATE accounts SET access_token_enc='corrupt-ciphertext' WHERE id=?`, seed.accountID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.store.createPortableBackupFile(context.Background(), portableTestPassphrase, filepath.Dir(source.cfg.DatabasePath)); err == nil {
		t.Fatal("export accepted a source ciphertext that cannot be restored")
	}
	backupPath := createUncheckedPortableBackup(t, source)
	target := newPortableTestSystem(t, 0x42)
	accountID, keyID, key := seedPortableTargetSentinel(t, target)
	if _, err := target.server.restorePortableBackupFile(context.Background(), backupPath, portableTestPassphrase); !errors.Is(err, errInvalidPortableBackup) {
		t.Fatalf("error=%v", err)
	}
	assertPortableTargetSentinel(t, target, accountID, keyID, key)
}

func TestPortableBackupAcceptsLegacySnapshotWithoutModelTables(t *testing.T) {
	source := newPortableTestSystem(t, 0x51)
	seed := seedPortableSource(t, source)
	snapshotPath, err := source.store.createSessionFreeSQLiteSnapshot(context.Background(), filepath.Dir(source.cfg.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(snapshotPath)
	snapshotDB, err := openPortableSQLite(snapshotPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotDB.Exec(`DROP TABLE account_models`); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotDB.Exec(`DROP TABLE account_model_snapshots`); err != nil {
		t.Fatal(err)
	}
	if err := snapshotDB.Close(); err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(t.TempDir(), "legacy-without-models.fgbackup")
	envelope, err := os.OpenFile(envelopePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePortableBackupEnvelope(envelope, snapshotPath, source.cfg.MasterKey, portableTestPassphrase); err != nil {
		_ = envelope.Close()
		t.Fatal(err)
	}
	if err := envelope.Close(); err != nil {
		t.Fatal(err)
	}

	target := newPortableTestSystem(t, 0x52)
	targetAccount := createTestAccount(t, target.store, "stale-model-account", "stale-access", "acct-stale")
	if _, err := target.store.db.Exec(`INSERT INTO account_model_snapshots(account_id,manifest_json,updated_at,error) VALUES(?, '{}', 1, '')`, targetAccount); err != nil {
		t.Fatal(err)
	}
	if _, err := target.store.db.Exec(`INSERT INTO account_models(account_id,model_id,model_json,updated_at) VALUES(?, 'stale-model', '{}', 1)`, targetAccount); err != nil {
		t.Fatal(err)
	}
	summary, err := target.server.restorePortableBackupFile(context.Background(), envelopePath, portableTestPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Tables != len(portableTableSpecs)-2 {
		t.Fatalf("tables=%d", summary.Tables)
	}
	var models, snapshots int
	if err := target.store.db.QueryRow(`SELECT COUNT(*) FROM account_models`).Scan(&models); err != nil {
		t.Fatal(err)
	}
	if err := target.store.db.QueryRow(`SELECT COUNT(*) FROM account_model_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if models != 0 || snapshots != 0 {
		t.Fatalf("legacy restore left models=%d snapshots=%d", models, snapshots)
	}
	if account, err := target.store.GetAccount(context.Background(), seed.accountID); err != nil || account.Name != "portable-account" {
		t.Fatalf("legacy account=%+v err=%v", account, err)
	}
}

func TestPortableBackupRejectsAdministratorLockoutStateBeforeAdmission(t *testing.T) {
	for name, damage := range map[string]func(*portableTestSystem){
		"password hash": func(system *portableTestSystem) {
			if _, err := system.store.db.Exec(`UPDATE settings SET value='not-a-password-hash' WHERE key='admin_password_hash'`); err != nil {
				t.Fatal(err)
			}
		},
		"TOTP plaintext": func(system *portableTestSystem) {
			encrypted, err := system.vault.Encrypt("TOO-SHORT", "admin-totp")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := system.store.db.Exec(`UPDATE settings SET value=? WHERE key='admin_totp_secret_enc'`, encrypted); err != nil {
				t.Fatal(err)
			}
		},
		"initialization marker": func(system *portableTestSystem) {
			if _, err := system.store.db.Exec(`DELETE FROM settings WHERE key='admin_initialized_at'`); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			source := newPortableTestSystem(t, 0x53)
			seedPortableSource(t, source)
			damage(source)
			if _, _, err := source.store.createPortableBackupFile(context.Background(), portableTestPassphrase, filepath.Dir(source.cfg.DatabasePath)); err == nil {
				t.Fatal("export accepted administrator state that would lock out recovery")
			}
			backupPath := createUncheckedPortableBackup(t, source)
			target := newPortableTestSystem(t, 0x54)
			accountID, keyID, key := seedPortableTargetSentinel(t, target)
			if _, err := target.server.restorePortableBackupFile(context.Background(), backupPath, portableTestPassphrase); !errors.Is(err, errInvalidPortableBackup) {
				t.Fatalf("restore error=%v", err)
			}
			assertPortableTargetSentinel(t, target, accountID, keyID, key)
		})
	}
}

type portableMultipartField struct {
	name     string
	filename string
	value    []byte
}

func portableMultipartRequest(t *testing.T, fields []portableMultipartField) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, field := range fields {
		var part io.Writer
		var err error
		if field.filename != "" {
			part, err = writer.CreateFormFile(field.name, field.filename)
		} else {
			part, err = writer.CreateFormField(field.name)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(field.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://admin.local/api/system/backup/import", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func authorizePortableBackupRequest(t *testing.T, system *portableTestSystem, request *http.Request) {
	t.Helper()
	token, csrf, err := system.store.NewAdminSession(context.Background(), "192.0.2.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: adminCookieName, Value: token})
	request.Header.Set("X-CSRF-Token", csrf)
}

func TestPortableBackupHTTPResponsesAndMultipartValidation(t *testing.T) {
	source := newPortableTestSystem(t, 0x61)
	seed := seedPortableSource(t, source)
	exportRequest := httptest.NewRequest(http.MethodPost, "http://admin.local/api/system/backup/export", strings.NewReader(`{"passphrase":"`+portableTestPassphrase+`"}`))
	exportRequest.Header.Set("Content-Type", "application/json")
	authorizePortableBackupRequest(t, source, exportRequest)
	exportRecorder := httptest.NewRecorder()
	source.server.adminExportBackup(exportRecorder, exportRequest)
	if exportRecorder.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportRecorder.Code, exportRecorder.Body.String())
	}
	if !strings.Contains(exportRecorder.Header().Get("Cache-Control"), "no-store") || exportRecorder.Header().Get("Pragma") != "no-cache" || !strings.Contains(exportRecorder.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export headers=%v", exportRecorder.Header())
	}
	backupBody := append([]byte(nil), exportRecorder.Body.Bytes()...)
	if bytes.Contains(backupBody, []byte(seed.plainKey)) || bytes.Contains(backupBody, []byte(portableTestPassphrase)) {
		t.Fatal("HTTP export leaked a secret")
	}

	target := newPortableTestSystem(t, 0x62)
	seedPortableTargetSentinel(t, target)
	importRequest := portableMultipartRequest(t, []portableMultipartField{
		{name: "backup", filename: "portable.fgbackup", value: backupBody},
		{name: "passphrase", value: []byte(portableTestPassphrase)},
	})
	authorizePortableBackupRequest(t, target, importRequest)
	importRecorder := httptest.NewRecorder()
	target.server.adminImportBackup(importRecorder, importRequest)
	if importRecorder.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importRecorder.Code, importRecorder.Body.String())
	}
	var response struct {
		OK                bool  `json:"ok"`
		RequiresRelogin   bool  `json:"requires_relogin"`
		Tables            int   `json:"tables"`
		Rows              int64 `json:"rows"`
		CancelledRequests int   `json:"cancelled_requests"`
		CacheDegraded     bool  `json:"cache_degraded"`
	}
	if err := json.Unmarshal(importRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || !response.RequiresRelogin || response.Tables != len(portableTableSpecs) || response.Rows == 0 || response.CancelledRequests != 0 || response.CacheDegraded {
		t.Fatalf("import response=%+v", response)
	}
	cookies := importRecorder.Result().Cookies()
	foundExpired := false
	for _, cookie := range cookies {
		if cookie.Name == adminCookieName && cookie.MaxAge < 0 {
			foundExpired = true
		}
	}
	if !foundExpired {
		t.Fatalf("restore did not expire admin cookie: %+v", cookies)
	}
	var sessions int
	if err := target.store.db.QueryRow(`SELECT COUNT(*) FROM admin_sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}

	validationTarget := newPortableTestSystem(t, 0x63)
	invalidCases := map[string][]portableMultipartField{
		"missing passphrase": {{name: "backup", filename: "backup.fgbackup", value: backupBody}},
		"missing backup":     {{name: "passphrase", value: []byte(portableTestPassphrase)}},
		"duplicate passphrase": {
			{name: "passphrase", value: []byte(portableTestPassphrase)},
			{name: "passphrase", value: []byte(portableTestPassphrase)},
			{name: "backup", filename: "backup.fgbackup", value: backupBody},
		},
		"duplicate backup": {
			{name: "passphrase", value: []byte(portableTestPassphrase)},
			{name: "backup", filename: "backup.fgbackup", value: backupBody},
			{name: "backup", filename: "backup2.fgbackup", value: backupBody},
		},
		"unknown field": {
			{name: "passphrase", value: []byte(portableTestPassphrase)},
			{name: "backup", filename: "backup.fgbackup", value: backupBody},
			{name: "role", value: []byte("admin")},
		},
	}
	for name, fields := range invalidCases {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			validationTarget.server.adminImportBackup(recorder, portableMultipartRequest(t, fields))
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_backup_upload") {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestPortableExportAuditRequiresCompleteResponseStream(t *testing.T) {
	system := newPortableTestSystem(t, 0x7a)
	seedPortableSource(t, system)
	newRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "http://admin.local/api/system/backup/export", strings.NewReader(`{"passphrase":"`+portableTestPassphrase+`"}`))
		request.Header.Set("Content-Type", "application/json")
		authorizePortableBackupRequest(t, system, request)
		return request
	}
	exportedAudits := func() int {
		var count int
		if err := system.store.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action='backup.exported'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	failingWriter := &portableFailingResponseWriter{remaining: 64}
	system.server.adminExportBackup(failingWriter, newRequest())
	if failingWriter.status != http.StatusOK || failingWriter.written != 64 {
		t.Fatalf("failed stream status=%d bytes=%d", failingWriter.status, failingWriter.written)
	}
	if count := exportedAudits(); count != 0 {
		t.Fatalf("partial response recorded %d successful exports", count)
	}
	if !system.server.hasSecurityRuntimeFailure("backup_export_stream") {
		t.Fatal("partial response did not expose a backup stream health failure")
	}

	recorder := httptest.NewRecorder()
	system.server.adminExportBackup(recorder, newRequest())
	if recorder.Code != http.StatusOK {
		t.Fatalf("complete stream status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Length") != strconv.Itoa(recorder.Body.Len()) {
		t.Fatalf("content-length=%q bytes=%d", recorder.Header().Get("Content-Length"), recorder.Body.Len())
	}
	if count := exportedAudits(); count != 1 {
		t.Fatalf("complete response recorded %d successful exports", count)
	}
	if system.server.hasSecurityRuntimeFailure("backup_export_stream") {
		t.Fatal("successful response did not clear the backup stream health failure")
	}
}

func TestPortableConcurrentImportsRevalidateSessionInsideSerializationLock(t *testing.T) {
	source := newPortableTestSystem(t, 0x64)
	seedPortableSource(t, source)
	_, backupBody := createPortableBackup(t, source)
	target := newPortableTestSystem(t, 0x65)
	token, csrf, err := target.store.NewAdminSession(context.Background(), "192.0.2.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func() *http.Request {
		request := portableMultipartRequest(t, []portableMultipartField{
			{name: "passphrase", value: []byte(portableTestPassphrase)},
			{name: "backup", filename: "backup.fgbackup", value: backupBody},
		})
		request.AddCookie(&http.Cookie{Name: adminCookieName, Value: token})
		request.Header.Set("X-CSRF-Token", csrf)
		return request
	}
	recorders := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	requests := []*http.Request{newRequest(), newRequest()}
	done := make(chan struct{}, len(recorders))
	portableImportMu.Lock()
	for index := range recorders {
		go func(index int) {
			target.server.adminImportBackup(recorders[index], requests[index])
			done <- struct{}{}
		}(index)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(target.cfg.DatabasePath), ".friendgate-upload-*.fgbackup"))
		if globErr != nil {
			portableImportMu.Unlock()
			t.Fatal(globErr)
		}
		if len(matches) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			portableImportMu.Unlock()
			t.Fatal("concurrent imports did not reach the serialization boundary")
		}
		time.Sleep(time.Millisecond)
	}
	portableImportMu.Unlock()
	for range recorders {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("concurrent import did not finish")
		}
	}
	statuses := map[int]int{}
	for _, recorder := range recorders {
		statuses[recorder.Code]++
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusUnauthorized] != 1 {
		t.Fatalf("concurrent import statuses=%v bodies=%q / %q", statuses, recorders[0].Body.String(), recorders[1].Body.String())
	}
}

func TestPortableImportRejectsBackupThatWouldBanCurrentAdministrator(t *testing.T) {
	source := newPortableTestSystem(t, 0x68)
	seedPortableSource(t, source)
	now := time.Now().Unix()
	if _, err := source.store.db.Exec(`INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope)
VALUES('192.0.2.1','cross-environment administrator ban',9,?,0,'admin-lockout-group','all')`, now); err != nil {
		t.Fatal(err)
	}
	_, backupBody := createPortableBackup(t, source)
	target := newPortableTestSystem(t, 0x69)
	accountID, keyID, key := seedPortableTargetSentinel(t, target)
	request := portableMultipartRequest(t, []portableMultipartField{
		{name: "passphrase", value: []byte(portableTestPassphrase)},
		{name: "backup", filename: "self-ban.fgbackup", value: backupBody},
	})
	authorizePortableBackupRequest(t, target, request)
	recorder := httptest.NewRecorder()
	target.server.adminImportBackup(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "restore_would_ban_admin") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertPortableTargetSentinel(t, target, accountID, keyID, key)
}

func TestPortableImportFinalAuthorizationDetectsConcurrentSessionRevocation(t *testing.T) {
	source := newPortableTestSystem(t, 0x6a)
	seedPortableSource(t, source)
	_, backupBody := createPortableBackup(t, source)
	target := newPortableTestSystem(t, 0x6b)
	accountID, keyID, key := seedPortableTargetSentinel(t, target)
	token, csrf, err := target.store.NewAdminSession(context.Background(), "192.0.2.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := portableMultipartRequest(t, []portableMultipartField{
		{name: "passphrase", value: []byte(portableTestPassphrase)},
		{name: "backup", filename: "revoked-session.fgbackup", value: backupBody},
	})
	request.AddCookie(&http.Cookie{Name: adminCookieName, Value: token})
	request.Header.Set("X-CSRF-Token", csrf)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	// This read lock models a logout/password-change request admitted before the
	// restore flag closed the generation. It may revoke the session, then exits;
	// the importer must re-check only after acquiring the exclusive gate.
	target.server.restoreGate.RLock()
	gateHeld := true
	defer func() {
		if gateHeld {
			target.server.restoreGate.RUnlock()
		}
	}()
	go func() {
		target.server.adminImportBackup(recorder, request)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		target.server.keyRequestMu.Lock()
		active := target.server.restoreInProgress
		target.server.keyRequestMu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("import did not close generation admission")
		}
		time.Sleep(time.Millisecond)
	}
	if err := target.store.DeleteAdminSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	target.server.restoreGate.RUnlock()
	gateHeld = false
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("import did not finish after concurrent revocation")
	}
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "admin_session_expired") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertPortableTargetSentinel(t, target, accountID, keyID, key)
}

func TestPortableExportAndImportUseNonCircularSerialization(t *testing.T) {
	source := newPortableTestSystem(t, 0x66)
	seedPortableSource(t, source)
	_, backupBody := createPortableBackup(t, source)
	target := newPortableTestSystem(t, 0x67)
	seedPortableTargetSentinel(t, target)
	adminHash, err := passwordHash("target-export-administrator", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	encryptedTOTP, err := target.vault.Encrypt("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "admin-totp")
	if err != nil {
		t.Fatal(err)
	}
	if err := target.store.CompleteAdminSetup(context.Background(), "target-export-admin", adminHash, encryptedTOTP, -1); err != nil {
		t.Fatal(err)
	}
	token, csrf, err := target.store.NewAdminSession(context.Background(), "192.0.2.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authorize := func(request *http.Request) {
		request.AddCookie(&http.Cookie{Name: adminCookieName, Value: token})
		request.Header.Set("X-CSRF-Token", csrf)
	}
	exportRequest := httptest.NewRequest(http.MethodPost, "http://admin.local/api/system/backup/export", strings.NewReader(`{"passphrase":"`+portableTestPassphrase+`"}`))
	exportRequest.Header.Set("Content-Type", "application/json")
	authorize(exportRequest)
	importRequest := portableMultipartRequest(t, []portableMultipartField{
		{name: "passphrase", value: []byte(portableTestPassphrase)},
		{name: "backup", filename: "backup.fgbackup", value: backupBody},
	})
	authorize(importRequest)
	exportRecorder, importRecorder := httptest.NewRecorder(), httptest.NewRecorder()
	exportDone, importDone := make(chan struct{}), make(chan struct{})

	// Model an export which already passed commonHeaders and therefore owns the
	// old generation's read gate, then make it wait on only the export mutex.
	target.server.restoreGate.RLock()
	gateHeld := true
	portableExportMu.Lock()
	exportLockHeld := true
	defer func() {
		if exportLockHeld {
			portableExportMu.Unlock()
		}
		if gateHeld {
			target.server.restoreGate.RUnlock()
		}
	}()
	go func() {
		target.server.adminExportBackup(exportRecorder, exportRequest)
		close(exportDone)
	}()
	go func() {
		target.server.adminImportBackup(importRecorder, importRequest)
		close(importDone)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		target.server.keyRequestMu.Lock()
		active := target.server.restoreInProgress
		target.server.keyRequestMu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("import did not reach restore generation boundary")
		}
		time.Sleep(time.Millisecond)
	}
	portableExportMu.Unlock()
	exportLockHeld = false
	select {
	case <-exportDone:
	case <-time.After(10 * time.Second):
		t.Fatal("export remained blocked by import")
	}
	target.server.restoreGate.RUnlock()
	gateHeld = false
	select {
	case <-importDone:
	case <-time.After(15 * time.Second):
		t.Fatal("import remained blocked after export released its generation")
	}
	if exportRecorder.Code != http.StatusOK || importRecorder.Code != http.StatusOK {
		t.Fatalf("export=%d %s import=%d %s", exportRecorder.Code, exportRecorder.Body.String(), importRecorder.Code, importRecorder.Body.String())
	}
}

func TestPortableRestoreGenerationFenceDrainsBeforeDatabaseMutation(t *testing.T) {
	source := newPortableTestSystem(t, 0x71)
	seedPortableSource(t, source)
	backupPath, _ := createPortableBackup(t, source)
	target := newPortableTestSystem(t, 0x73)
	accountID, keyID, key := seedPortableTargetSentinel(t, target)

	if !target.server.beginRuntimeOperation() {
		t.Fatal("could not enter target generation")
	}
	restoreResult := make(chan error, 1)
	go func() {
		_, err := target.server.restorePortableBackupFile(context.Background(), backupPath, portableTestPassphrase)
		restoreResult <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		target.server.keyRequestMu.Lock()
		active := target.server.restoreInProgress
		target.server.keyRequestMu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restore never entered maintenance mode")
		}
		time.Sleep(time.Millisecond)
	}
	request := httptest.NewRequest(http.MethodPost, "http://api.local/v1/responses", nil)
	if _, _, err := target.server.beginKeyRequest(request, keyID, accountID, "203.0.113.220"); !errors.Is(err, errBackupRestoreActive) {
		t.Fatalf("new key request error=%v", err)
	}
	// The restore is waiting on this old-generation operation, so the sentinel
	// must still be intact until it is explicitly released.
	assertPortableTargetSentinel(t, target, accountID, keyID, key)
	select {
	case err := <-restoreResult:
		t.Fatalf("restore completed before old operation drained: %v", err)
	default:
	}
	target.server.restoreGate.RUnlock()
	select {
	case err := <-restoreResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("restore did not finish after old operation drained")
	}
	target.server.keyRequestMu.Lock()
	active := target.server.restoreInProgress
	target.server.keyRequestMu.Unlock()
	if active {
		t.Fatal("restore flag was not cleared")
	}
}
