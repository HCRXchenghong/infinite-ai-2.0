package app

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound                = errors.New("not found")
	ErrInvalidInvite           = errors.New("invalid or expired invitation")
	ErrInvalidCode             = errors.New("invalid invitation recognition code")
	ErrQuotaExceeded           = errors.New("quota exceeded")
	ErrIPNotAllowed            = errors.New("ip not allowed")
	ErrDeviceNotAllowed        = errors.New("device credential not allowed")
	ErrKeyInactive             = errors.New("api key is inactive")
	ErrInviteConsumed          = errors.New("invitation already consumed")
	ErrNoAccount               = errors.New("no available ChatGPT account")
	ErrProtectedIP             = errors.New("protected IP cannot be banned")
	ErrInvalidAdminCredentials = errors.New("invalid administrator credentials")
	ErrAdminSetupClosed        = errors.New("administrator setup is already closed")
	ErrUserInactive            = errors.New("desktop user is inactive")
	ErrUserNotProvisioned      = errors.New("desktop user has no active API key")
	ErrDesktopSessionInvalid   = errors.New("desktop session is invalid or expired")
	ErrDesktopFlowPending      = errors.New("desktop authorization is pending")
	ErrDesktopFlowExpired      = errors.New("desktop authorization flow expired")
	ErrReplayDetected          = errors.New("desktop request nonce was already used")
	ErrDesktopBodyTampered     = errors.New("desktop request body digest mismatch")
)

type Store struct {
	db               *sql.DB
	platform         *PlatformStore
	vault            *Vault
	runtimeFailureMu sync.RWMutex
	runtimeFailure   func(string, error)
}

func (s *Store) SetRuntimeFailureReporter(reporter func(string, error)) {
	s.runtimeFailureMu.Lock()
	s.runtimeFailure = reporter
	s.runtimeFailureMu.Unlock()
}

func (s *Store) reportRuntimeFailure(key string, err error) {
	s.runtimeFailureMu.RLock()
	reporter := s.runtimeFailure
	s.runtimeFailureMu.RUnlock()
	if reporter != nil {
		reporter(key, err)
	}
}

func OpenStore(cfg Config, vault *Vault) (*Store, error) {
	databasePath, err := filepath.Abs(cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	// SQLite otherwise inherits the process umask, which commonly leaves the
	// database and WAL readable by other local users. Pre-create and tighten the
	// main file before the driver can create its journaling sidecars.
	file, err := os.OpenFile(databasePath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("prepare sqlite database: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure sqlite database: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close prepared sqlite database: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: databasePath}).String() + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, vault: vault}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.setupAdmin(ctx, cfg.AdminUsername, cfg.AdminPassword); err != nil {
		_ = db.Close()
		return nil, err
	}
	if cfg.PlatformDatabaseURL != "" {
		platform, platformErr := OpenPlatformStore(ctx, cfg, vault)
		if platformErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("open PostgreSQL platform store: %w", platformErr)
		}
		store.platform = platform
	}
	if err := secureSQLiteRuntimeFiles(databasePath); err != nil {
		if store.platform != nil {
			_ = store.platform.Close()
		}
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func secureSQLiteRuntimeFiles(databasePath string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := databasePath + suffix
		if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("secure sqlite file %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	var platformErr error
	if s.platform != nil {
		platformErr = s.platform.Close()
	}
	databaseErr := s.db.Close()
	return errors.Join(platformErr, databaseErr)
}

// Platform exposes the PostgreSQL-backed unified product domain. It is nil
// until LITE_DATABASE_URL is configured, which keeps a running local gateway
// operational while its data is explicitly migrated and verified.
func (s *Store) Platform() *PlatformStore { return s.platform }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  csrf_token TEXT NOT NULL,
  ip TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  access_token_enc TEXT NOT NULL,
  refresh_token_enc TEXT NOT NULL DEFAULT '',
  chatgpt_account_id TEXT NOT NULL,
  client_id TEXT NOT NULL DEFAULT 'app_EMoamEEZ73f0CkXaXp7hrann',
  active INTEGER NOT NULL DEFAULT 1,
  max_concurrency INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL DEFAULT 0,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  cooldown_until INTEGER NOT NULL DEFAULT 0,
  plan_type TEXT NOT NULL DEFAULT '',
  quota_5h_used REAL NOT NULL DEFAULT -1,
  quota_5h_reset_at INTEGER NOT NULL DEFAULT 0,
  quota_7d_used REAL NOT NULL DEFAULT -1,
  quota_7d_reset_at INTEGER NOT NULL DEFAULT 0,
  quota_updated_at INTEGER NOT NULL DEFAULT 0,
  quota_error TEXT NOT NULL DEFAULT '',
  reset_credits INTEGER NOT NULL DEFAULT 0,
  reset_credit_times TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_enc TEXT NOT NULL,
  masked_key TEXT NOT NULL,
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  quota_requests INTEGER NOT NULL DEFAULT 0,
  used_requests INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  last_used_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys(account_id);
CREATE TABLE IF NOT EXISTS key_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  family TEXT NOT NULL DEFAULT '',
  device_note TEXT NOT NULL,
  device_group TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(key_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_key_ips_ip ON key_ips(ip);
CREATE TABLE IF NOT EXISTS session_affinities (
  key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL,
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  expires_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(key_id, session_hash)
);
CREATE INDEX IF NOT EXISTS idx_affinity_account_expiry ON session_affinities(account_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_affinity_expiry ON session_affinities(expires_at);
CREATE TABLE IF NOT EXISTS account_model_snapshots (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  manifest_json TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS account_models (
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  model_id TEXT NOT NULL,
  model_json TEXT NOT NULL,
  model_object TEXT NOT NULL DEFAULT '',
  owned_by TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(account_id, model_id)
);
CREATE INDEX IF NOT EXISTS idx_account_models_model ON account_models(model_id, account_id);
CREATE TRIGGER IF NOT EXISTS trg_accounts_credentials_cleared_models
AFTER UPDATE OF access_token_enc ON accounts
WHEN NEW.access_token_enc='' AND OLD.access_token_enc<>''
BEGIN
  DELETE FROM account_models WHERE account_id=NEW.id;
  DELETE FROM account_model_snapshots WHERE account_id=NEW.id;
END;
CREATE TABLE IF NOT EXISTS invitations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_enc TEXT NOT NULL DEFAULT '',
  code_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  account_id INTEGER REFERENCES accounts(id),
  quota_requests INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  verified_ip TEXT NOT NULL DEFAULT '',
  device_note TEXT NOT NULL DEFAULT '',
  binding_mode TEXT NOT NULL DEFAULT 'ip',
  device_token_hash TEXT NOT NULL DEFAULT '',
  claim_session_hash TEXT NOT NULL DEFAULT '',
  probe_token_hash TEXT NOT NULL DEFAULT '',
  verified_at INTEGER NOT NULL DEFAULT 0,
  api_key_id INTEGER REFERENCES api_keys(id),
  generated_at INTEGER NOT NULL DEFAULT 0,
  reveal_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invitation_ips (
  invitation_id INTEGER NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  family TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(invitation_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_invitation_ips_ip ON invitation_ips(ip);
CREATE TABLE IF NOT EXISTS key_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  device_token_hash TEXT NOT NULL,
  device_note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(key_id, device_token_hash)
);
CREATE INDEX IF NOT EXISTS idx_key_devices_hash ON key_devices(device_token_hash);
CREATE TABLE IF NOT EXISTS desktop_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  api_key_id INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
  last_login_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_desktop_users_key ON desktop_users(api_key_id);
CREATE TABLE IF NOT EXISTS user_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES desktop_users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  ip TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
CREATE TABLE IF NOT EXISTS desktop_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES desktop_users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT '',
  mac_hash TEXT NOT NULL DEFAULT '',
  mac_enc TEXT NOT NULL DEFAULT '',
  registered_ip TEXT NOT NULL,
  last_ip TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_desktop_devices_user ON desktop_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_desktop_devices_mac ON desktop_devices(mac_hash);
CREATE TABLE IF NOT EXISTS desktop_auth_flows (
  device_code_hash TEXT PRIMARY KEY,
  user_code_hash TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  device_name TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT '',
  mac_hash TEXT NOT NULL DEFAULT '',
  mac_enc TEXT NOT NULL DEFAULT '',
  request_ip TEXT NOT NULL,
  browser_ip TEXT NOT NULL DEFAULT '',
  user_id INTEGER REFERENCES desktop_users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at INTEGER NOT NULL,
  approved_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_desktop_auth_flows_expiry ON desktop_auth_flows(expires_at);
CREATE TABLE IF NOT EXISTS desktop_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES desktop_users(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL REFERENCES desktop_devices(id) ON DELETE CASCADE,
  access_hash TEXT NOT NULL UNIQUE,
  refresh_hash TEXT NOT NULL UNIQUE,
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  revoked_at INTEGER NOT NULL DEFAULT 0,
  last_ip TEXT NOT NULL DEFAULT '',
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_desktop_sessions_user ON desktop_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_desktop_sessions_device ON desktop_sessions(device_id);
CREATE TABLE IF NOT EXISTS desktop_nonces (
  session_id INTEGER NOT NULL REFERENCES desktop_sessions(id) ON DELETE CASCADE,
  nonce_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(session_id, nonce_hash)
);
CREATE INDEX IF NOT EXISTS idx_desktop_nonces_expiry ON desktop_nonces(expires_at);
CREATE TABLE IF NOT EXISTS usage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL,
  account_id INTEGER NOT NULL,
  ip TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  request_id TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_key_created ON usage_logs(key_id, created_at DESC);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  ip TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  kind TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_created ON security_events(created_at DESC);
CREATE TABLE IF NOT EXISTS ip_failures (
  ip TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL,
  last_attempt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS guide_failures (
  ip TEXT PRIMARY KEY,
  window24_start INTEGER NOT NULL,
  attempts24 INTEGER NOT NULL,
  window32_start INTEGER NOT NULL,
  attempts32 INTEGER NOT NULL,
  last_attempt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS status_failures (
  ip TEXT NOT NULL,
  status INTEGER NOT NULL,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL,
  last_attempt INTEGER NOT NULL,
  PRIMARY KEY(ip, status)
);
CREATE TABLE IF NOT EXISTS banned_ips (
  ip TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL DEFAULT 0,
  ban_group TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT 'all'
);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate lite database: %w", err)
	}
	// Forward-compatible additions for databases created by early Lite builds.
	// Check the schema explicitly: blindly ignoring ALTER errors can let a disk,
	// permission or corruption failure look like a successful startup.
	additions := []struct {
		table, column, definition string
	}{
		{"invitations", "token_enc", "TEXT NOT NULL DEFAULT ''"},
		{"accounts", "cooldown_until", "INTEGER NOT NULL DEFAULT 0"},
		{"accounts", "plan_type", "TEXT NOT NULL DEFAULT ''"},
		{"accounts", "quota_5h_used", "REAL NOT NULL DEFAULT -1"},
		{"accounts", "quota_5h_reset_at", "INTEGER NOT NULL DEFAULT 0"},
		{"accounts", "quota_7d_used", "REAL NOT NULL DEFAULT -1"},
		{"accounts", "quota_7d_reset_at", "INTEGER NOT NULL DEFAULT 0"},
		{"accounts", "quota_updated_at", "INTEGER NOT NULL DEFAULT 0"},
		{"accounts", "quota_error", "TEXT NOT NULL DEFAULT ''"},
		{"accounts", "reset_credits", "INTEGER NOT NULL DEFAULT 0"},
		{"accounts", "reset_credit_times", "TEXT NOT NULL DEFAULT '[]'"},
		{"key_ips", "family", "TEXT NOT NULL DEFAULT ''"},
		{"key_ips", "device_group", "TEXT NOT NULL DEFAULT ''"},
		{"invitations", "probe_token_hash", "TEXT NOT NULL DEFAULT ''"},
		{"invitations", "binding_mode", "TEXT NOT NULL DEFAULT 'ip'"},
		{"invitations", "device_token_hash", "TEXT NOT NULL DEFAULT ''"},
		{"banned_ips", "ban_group", "TEXT NOT NULL DEFAULT ''"},
		// Unknown legacy bans must fail closed. Known automatic bans are
		// classified as public-only by the forward migration below.
		{"banned_ips", "scope", "TEXT NOT NULL DEFAULT 'all'"},
	}
	for _, addition := range additions {
		var exists int
		query := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name=?", addition.table)
		if err := s.db.QueryRowContext(ctx, query, addition.column).Scan(&exists); err != nil {
			return fmt.Errorf("inspect %s.%s: %w", addition.table, addition.column, err)
		}
		if exists == 0 {
			statement := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", addition.table, addition.column, addition.definition)
			if _, err := s.db.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("add %s.%s: %w", addition.table, addition.column, err)
			}
		}
	}
	forwardWrites := []string{
		"UPDATE accounts SET max_concurrency=0 WHERE max_concurrency<>0",
		`UPDATE banned_ips SET scope='all' WHERE scope NOT IN ('public','all')`,
		`UPDATE banned_ips SET scope='public' WHERE reason IN (
			'unauthorized API access',
			'paired dual-stack address blocked'
		) OR reason GLOB 'HTTP [0-9]* exceeded threshold'
		   OR reason GLOB 'paired dual-stack address; HTTP [0-9]* threshold'`,
		// Early Lite builds added scope with a public default. Restore manual
		// bans to all surfaces using the durable event written by BanIP.
		`UPDATE banned_ips SET scope='all' WHERE EXISTS (
			SELECT 1 FROM security_events event
			WHERE event.ip=banned_ips.ip AND event.kind='manual_ban'
			  AND event.created_at=banned_ips.created_at
		)`,
		`UPDATE key_ips SET family=CASE WHEN instr(ip,':')>0 THEN 'ipv6' ELSE 'ipv4' END WHERE family=''`,
		`UPDATE key_ips SET device_group='legacy-ip-'||id WHERE device_group=''`,
		`UPDATE invitations SET binding_mode='ip' WHERE binding_mode NOT IN ('ip','device','ip_device') OR binding_mode=''`,
		`UPDATE banned_ips SET ban_group='device-'||(
			SELECT MIN(device_group) FROM key_ips WHERE key_ips.ip=banned_ips.ip AND device_group<>''
		) WHERE ban_group='' AND EXISTS(SELECT 1 FROM key_ips WHERE key_ips.ip=banned_ips.ip AND device_group<>'')`,
		`UPDATE banned_ips SET ban_group='legacy-'||ip WHERE ban_group=''`,
		`INSERT OR IGNORE INTO invitation_ips(invitation_id,ip,family,created_at)
SELECT id,verified_ip,CASE WHEN instr(verified_ip,':')>0 THEN 'ipv6' ELSE 'ipv4' END,CASE WHEN verified_at>0 THEN verified_at ELSE created_at END
FROM invitations WHERE verified_ip<>''`,
	}
	for _, statement := range forwardWrites {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate Lite data: %w", err)
		}
	}
	return nil
}

func (s *Store) setupAdmin(ctx context.Context, username, password string) error {
	var existing int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM settings WHERE key='admin_password_hash'").Scan(&existing); err != nil {
		return err
	}
	// Environment credentials are a bootstrap secret only. Once the database
	// has an administrator they must never overwrite an in-app password change.
	if existing > 0 {
		return nil
	}
	hash, err := passwordHash(password, 600_000)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range map[string]string{"admin_username": username, "admin_password_hash": hash} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AdminSetupRequired(ctx context.Context) (bool, error) {
	var encrypted, initializedAt string
	err := s.db.QueryRowContext(ctx, `SELECT
COALESCE((SELECT value FROM settings WHERE key='admin_totp_secret_enc'),''),
COALESCE((SELECT value FROM settings WHERE key='admin_initialized_at'),'')`).Scan(&encrypted, &initializedAt)
	if err != nil {
		// Fail closed: an unreadable setup state must never be interpreted as an
		// invitation to create or replace the sole administrator.
		return false, err
	}
	// Once the durable completion marker exists the public setup channel is
	// permanently closed, even if the encrypted factor is later corrupted or
	// accidentally cleared. That condition is a health/login failure requiring
	// offline recovery, never permission to replace the administrator.
	if strings.TrimSpace(initializedAt) != "" {
		return false, nil
	}
	// Compatibility: completed builds predating admin_initialized_at already
	// have a non-empty encrypted factor and must remain closed.
	return strings.TrimSpace(encrypted) == "", nil
}

// CheckAdminTOTP validates the stored encrypted factor without consuming a
// code. A non-empty setting alone is not enough: corrupted ciphertext or a
// mismatched master key would otherwise be shown as healthy while every login
// is permanently locked out.
func (s *Store) CheckAdminTOTP(ctx context.Context) error {
	var encrypted, lastRaw string
	if err := s.db.QueryRowContext(ctx, `SELECT
(SELECT value FROM settings WHERE key='admin_totp_secret_enc'),
COALESCE((SELECT value FROM settings WHERE key='admin_totp_last_counter'),'0')`).Scan(&encrypted, &lastRaw); err != nil {
		return err
	}
	if strings.TrimSpace(encrypted) == "" {
		return errors.New("administrator TOTP is not initialized")
	}
	secret, err := s.vault.Decrypt(encrypted, "admin-totp")
	if err != nil {
		return errors.New("administrator TOTP ciphertext cannot be decrypted")
	}
	if _, ok := totpValue(secret, time.Now().Unix()/30); !ok {
		return errors.New("administrator TOTP secret is invalid")
	}
	if _, err := strconv.ParseInt(lastRaw, 10, 64); err != nil {
		return errors.New("administrator TOTP replay counter is invalid")
	}
	return nil
}

func (s *Store) AdminUsername(ctx context.Context) string {
	var username string
	_ = s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='admin_username'").Scan(&username)
	return username
}

func (s *Store) CompleteAdminSetup(ctx context.Context, username, passwordHashValue, encryptedSecret string, counter int64) error {
	if username == "" || passwordHashValue == "" || encryptedSecret == "" {
		return errors.New("invalid administrator setup")
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current, initializedAt string
	err = tx.QueryRowContext(ctx, `SELECT
COALESCE((SELECT value FROM settings WHERE key='admin_totp_secret_enc'),''),
COALESCE((SELECT value FROM settings WHERE key='admin_initialized_at'),'')`).Scan(&current, &initializedAt)
	if err != nil {
		return err
	}
	if current != "" || initializedAt != "" {
		return ErrAdminSetupClosed
	}
	values := map[string]string{
		"admin_username":          username,
		"admin_password_hash":     passwordHashValue,
		"admin_totp_secret_enc":   encryptedSecret,
		"admin_totp_last_counter": strconv.FormatInt(counter, 10),
		"admin_initialized_at":    strconv.FormatInt(now, 10),
	}
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) VerifyAdmin(ctx context.Context, username, password string) bool {
	var wantUser, hash string
	if err := s.db.QueryRowContext(ctx, `SELECT
(SELECT value FROM settings WHERE key='admin_username'),
(SELECT value FROM settings WHERE key='admin_password_hash')`).Scan(&wantUser, &hash); err != nil {
		return false
	}
	return username == wantUser && passwordVerify(hash, password)
}

func (s *Store) AuthenticateAdmin(ctx context.Context, username, password, code string) bool {
	ok, err := s.authenticateAdmin(ctx, username, password, code)
	return err == nil && ok
}

func (s *Store) authenticateAdmin(ctx context.Context, username, password, code string) (bool, error) {
	var wantUser, hash, encryptedSecret, lastRaw string
	if err := s.db.QueryRowContext(ctx, `SELECT
(SELECT value FROM settings WHERE key='admin_username'),
(SELECT value FROM settings WHERE key='admin_password_hash'),
(SELECT value FROM settings WHERE key='admin_totp_secret_enc'),
COALESCE((SELECT value FROM settings WHERE key='admin_totp_last_counter'),'0')`).Scan(&wantUser, &hash, &encryptedSecret, &lastRaw); err != nil {
		return false, err
	}
	if username != wantUser || !passwordVerify(hash, password) || encryptedSecret == "" {
		return false, nil
	}
	secret, err := s.vault.Decrypt(encryptedSecret, "admin-totp")
	if err != nil {
		return false, fmt.Errorf("decrypt administrator TOTP: %w", err)
	}
	last, err := strconv.ParseInt(lastRaw, 10, 64)
	if err != nil {
		return false, errors.New("invalid administrator TOTP replay counter")
	}
	counter, ok := verifyTOTP(secret, code, time.Now(), last)
	if !ok {
		return false, nil
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `UPDATE settings SET value=?,updated_at=?
WHERE key='admin_totp_last_counter' AND CAST(value AS INTEGER)<?`, strconv.FormatInt(counter, 10), now, counter)
	if err != nil {
		return false, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return updated == 1, nil
}

func (s *Store) ChangeAdminPassword(ctx context.Context, currentPassword, newPassword, code string) error {
	username := s.AdminUsername(ctx)
	authenticated, err := s.authenticateAdmin(ctx, username, currentPassword, code)
	if err != nil {
		return fmt.Errorf("authenticate administrator for password change: %w", err)
	}
	if !authenticated {
		return ErrInvalidAdminCredentials
	}
	hash, err := passwordHash(newPassword, 600_000)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE settings SET value=?,updated_at=? WHERE key='admin_password_hash'", hash, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) NewAdminSession(ctx context.Context, ip string, ttl time.Duration) (token, csrf string, err error) {
	token, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomToken(24)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	_, err = s.db.ExecContext(ctx, `INSERT INTO admin_sessions(token_hash,csrf_token,ip,expires_at,created_at) VALUES(?,?,?,?,?)`,
		tokenHash(token), csrf, ip, now.Add(ttl).Unix(), now.Unix())
	return token, csrf, err
}

func (s *Store) AdminSession(ctx context.Context, token, ip string) (string, bool) {
	if token == "" {
		return "", false
	}
	var csrf string
	err := s.db.QueryRowContext(ctx, "SELECT csrf_token FROM admin_sessions WHERE token_hash=? AND ip=? AND expires_at>?", tokenHash(token), ip, time.Now().Unix()).Scan(&csrf)
	return csrf, err == nil
}

func (s *Store) DeleteAdminSession(ctx context.Context, token string) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(writeCtx, "DELETE FROM admin_sessions WHERE token_hash=?", tokenHash(token))
	return err
}

func (s *Store) CreateAccount(ctx context.Context, account Account) (int64, error) {
	access, err := s.vault.Encrypt(account.AccessToken, "account-access")
	if err != nil {
		return 0, err
	}
	refresh, err := s.vault.Encrypt(account.RefreshToken, "account-refresh")
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `INSERT INTO accounts(name,access_token_enc,refresh_token_enc,chatgpt_account_id,client_id,active,max_concurrency,expires_at,created_at,updated_at)
VALUES(?,?,?,?,?,1,0,?,?,?)`, account.Name, access, refresh, account.ChatGPTAccountID, account.ClientID, account.ExpiresAt, now, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) ListAccounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,chatgpt_account_id,active,max_concurrency,expires_at,last_used_at,last_error,cooldown_until,
plan_type,quota_5h_used,quota_5h_reset_at,quota_7d_used,quota_7d_reset_at,quota_updated_at,quota_error,reset_credits,reset_credit_times,created_at
FROM accounts WHERE access_token_enc<>'' ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Account
	for rows.Next() {
		var item Account
		var resetTimes string
		if err := rows.Scan(&item.ID, &item.Name, &item.ChatGPTAccountID, &item.Active, &item.MaxConcurrency, &item.ExpiresAt, &item.LastUsedAt, &item.LastError, &item.CooldownUntil,
			&item.PlanType, &item.Quota5HUsed, &item.Quota5HResetAt, &item.Quota7DUsed, &item.Quota7DResetAt, &item.QuotaUpdatedAt, &item.QuotaError, &item.ResetCredits, &resetTimes, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(resetTimes), &item.ResetCreditTimes)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) GetAccount(ctx context.Context, id int64) (*Account, error) {
	var item Account
	var accessEnc, refreshEnc string
	var resetTimes string
	err := s.db.QueryRowContext(ctx, `SELECT id,name,chatgpt_account_id,active,max_concurrency,expires_at,last_used_at,last_error,cooldown_until,
plan_type,quota_5h_used,quota_5h_reset_at,quota_7d_used,quota_7d_reset_at,quota_updated_at,quota_error,reset_credits,reset_credit_times,
created_at,access_token_enc,refresh_token_enc,client_id FROM accounts WHERE id=? AND access_token_enc<>''`, id).
		Scan(&item.ID, &item.Name, &item.ChatGPTAccountID, &item.Active, &item.MaxConcurrency, &item.ExpiresAt, &item.LastUsedAt, &item.LastError, &item.CooldownUntil,
			&item.PlanType, &item.Quota5HUsed, &item.Quota5HResetAt, &item.Quota7DUsed, &item.Quota7DResetAt, &item.QuotaUpdatedAt, &item.QuotaError, &item.ResetCredits, &resetTimes,
			&item.CreatedAt, &accessEnc, &refreshEnc, &item.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	item.AccessToken, err = s.vault.Decrypt(accessEnc, "account-access")
	if err != nil {
		return nil, err
	}
	item.RefreshToken, err = s.vault.Decrypt(refreshEnc, "account-refresh")
	_ = json.Unmarshal([]byte(resetTimes), &item.ResetCreditTimes)
	return &item, err
}

func (s *Store) UpdateAccountState(ctx context.Context, id int64, active bool) error {
	result, err := s.db.ExecContext(ctx, "UPDATE accounts SET active=?,max_concurrency=0,updated_at=? WHERE id=? AND access_token_enc<>''", active, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateAccountTokens(ctx context.Context, id int64, accessToken, refreshToken string, expiresAt int64, accountID string) error {
	access, err := s.vault.Encrypt(accessToken, "account-access")
	if err != nil {
		return err
	}
	refresh, err := s.vault.Encrypt(refreshToken, "account-refresh")
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE accounts SET access_token_enc=?,refresh_token_enc=?,expires_at=?,chatgpt_account_id=?,last_error='',updated_at=? WHERE id=? AND active=1 AND access_token_enc<>''`, access, refresh, expiresAt, accountID, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNoAccount
	}
	return nil
}

func (s *Store) MarkAccountResult(ctx context.Context, id int64, errText string) {
	now := time.Now().Unix()
	if len(errText) > 500 {
		errText = errText[:500]
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE accounts SET last_used_at=?,last_error=?,updated_at=? WHERE id=?`, now, errText, now, id)
}

func (s *Store) MarkAccountCooldown(ctx context.Context, id int64, until int64, errText string) {
	now := time.Now().Unix()
	_, _ = s.db.ExecContext(ctx, `UPDATE accounts SET last_used_at=?,last_error=?,cooldown_until=MAX(cooldown_until,?),updated_at=? WHERE id=?`, now, truncate(errText, 500), until, now, id)
}

func (s *Store) UpdateAccountQuota(ctx context.Context, id int64, snapshot AccountQuotaSnapshot) error {
	resetTimes, err := json.Marshal(snapshot.ResetCreditTimes)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `UPDATE accounts SET
plan_type=?,quota_5h_used=?,quota_5h_reset_at=?,quota_7d_used=?,quota_7d_reset_at=?,quota_updated_at=?,quota_error='',
reset_credits=?,reset_credit_times=?,cooldown_until=?,updated_at=? WHERE id=? AND active=1 AND access_token_enc<>''`,
		snapshot.PlanType, snapshot.FiveHourUsed, snapshot.FiveHourResetAt, snapshot.SevenDayUsed, snapshot.SevenDayResetAt,
		snapshot.FetchedAt, snapshot.ResetCredits, string(resetTimes), snapshot.CooldownUntil, now, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNoAccount
	}
	return nil
}

func (s *Store) MarkAccountQuotaError(ctx context.Context, id int64, errText string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE accounts SET quota_error=?,updated_at=? WHERE id=? AND active=1 AND access_token_enc<>''`, truncate(errText, 500), time.Now().Unix(), id)
}

// SelectAccount is retained for callers which do not need model-aware routing.
// The implementation still passes through the same lifecycle and credential
// predicates used by model-aware gateway requests.
func (s *Store) SelectAccount(ctx context.Context, keyID int64, sessionHash string, ttl time.Duration) (*Account, error) {
	return s.SelectAccountForModel(ctx, keyID, sessionHash, "", ttl)
}

func (s *Store) CreateInvitation(ctx context.Context, role, token, code string, accountID, quota int64, expiresAt int64) (int64, error) {
	return s.CreateInvitationWithBinding(ctx, role, token, code, accountID, quota, expiresAt, "ip")
}

// CreateInvitationWithBinding keeps the original IP-only invitation API
// compatible while allowing administrators to opt into an opaque device
// credential. A device credential is deliberately not a user-supplied MAC:
// browsers cannot read a NIC MAC over the public Internet and a raw MAC header
// would be trivially spoofable.
func (s *Store) CreateInvitationWithBinding(ctx context.Context, role, token, code string, accountID, quota int64, expiresAt int64, bindingMode string) (int64, error) {
	if bindingMode != "ip" && bindingMode != "device" && bindingMode != "ip_device" {
		return 0, errors.New("invalid invitation binding mode")
	}
	codeHash, err := passwordHash(code, 150_000)
	if err != nil {
		return 0, err
	}
	tokenEnc, err := s.vault.Encrypt(token, "invite-token")
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	var account any
	if accountID > 0 {
		account = accountID
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO invitations(role,token_hash,token_enc,code_hash,account_id,quota_requests,expires_at,binding_mode,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		role, tokenHash(token), tokenEnc, codeHash, account, quota, expiresAt, bindingMode, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) RevokeInvitation(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE invitations SET status='revoked',token_enc='',code_hash='',claim_session_hash='',probe_token_hash='',device_token_hash=''
WHERE id=? AND status='pending'`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteInvitation permanently removes only terminal invitation metadata.
// A key generated from a claimed invitation is deliberately preserved.
func (s *Store) DeleteInvitation(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM invitations
WHERE id=? AND (status<>'pending' OR expires_at<=?)`, id, time.Now().Unix())
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListInvitations(ctx context.Context) ([]Invitation, error) {
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `UPDATE invitations SET status='expired',token_enc='',code_hash='',claim_session_hash='',probe_token_hash='',device_token_hash=''
WHERE status='pending' AND expires_at<=?`, now); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,role,status,COALESCE(account_id,0),quota_requests,expires_at,created_at,generated_at,reveal_until,verified_ip,device_note,binding_mode,COALESCE(api_key_id,0),
COALESCE((SELECT status FROM api_keys WHERE id=invitations.api_key_id),''),token_enc FROM invitations ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	var result []Invitation
	for rows.Next() {
		var item Invitation
		var tokenEnc string
		if err := rows.Scan(&item.ID, &item.Role, &item.Status, &item.AccountID, &item.QuotaRequests, &item.ExpiresAt, &item.CreatedAt, &item.GeneratedAt, &item.RevealUntil, &item.VerifiedIP, &item.DeviceNote, &item.BindingMode, &item.APIKeyID, &item.APIKeyStatus, &tokenEnc); err != nil {
			return nil, err
		}
		if tokenEnc != "" {
			if item.Token, err = s.vault.Decrypt(tokenEnc, "invite-token"); err != nil {
				return nil, err
			}
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range result {
		ips, err := s.listInvitationIPs(ctx, result[i].ID)
		if err != nil {
			return nil, err
		}
		result[i].ObservedIPs = ips
	}
	return result, nil
}

func (s *Store) PublicInvitation(ctx context.Context, token string) (*Invitation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var item Invitation
	err = tx.QueryRowContext(ctx, `SELECT i.id,i.role,i.status,COALESCE(i.account_id,0),i.quota_requests,i.expires_at,i.created_at,i.generated_at,i.reveal_until,i.verified_ip,i.device_note,i.binding_mode,COALESCE(i.api_key_id,0),i.claim_session_hash,i.probe_token_hash,COALESCE(k.status,'')
	FROM invitations i LEFT JOIN api_keys k ON k.id=i.api_key_id WHERE i.token_hash=?`, tokenHash(token)).
		Scan(&item.ID, &item.Role, &item.Status, &item.AccountID, &item.QuotaRequests, &item.ExpiresAt, &item.CreatedAt, &item.GeneratedAt, &item.RevealUntil, &item.VerifiedIP, &item.DeviceNote, &item.BindingMode, &item.APIKeyID, &item.ClaimSessionHash, &item.ProbeTokenHash, &item.APIKeyStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidInvite
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if item.Status == "pending" && now >= item.ExpiresAt {
		if _, err = tx.ExecContext(ctx, `UPDATE invitations SET status='expired',token_enc='',code_hash='',claim_session_hash='',probe_token_hash='',device_token_hash=''
WHERE id=? AND status='pending'`, item.ID); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrInvalidInvite
	}
	if item.Status != "pending" && item.Status != "claimed" {
		return nil, ErrInvalidInvite
	}
	if item.Status == "claimed" && (now >= item.RevealUntil || item.APIKeyStatus == "" || item.APIKeyStatus == "deleted") {
		return nil, ErrInvalidInvite
	}
	item.ObservedIPs, err = listInvitationIPsWith(ctx, tx, item.ID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Store) listInvitationIPs(ctx context.Context, invitationID int64) ([]InvitationIP, error) {
	return listInvitationIPsWith(ctx, s.db, invitationID)
}

type invitationIPQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listInvitationIPsWith(ctx context.Context, queryer invitationIPQuerier, invitationID int64) ([]InvitationIP, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT ip,family,created_at FROM invitation_ips WHERE invitation_id=? ORDER BY family,ip`, invitationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []InvitationIP
	for rows.Next() {
		var item InvitationIP
		if err := rows.Scan(&item.IP, &item.Family, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) VerifyInvitation(ctx context.Context, token, code, ip, claimSession, probeToken string) (*Invitation, error) {
	var item Invitation
	var codeHash string
	now := time.Now().Unix()
	err := s.db.QueryRowContext(ctx, `SELECT id,role,status,expires_at,code_hash,binding_mode FROM invitations
	WHERE token_hash=? AND status='pending' AND expires_at>? AND claim_session_hash=''`, tokenHash(token), now).
		Scan(&item.ID, &item.Role, &item.Status, &item.ExpiresAt, &codeHash, &item.BindingMode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidInvite
	}
	if err != nil {
		return nil, err
	}
	if !passwordVerify(codeHash, code) {
		return nil, ErrInvalidCode
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE invitations SET verified_ip=?,claim_session_hash=?,probe_token_hash=?,verified_at=?
	WHERE id=? AND status='pending' AND expires_at>? AND claim_session_hash=''`, ip, tokenHash(claimSession), tokenHash(probeToken), now, item.ID, now)
	if err != nil {
		return nil, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return nil, ErrInvalidInvite
	}
	// A successfully locked claim starts with an exact, clean IP set. This also
	// removes any stale rows left by pre-lock Lite builds.
	if _, err = tx.ExecContext(ctx, `DELETE FROM invitation_ips WHERE invitation_id=?`, item.ID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO invitation_ips(invitation_id,ip,family,created_at) VALUES(?,?,?,?) ON CONFLICT(invitation_id,ip) DO NOTHING`, item.ID, ip, ipFamily(ip), now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	item.VerifiedIP = ip
	item.ClaimSessionHash = tokenHash(claimSession)
	item.ProbeTokenHash = tokenHash(probeToken)
	item.ObservedIPs = []InvitationIP{{IP: ip, Family: ipFamily(ip), CreatedAt: now}}
	return &item, nil
}

func (s *Store) RecordInvitationProbe(ctx context.Context, token, probeToken, ip string) ([]InvitationIP, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var invitationID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM invitations WHERE token_hash=? AND probe_token_hash=? AND claim_session_hash<>'' AND status='pending' AND expires_at>?`, tokenHash(token), tokenHash(probeToken), time.Now().Unix()).Scan(&invitationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidInvite
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO invitation_ips(invitation_id,ip,family,created_at) VALUES(?,?,?,?) ON CONFLICT(invitation_id,ip) DO NOTHING`, invitationID, ip, ipFamily(ip), time.Now().Unix()); err != nil {
		return nil, err
	}
	ips, err := listInvitationIPsWith(ctx, tx, invitationID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return ips, nil
}

func (s *Store) InvitationClaimValid(ctx context.Context, token, claimSession, ip string) bool {
	var count int
	now := time.Now().Unix()
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM invitations i
	WHERE i.token_hash=? AND i.claim_session_hash=?
	AND ((i.status='pending' AND i.expires_at>?) OR
	     (i.status='claimed' AND i.reveal_until>? AND EXISTS(SELECT 1 FROM api_keys k WHERE k.id=i.api_key_id AND k.status<>'deleted' AND k.key_enc<>'')))
	AND (i.binding_mode='device' OR EXISTS(SELECT 1 FROM invitation_ips p WHERE p.invitation_id=i.id AND p.ip=?))`, tokenHash(token), tokenHash(claimSession), now, now, ip).Scan(&count)
	return err == nil && count > 0
}

func (s *Store) SaveInviteDevice(ctx context.Context, token, claimSession, ip, note string) error {
	return s.saveInviteDevice(ctx, token, claimSession, ip, note, "")
}

// SaveInviteDeviceWithCredential stores only the hash of the device bearer.
// The plaintext is returned to the claimant once by the HTTP handler and is
// never recoverable from the database.
func (s *Store) SaveInviteDeviceWithCredential(ctx context.Context, token, claimSession, ip, note, deviceToken string) error {
	return s.saveInviteDevice(ctx, token, claimSession, ip, note, deviceToken)
}

func (s *Store) saveInviteDevice(ctx context.Context, token, claimSession, ip, note, deviceToken string) error {
	var hash string
	if strings.TrimSpace(deviceToken) != "" {
		hash = tokenHash(deviceToken)
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `UPDATE invitations SET device_note=?,device_token_hash=? WHERE token_hash=? AND claim_session_hash=? AND status='pending' AND expires_at>?
AND (binding_mode='device' OR EXISTS(SELECT 1 FROM invitation_ips p WHERE p.invitation_id=invitations.id AND p.ip=?))`,
		note, hash, tokenHash(token), tokenHash(claimSession), now, ip)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrInvalidInvite
	}
	return nil
}

func (s *Store) GenerateInvitedKey(ctx context.Context, token, claimSession, ip, plainKey string, revealTTL time.Duration) (*APIKey, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var inv Invitation
	var deviceTokenHash string
	err = tx.QueryRowContext(ctx, `SELECT id,role,status,COALESCE(account_id,0),quota_requests,expires_at,verified_ip,device_note,binding_mode,device_token_hash,claim_session_hash FROM invitations WHERE token_hash=?`, tokenHash(token)).
		Scan(&inv.ID, &inv.Role, &inv.Status, &inv.AccountID, &inv.QuotaRequests, &inv.ExpiresAt, &inv.VerifiedIP, &inv.DeviceNote, &inv.BindingMode, &deviceTokenHash, &inv.ClaimSessionHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrInvalidInvite
	}
	if err != nil {
		return nil, 0, err
	}
	if inv.Status != "pending" || inv.ExpiresAt <= time.Now().Unix() || inv.ClaimSessionHash != tokenHash(claimSession) || strings.TrimSpace(inv.DeviceNote) == "" {
		return nil, 0, ErrInvalidInvite
	}
	if (inv.BindingMode == "device" || inv.BindingMode == "ip_device") && deviceTokenHash == "" {
		return nil, 0, ErrInvalidInvite
	}
	var currentIPAllowed int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM invitation_ips WHERE invitation_id=? AND ip=?`, inv.ID, ip).Scan(&currentIPAllowed); err != nil || (inv.BindingMode != "device" && currentIPAllowed == 0) {
		return nil, 0, ErrInvalidInvite
	}
	// account_id is retained only as a compatibility column for databases made
	// by the first Lite build, where it was NOT NULL. Routing no longer reads it.
	var compatibilityAccountID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE active=1 ORDER BY id LIMIT 1`).Scan(&compatibilityAccountID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNoAccount
	}
	if err != nil {
		return nil, 0, err
	}
	encrypted, err := s.vault.Encrypt(plainKey, "client-api-key")
	if err != nil {
		return nil, 0, err
	}
	masked := maskAPIKey(plainKey)
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, `INSERT INTO api_keys(role,key_hash,key_enc,masked_key,account_id,quota_requests,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		inv.Role, tokenHash(plainKey), encrypted, masked, compatibilityAccountID, inv.QuotaRequests, now, now)
	if err != nil {
		return nil, 0, err
	}
	keyID, _ := result.LastInsertId()
	ipRows, err := tx.QueryContext(ctx, `SELECT ip,family FROM invitation_ips WHERE invitation_id=? ORDER BY family,ip`, inv.ID)
	if err != nil {
		return nil, 0, err
	}
	var observed []InvitationIP
	for ipRows.Next() {
		var observedIP InvitationIP
		if err := ipRows.Scan(&observedIP.IP, &observedIP.Family); err != nil {
			_ = ipRows.Close()
			return nil, 0, err
		}
		observed = append(observed, observedIP)
	}
	if err := ipRows.Err(); err != nil {
		_ = ipRows.Close()
		return nil, 0, err
	}
	if err := ipRows.Close(); err != nil {
		return nil, 0, err
	}
	deviceGroup := "invite-" + strconv.FormatInt(inv.ID, 10)
	if inv.BindingMode != "device" {
		for _, observedIP := range observed {
			if _, err := tx.ExecContext(ctx, `INSERT INTO key_ips(key_id,ip,family,device_note,device_group,created_at) VALUES(?,?,?,?,?,?)`, keyID, observedIP.IP, observedIP.Family, inv.DeviceNote, deviceGroup, now); err != nil {
				return nil, 0, err
			}
		}
	}
	if deviceTokenHash != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_devices(key_id,device_token_hash,device_note,created_at) VALUES(?,?,?,?)`, keyID, deviceTokenHash, inv.DeviceNote, now); err != nil {
			return nil, 0, err
		}
	}
	revealUntil := time.Now().Add(revealTTL).Unix()
	result, err = tx.ExecContext(ctx, `UPDATE invitations
SET status='claimed',api_key_id=?,generated_at=?,reveal_until=?,token_enc='',code_hash='',probe_token_hash='',device_token_hash=''
WHERE id=? AND status='pending'`, keyID, now, revealUntil, inv.ID)
	if err != nil {
		return nil, 0, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return nil, 0, ErrInviteConsumed
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return &APIKey{ID: keyID, Role: inv.Role, MaskedKey: masked, QuotaRequests: inv.QuotaRequests, Status: "active", CreatedAt: now}, revealUntil, nil
}

func (s *Store) RevealInvitedKey(ctx context.Context, token, claimSession, ip string) (string, int64, error) {
	var encrypted string
	var until int64
	err := s.db.QueryRowContext(ctx, `SELECT k.key_enc,i.reveal_until FROM invitations i JOIN api_keys k ON k.id=i.api_key_id
WHERE i.token_hash=? AND i.claim_session_hash=? AND i.status='claimed' AND i.reveal_until>? AND k.status<>'deleted' AND k.key_enc<>''
	AND (i.binding_mode='device' OR EXISTS(SELECT 1 FROM invitation_ips p WHERE p.invitation_id=i.id AND p.ip=?))`,
		tokenHash(token), tokenHash(claimSession), time.Now().Unix(), ip).Scan(&encrypted, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrInvalidInvite
	}
	if err != nil {
		return "", 0, err
	}
	plain, err := s.vault.Decrypt(encrypted, "client-api-key")
	return plain, until, err
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT k.id,k.role,k.masked_key,k.quota_requests,k.used_requests,k.status,k.last_used_at,k.created_at,k.key_enc,k.account_id,
(SELECT COUNT(*) FROM session_affinities f WHERE f.key_id=k.id AND f.expires_at>?),(SELECT COUNT(*) FROM key_devices d WHERE d.key_id=k.id)
FROM api_keys k WHERE k.status<>'deleted' ORDER BY k.id DESC`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	var result []APIKey
	for rows.Next() {
		var item APIKey
		var deviceCount int64
		if err := rows.Scan(&item.ID, &item.Role, &item.MaskedKey, &item.QuotaRequests, &item.UsedRequests, &item.Status, &item.LastUsedAt, &item.CreatedAt, &item.EncryptedKey, &item.AccountID, &item.AffinityCount, &deviceCount); err != nil {
			return nil, err
		}
		item.DeviceBound = deviceCount > 0
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range result {
		ips, err := s.listKeyIPs(ctx, result[i].ID)
		if err != nil {
			return nil, err
		}
		result[i].AllowedIPs = ips
	}
	return result, nil
}

func (s *Store) listKeyIPs(ctx context.Context, keyID int64) ([]KeyIP, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,ip,family,device_note,device_group,created_at,last_seen_at FROM key_ips WHERE key_id=? ORDER BY family,ip`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []KeyIP
	for rows.Next() {
		var item KeyIP
		if err := rows.Scan(&item.ID, &item.IP, &item.Family, &item.DeviceNote, &item.DeviceGroup, &item.CreatedAt, &item.LastSeenAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) CopyAPIKey(ctx context.Context, id int64) (string, error) {
	var encrypted string
	if err := s.db.QueryRowContext(ctx, "SELECT key_enc FROM api_keys WHERE id=? AND status<>'deleted' AND key_enc<>''", id).Scan(&encrypted); errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	return s.vault.Decrypt(encrypted, "client-api-key")
}

func (s *Store) UpdateAPIKey(ctx context.Context, id int64, status string, quota int64) error {
	if status != "active" && status != "disabled" {
		return errors.New("invalid status")
	}
	if quota < 0 {
		return errors.New("quota must be non-negative")
	}
	result, err := s.db.ExecContext(ctx, "UPDATE api_keys SET status=?,quota_requests=?,updated_at=? WHERE id=? AND status<>'deleted'", status, quota, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAPIKey is a security-preserving soft delete. The encrypted secret,
// IP ACL and live affinities are destroyed immediately, while the minimal row
// remains as a tombstone so historical usage logs keep their role association.
func (s *Store) DeleteAPIKey(ctx context.Context, id int64) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE api_keys SET status='deleted',key_enc='',masked_key='deleted',updated_at=? WHERE id=? AND status<>'deleted'`, now, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM session_affinities WHERE key_id=?", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM key_ips WHERE key_id=?", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM key_devices WHERE key_id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AddKeyIP(ctx context.Context, keyID int64, ip, note string) error {
	result, err := s.db.ExecContext(ctx, `INSERT INTO key_ips(key_id,ip,family,device_note,device_group,created_at)
SELECT id,?,?,?,?,? FROM api_keys WHERE id=? AND status<>'deleted'
ON CONFLICT(key_id,ip) DO UPDATE SET family=excluded.family,device_note=excluded.device_note`, ip, ipFamily(ip), note, "manual-"+ip, time.Now().Unix(), keyID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) DeleteKeyIP(ctx context.Context, keyID, ipID int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM key_ips WHERE id=? AND key_id=?", ipID, keyID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AuthorizeKey(ctx context.Context, plainKey, ip string) (*APIKey, error) {
	return s.AuthorizeKeyWithDevice(ctx, plainKey, ip, "")
}

// AuthorizeGuideKey validates an active key without applying the API route's
// IP/device ACL. The guide is a separately protected documentation surface;
// the key itself is the bearer credential for entering it. API calls continue
// to require their normal IP and device checks.
func (s *Store) AuthorizeGuideKey(ctx context.Context, plainKey string) (*APIKey, error) {
	var item APIKey
	err := s.db.QueryRowContext(ctx, `SELECT id,role,masked_key,quota_requests,used_requests,status,last_used_at,created_at,account_id
FROM api_keys WHERE key_hash=? AND status='active'`, tokenHash(plainKey)).Scan(
		&item.ID, &item.Role, &item.MaskedKey, &item.QuotaRequests, &item.UsedRequests,
		&item.Status, &item.LastUsedAt, &item.CreatedAt, &item.AccountID)
	if err != nil {
		return nil, ErrNotFound
	}
	return &item, nil
}

func (s *Store) AuthorizeGuideHash(ctx context.Context, keyHash string) (*APIKey, error) {
	var item APIKey
	err := s.db.QueryRowContext(ctx, `SELECT id,role,masked_key,quota_requests,used_requests,status,last_used_at,created_at,account_id
FROM api_keys WHERE key_hash=? AND status='active'`, strings.TrimSpace(keyHash)).Scan(
		&item.ID, &item.Role, &item.MaskedKey, &item.QuotaRequests, &item.UsedRequests,
		&item.Status, &item.LastUsedAt, &item.CreatedAt, &item.AccountID)
	if err != nil {
		return nil, ErrNotFound
	}
	return &item, nil
}

// RecordGuideFailure maintains the guide-only 24-hour and 32-hour windows.
// It persists the counters so a process restart cannot reset an attacker's
// progress. The resulting ban is scoped to the guide surface and does not
// silently revoke an otherwise valid API key.
func (s *Store) RecordGuideFailure(ctx context.Context, ip, path, detail string) (temporary, permanent bool, err error) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(writeCtx, nil)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()
	const day24 = int64(24 * time.Hour / time.Second)
	const day32 = int64(32 * time.Hour / time.Second)
	var start24, attempts24, start32, attempts32 int64
	err = tx.QueryRowContext(writeCtx, `SELECT window24_start,attempts24,window32_start,attempts32 FROM guide_failures WHERE ip=?`, ip).
		Scan(&start24, &attempts24, &start32, &attempts32)
	if errors.Is(err, sql.ErrNoRows) || err == nil && now-start24 >= day24 {
		start24, attempts24 = now, 0
	}
	if errors.Is(err, sql.ErrNoRows) || err == nil && now-start32 >= day32 {
		start32, attempts32 = now, 0
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, false, err
	}
	attempts24++
	attempts32++
	if _, err := tx.ExecContext(writeCtx, `INSERT INTO guide_failures(ip,window24_start,attempts24,window32_start,attempts32,last_attempt) VALUES(?,?,?,?,?,?)
ON CONFLICT(ip) DO UPDATE SET window24_start=excluded.window24_start,attempts24=excluded.attempts24,window32_start=excluded.window32_start,attempts32=excluded.attempts32,last_attempt=excluded.last_attempt`,
		ip, start24, attempts24, start32, attempts32, now); err != nil {
		return false, false, err
	}
	if _, err := tx.ExecContext(writeCtx, `INSERT INTO security_events(ip,kind,path,detail,created_at) VALUES(?,?,?,?,?)`, ip, "guide_auth_failed", truncate(path, 500), truncate(fmt.Sprintf("%s；24h=%d/5；32h=%d/10", detail, attempts24, attempts32), 500), now); err != nil {
		return false, false, err
	}
	temporary = attempts24 > 5
	permanent = attempts32 > 10
	if temporary || permanent {
		related, relatedErr := s.relatedDeviceIPs(writeCtx, ip)
		if relatedErr != nil {
			return false, false, relatedErr
		}
		group, groupErr := s.prepareBanGroup(writeCtx, tx, related, "guide-"+ip)
		if groupErr != nil {
			return false, false, groupErr
		}
		expires := int64(0)
		if !permanent {
			expires = now + day24
		}
		for _, targetIP := range related {
			reason := "guide authentication failures"
			if permanent {
				reason = "guide authentication failures (permanent)"
			}
			if _, banErr := tx.ExecContext(writeCtx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope) VALUES(?,?,?,?,?,?, 'guide')
ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,attempts=excluded.attempts,created_at=excluded.created_at,expires_at=excluded.expires_at,ban_group=excluded.ban_group,scope=CASE WHEN banned_ips.scope IN ('all','public') THEN banned_ips.scope ELSE 'guide' END`, targetIP, reason, attempts32, now, expires, group); banErr != nil {
				return false, false, banErr
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return false, false, err
	}
	return temporary, permanent, nil
}

func (s *Store) AuthorizeKeyWithDevice(ctx context.Context, plainKey, ip, deviceToken string) (*APIKey, error) {
	var item APIKey
	err := s.db.QueryRowContext(ctx, `SELECT id,role,masked_key,quota_requests,used_requests,status,last_used_at,created_at,account_id FROM api_keys WHERE key_hash=? AND status='active'`, tokenHash(plainKey)).Scan(&item.ID, &item.Role, &item.MaskedKey, &item.QuotaRequests, &item.UsedRequests, &item.Status, &item.LastUsedAt, &item.CreatedAt, &item.AccountID)
	if err != nil {
		return nil, ErrNotFound
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_ips WHERE key_id=? AND ip=?", item.ID, ip).Scan(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		var ipBindings int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_ips WHERE key_id=?", item.ID).Scan(&ipBindings); err != nil {
			return nil, err
		}
		if ipBindings > 0 {
			return &item, ErrIPNotAllowed
		}
		var deviceBindings int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=?", item.ID).Scan(&deviceBindings); err != nil {
			return nil, err
		}
		if deviceBindings == 0 {
			return &item, ErrIPNotAllowed
		}
	}
	var deviceCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=?", item.ID).Scan(&deviceCount); err != nil {
		return nil, err
	}
	if deviceCount > 0 {
		if strings.TrimSpace(deviceToken) == "" {
			return &item, ErrDeviceNotAllowed
		}
		var allowed int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=? AND device_token_hash=?", item.ID, tokenHash(deviceToken)).Scan(&allowed); err != nil {
			return nil, err
		}
		if allowed == 0 {
			return &item, ErrDeviceNotAllowed
		}
		item.DeviceBound = true
	}
	return &item, nil
}

// RequireAuthorizedKey re-checks key status and IP membership without
// consuming request quota. It is used by authenticated metadata endpoints
// such as GET /models, which are non-billable but still obey immediate
// disable/delete/IP-removal boundaries.
func (s *Store) RequireAuthorizedKey(ctx context.Context, keyID int64, ip string) error {
	return s.RequireAuthorizedKeyWithDevice(ctx, keyID, ip, "")
}

func (s *Store) RequireAuthorizedKeyWithDevice(ctx context.Context, keyID int64, ip, deviceToken string) error {
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM api_keys WHERE id=?`, keyID).Scan(&status); err != nil || status != "active" {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return ErrKeyInactive
	}
	var allowed int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM key_ips WHERE key_id=? AND ip=?`, keyID, ip).Scan(&allowed); err != nil {
		return err
	}
	if allowed == 0 {
		var ipBindings int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_ips WHERE key_id=?", keyID).Scan(&ipBindings); err != nil {
			return err
		}
		if ipBindings > 0 {
			return ErrIPNotAllowed
		}
		var deviceBindings int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=?", keyID).Scan(&deviceBindings); err != nil {
			return err
		}
		if deviceBindings == 0 {
			return ErrIPNotAllowed
		}
	}
	var deviceCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=?", keyID).Scan(&deviceCount); err != nil {
		return err
	}
	if deviceCount > 0 {
		if strings.TrimSpace(deviceToken) == "" {
			return ErrDeviceNotAllowed
		}
		var deviceAllowed int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=? AND device_token_hash=?", keyID, tokenHash(deviceToken)).Scan(&deviceAllowed); err != nil {
			return err
		}
		if deviceAllowed == 0 {
			return ErrDeviceNotAllowed
		}
	}
	return nil
}

func (s *Store) ConsumeQuota(ctx context.Context, keyID int64) error {
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `UPDATE api_keys SET used_requests=used_requests+1,last_used_at=?,updated_at=? WHERE id=? AND status='active' AND (quota_requests=0 OR used_requests<quota_requests)`, now, now, keyID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		var status string
		if err := s.db.QueryRowContext(ctx, "SELECT status FROM api_keys WHERE id=?", keyID).Scan(&status); err != nil || status != "active" {
			return ErrKeyInactive
		}
		return ErrQuotaExceeded
	}
	return nil
}

// ConsumeQuotaAuthorized re-checks both the key state and its IP ACL while
// consuming quota. The proxy calls this immediately before dispatching the
// upstream request so an ACL removal that raced with the initial lookup cannot
// leave a newly admitted request behind.
func (s *Store) ConsumeQuotaAuthorized(ctx context.Context, keyID int64, ip string) error {
	return s.ConsumeQuotaAuthorizedWithDevice(ctx, keyID, ip, "")
}

func (s *Store) ConsumeQuotaAuthorizedWithDevice(ctx context.Context, keyID int64, ip, deviceToken string) error {
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `UPDATE api_keys
SET used_requests=used_requests+1,last_used_at=?,updated_at=?
WHERE id=? AND status='active'
  AND (quota_requests=0 OR used_requests<quota_requests)
  AND (NOT EXISTS(SELECT 1 FROM key_ips WHERE key_id=?) OR EXISTS(SELECT 1 FROM key_ips WHERE key_id=? AND ip=?))
  AND (NOT EXISTS(SELECT 1 FROM key_devices WHERE key_id=?) OR EXISTS(SELECT 1 FROM key_devices WHERE key_id=? AND device_token_hash=?))`, now, now, keyID, keyID, keyID, ip, keyID, keyID, tokenHash(deviceToken))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 0 {
		return nil
	}
	var status string
	var quota, used int64
	if err := s.db.QueryRowContext(ctx, "SELECT status,quota_requests,used_requests FROM api_keys WHERE id=?", keyID).Scan(&status, &quota, &used); err != nil || status != "active" {
		return ErrKeyInactive
	}
	var allowed int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_ips WHERE key_id=? AND ip=?", keyID, ip).Scan(&allowed); err != nil {
		return err
	}
	if allowed == 0 {
		var keyIPCount int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_ips WHERE key_id=?", keyID).Scan(&keyIPCount); err != nil {
			return err
		}
		if keyIPCount > 0 {
			return ErrIPNotAllowed
		}
	}
	var deviceCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=?", keyID).Scan(&deviceCount); err != nil {
		return err
	}
	if deviceCount > 0 {
		var deviceAllowed int
		if strings.TrimSpace(deviceToken) == "" || s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM key_devices WHERE key_id=? AND device_token_hash=?", keyID, tokenHash(deviceToken)).Scan(&deviceAllowed) != nil || deviceAllowed == 0 {
			return ErrDeviceNotAllowed
		}
	}
	if quota > 0 && used >= quota {
		return ErrQuotaExceeded
	}
	return ErrQuotaExceeded
}

func (s *Store) TouchKeyIP(ctx context.Context, keyID int64, ip string) {
	_, _ = s.db.ExecContext(ctx, "UPDATE key_ips SET last_seen_at=? WHERE key_id=? AND ip=?", time.Now().Unix(), keyID, ip)
}

func (s *Store) TouchKeyDevice(ctx context.Context, keyID int64, deviceToken string) {
	if strings.TrimSpace(deviceToken) == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx, "UPDATE key_devices SET last_seen_at=? WHERE key_id=? AND device_token_hash=?", time.Now().Unix(), keyID, tokenHash(deviceToken))
}

func (s *Store) IsBanned(ctx context.Context, ip string) (bool, error) {
	var expires int64
	err := s.db.QueryRowContext(ctx, "SELECT expires_at FROM banned_ips WHERE ip=?", ip).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if expires > 0 && expires <= time.Now().Unix() {
		_, _ = s.db.ExecContext(ctx, "DELETE FROM banned_ips WHERE ip=?", ip)
		return false, nil
	}
	return true, nil
}

func (s *Store) Setting(ctx context.Context, key string) string {
	value, _ := s.SettingValue(ctx, key)
	return value
}

func (s *Store) SettingValue(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, time.Now().Unix())
	return err
}

const openAIOAuthFlowSettingPrefix = "oauth_flow:"

type storedOpenAIOAuthFlow struct {
	SessionID    string `json:"session_id"`
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	OwnerHash    string `json:"owner_hash"`
	IP           string `json:"ip"`
	CreatedAt    int64  `json:"created_at"`
}

func (s *Store) SaveOpenAIOAuthFlow(ctx context.Context, flow *openAIOAuthFlow) error {
	if flow == nil || strings.TrimSpace(flow.State) == "" {
		return errors.New("invalid OAuth flow")
	}
	payload, err := json.Marshal(storedOpenAIOAuthFlow{
		SessionID: flow.SessionID, State: flow.State, CodeVerifier: flow.CodeVerifier,
		OwnerHash: flow.OwnerHash, IP: flow.IP, CreatedAt: flow.CreatedAt.Unix(),
	})
	if err != nil {
		return err
	}
	encrypted, err := s.vault.Encrypt(string(payload), "openai-oauth-flow")
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, openAIOAuthFlowSettingPrefix+flow.State, encrypted)
}

func (s *Store) OpenAIOAuthFlow(ctx context.Context, state string) (*openAIOAuthFlow, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, nil
	}
	encrypted, err := s.SettingValue(ctx, openAIOAuthFlowSettingPrefix+state)
	if err != nil || encrypted == "" {
		return nil, err
	}
	payload, err := s.vault.Decrypt(encrypted, "openai-oauth-flow")
	if err != nil {
		return nil, err
	}
	var stored storedOpenAIOAuthFlow
	if err := json.Unmarshal([]byte(payload), &stored); err != nil {
		return nil, err
	}
	if subtleCompare(stored.State, state) != 1 || stored.SessionID == "" || stored.CodeVerifier == "" || stored.CreatedAt <= 0 {
		return nil, errors.New("invalid OAuth flow")
	}
	return &openAIOAuthFlow{
		SessionID: stored.SessionID, State: stored.State, CodeVerifier: stored.CodeVerifier,
		OwnerHash: stored.OwnerHash, IP: stored.IP, CreatedAt: time.Unix(stored.CreatedAt, 0),
	}, nil
}

func (s *Store) DeleteOpenAIOAuthFlow(ctx context.Context, state string) error {
	if strings.TrimSpace(state) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM settings WHERE key=?", openAIOAuthFlowSettingPrefix+strings.TrimSpace(state))
	return err
}

func (s *Store) CleanupOpenAIOAuthFlows(ctx context.Context, olderThan time.Time) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM settings WHERE key LIKE ? AND updated_at<?", openAIOAuthFlowSettingPrefix+"%", olderThan.Unix())
	return err
}

func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

// CheckObservability verifies the exact read/write columns used by all three
// monitoring pipelines. Every synthetic row is inserted and read back inside
// one transaction which is always rolled back, so the health probe can catch a
// broken table/trigger/read-only database without manufacturing visible logs.
func (s *Store) CheckObservability(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rolledBack := false
	defer func() {
		if !rolledBack {
			_ = tx.Rollback()
		}
	}()
	var tables int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('usage_logs','audit_logs','security_events')`).Scan(&tables); err != nil {
		return err
	}
	if tables != 3 {
		return errors.New("observability schema is incomplete")
	}
	now := time.Now().Unix()
	usageResult, err := tx.ExecContext(ctx, `INSERT INTO usage_logs(
key_id,account_id,ip,method,path,model,status,duration_ms,input_tokens,output_tokens,total_tokens,request_id,error,created_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, 0, 0, "health-probe", "PROBE", "/health/observability", "health-probe", 200, 0, 0, 0, 0, "health-probe", "", now)
	if err != nil {
		return fmt.Errorf("usage log write probe: %w", err)
	}
	usageID, err := usageResult.LastInsertId()
	if err != nil {
		return fmt.Errorf("usage log probe id: %w", err)
	}
	var usage UsageLog
	var usageKeyID, usageAccountID int64
	if err := tx.QueryRowContext(ctx, `SELECT id,key_id,account_id,ip,method,path,model,status,duration_ms,input_tokens,output_tokens,total_tokens,request_id,error,created_at
FROM usage_logs WHERE id=?`, usageID).Scan(&usage.ID, &usageKeyID, &usageAccountID, &usage.IP, &usage.Method, &usage.Path, &usage.Model, &usage.Status, &usage.DurationMS, &usage.InputTokens, &usage.OutputTokens, &usage.TotalTokens, &usage.RequestID, &usage.Error, &usage.CreatedAt); err != nil {
		return fmt.Errorf("usage log read probe: %w", err)
	}

	auditResult, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,ip,detail,created_at) VALUES(?,?,?,?,?,?)`, "health-probe", "health.probe", "observability", "health-probe", "", now)
	if err != nil {
		return fmt.Errorf("audit log write probe: %w", err)
	}
	auditID, err := auditResult.LastInsertId()
	if err != nil {
		return fmt.Errorf("audit log probe id: %w", err)
	}
	var audit AuditLog
	if err := tx.QueryRowContext(ctx, `SELECT id,actor,action,target,ip,detail,created_at FROM audit_logs WHERE id=?`, auditID).Scan(&audit.ID, &audit.Actor, &audit.Action, &audit.Target, &audit.IP, &audit.Detail, &audit.CreatedAt); err != nil {
		return fmt.Errorf("audit log read probe: %w", err)
	}

	securityResult, err := tx.ExecContext(ctx, `INSERT INTO security_events(ip,kind,path,detail,created_at) VALUES(?,?,?,?,?)`, "health-probe", "health_probe", "/health/observability", "", now)
	if err != nil {
		return fmt.Errorf("security log write probe: %w", err)
	}
	securityID, err := securityResult.LastInsertId()
	if err != nil {
		return fmt.Errorf("security log probe id: %w", err)
	}
	var event SecurityEvent
	if err := tx.QueryRowContext(ctx, `SELECT id,ip,kind,path,detail,created_at FROM security_events WHERE id=?`, securityID).Scan(&event.ID, &event.IP, &event.Kind, &event.Path, &event.Detail, &event.CreatedAt); err != nil {
		return fmt.Errorf("security log read probe: %w", err)
	}
	if err := tx.Rollback(); err != nil {
		return fmt.Errorf("roll back observability probe: %w", err)
	}
	rolledBack = true
	return nil
}

func (s *Store) SaveNginxBaseline(ctx context.Context, hash, version string) error {
	if strings.TrimSpace(hash) == "" || strings.TrimSpace(version) == "" {
		return errors.New("invalid Nginx baseline")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	for key, value := range map[string]string{
		"security_nginx_baseline":         hash,
		"security_nginx_baseline_version": version,
		"security_nginx_last_alert_hash":  "",
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SecurityConfig(ctx context.Context) SecurityConfig {
	config := SecurityConfig{NginxProtection: true, Threshold404: 12, Threshold502: 30, WindowMinutes: 10, BanHours: 24}
	values := map[string]*string{}
	for _, key := range []string{"security_protection_enabled", "security_nginx_protection", "security_threshold_404", "security_threshold_502", "security_window_minutes", "security_ban_hours"} {
		value := ""
		values[key] = &value
		_ = s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&value)
	}
	if parsed, err := strconv.ParseBool(*values["security_protection_enabled"]); err == nil {
		config.ProtectionEnabled = parsed
	}
	if parsed, err := strconv.ParseBool(*values["security_nginx_protection"]); err == nil {
		config.NginxProtection = parsed
	}
	if parsed, err := strconv.Atoi(*values["security_threshold_404"]); err == nil && parsed >= 3 && parsed <= 10000 {
		config.Threshold404 = parsed
	}
	if parsed, err := strconv.Atoi(*values["security_threshold_502"]); err == nil && parsed >= 3 && parsed <= 10000 {
		config.Threshold502 = parsed
	}
	if parsed, err := strconv.Atoi(*values["security_window_minutes"]); err == nil && parsed >= 1 && parsed <= 1440 {
		config.WindowMinutes = parsed
	}
	if parsed, err := strconv.Atoi(*values["security_ban_hours"]); err == nil && parsed >= 1 && parsed <= 8760 {
		config.BanHours = parsed
	}
	return config
}

func (s *Store) SaveSecurityConfig(ctx context.Context, config SecurityConfig) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	values := map[string]string{
		"security_protection_enabled": strconv.FormatBool(config.ProtectionEnabled),
		"security_nginx_protection":   strconv.FormatBool(config.NginxProtection),
		"security_threshold_404":      strconv.Itoa(config.Threshold404),
		"security_threshold_502":      strconv.Itoa(config.Threshold502),
		"security_window_minutes":     strconv.Itoa(config.WindowMinutes),
		"security_ban_hours":          strconv.Itoa(config.BanHours),
	}
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RecordSecurityEvent(ctx context.Context, ip, kind, path, detail string) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(writeCtx, `INSERT INTO security_events(ip,kind,path,detail,created_at) VALUES(?,?,?,?,?)`, ip, kind, truncate(path, 500), truncate(detail, 500), time.Now().Unix())
	s.reportRuntimeFailure("security_log", err)
	if err != nil {
		slog.Error("security event persistence failed", "kind", kind, "error", err)
	}
	return err
}

// prepareBanGroup gives every ban episode a durable membership identifier.
// The relationship must not depend on key_ips: deleting a Key deliberately
// destroys its ACL, but an administrator must still be able to unban both
// addresses of a previously paired IPv4/IPv6 device afterwards.
func (s *Store) prepareBanGroup(ctx context.Context, tx *sql.Tx, ips []string, seed string) (string, error) {
	group := "ban-" + tokenHash(seed)[:24]
	chosenExisting := false
	existingGroups := make(map[string]bool)
	for _, ip := range ips {
		var existing string
		err := tx.QueryRowContext(ctx, "SELECT ban_group FROM banned_ips WHERE ip=?", ip).Scan(&existing)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return "", err
		}
		if existing == "" {
			continue
		}
		existingGroups[existing] = true
		if !chosenExisting {
			group = existing
			chosenExisting = true
		}
	}
	// If two previously separate ban groups now overlap through a device ACL,
	// merge the entire old groups so a later unban remains all-or-nothing.
	for existing := range existingGroups {
		if existing == group {
			continue
		}
		if _, err := tx.ExecContext(ctx, "UPDATE banned_ips SET ban_group=? WHERE ban_group=?", group, existing); err != nil {
			return "", err
		}
	}
	return group, nil
}

func (s *Store) RecordStatusFailure(ctx context.Context, ip string, status, threshold int, window, banDuration time.Duration, path string) (bool, error) {
	now := time.Now().Unix()
	windowStart := now - int64(window.Seconds())
	relatedIPs, err := s.relatedDeviceIPs(ctx, ip)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var start, attempts int64
	err = tx.QueryRowContext(ctx, "SELECT window_start,attempts FROM status_failures WHERE ip=? AND status=?", ip, status).Scan(&start, &attempts)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && start < windowStart) {
		start, attempts = now, 0
	} else if err != nil {
		return false, err
	}
	attempts++
	if _, err := tx.ExecContext(ctx, `INSERT INTO status_failures(ip,status,window_start,attempts,last_attempt) VALUES(?,?,?,?,?)
ON CONFLICT(ip,status) DO UPDATE SET window_start=excluded.window_start,attempts=excluded.attempts,last_attempt=excluded.last_attempt`, ip, status, start, attempts, now); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_events(ip,kind,path,detail,created_at) VALUES(?,?,?,?,?)`, ip, fmt.Sprintf("http_%d", status), truncate(path, 500), fmt.Sprintf("窗口内第 %d/%d 次", attempts, threshold), now); err != nil {
		return false, err
	}
	banned := attempts >= int64(threshold)
	if banned {
		expires := now + int64(banDuration.Seconds())
		banGroup, err := s.prepareBanGroup(ctx, tx, relatedIPs, fmt.Sprintf("status\x00%d\x00%s\x00%d", status, ip, now))
		if err != nil {
			return false, err
		}
		for _, targetIP := range relatedIPs {
			reason := fmt.Sprintf("HTTP %d exceeded threshold", status)
			if targetIP != ip {
				reason = fmt.Sprintf("paired dual-stack address; HTTP %d threshold", status)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope) VALUES(?,?,?,?,?,?, 'public')
ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,attempts=excluded.attempts,created_at=excluded.created_at,expires_at=excluded.expires_at,ban_group=excluded.ban_group,scope=CASE WHEN banned_ips.scope='all' THEN 'all' ELSE excluded.scope END`, targetIP, reason, attempts, now, expires, banGroup); err != nil {
				return false, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return banned, nil
}

func (s *Store) BanIP(ctx context.Context, ip, reason string, duration time.Duration, permanent bool, protectedIPs ...string) error {
	relatedIPs, err := s.relatedDeviceIPs(ctx, ip)
	if err != nil {
		return err
	}
	for _, relatedIP := range relatedIPs {
		for _, protectedIP := range protectedIPs {
			if relatedIP == protectedIP {
				return ErrProtectedIP
			}
		}
	}
	now := time.Now().Unix()
	expires := int64(0)
	if !permanent {
		expires = now + int64(duration.Seconds())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	banGroup, err := s.prepareBanGroup(ctx, tx, relatedIPs, fmt.Sprintf("manual\x00%s\x00%d", ip, now))
	if err != nil {
		return err
	}
	for _, targetIP := range relatedIPs {
		targetReason := reason
		if targetIP != ip {
			targetReason += " (paired dual-stack address)"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope) VALUES(?,?,?,?,?,?, 'all')
ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,attempts=excluded.attempts,created_at=excluded.created_at,expires_at=excluded.expires_at,ban_group=excluded.ban_group,scope='all'`, targetIP, targetReason, 0, now, expires, banGroup); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_events(ip,kind,path,detail,created_at) VALUES(?,?,?,?,?)`, targetIP, "manual_ban", "", truncate(targetReason, 500), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RecordUnauthorized(ctx context.Context, ip, kind, path, detail string, threshold int, window, banDuration time.Duration) (bool, error) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	now := time.Now().Unix()
	windowStart := now - int64(window.Seconds())
	relatedIPs, relatedErr := s.relatedDeviceIPs(writeCtx, ip)
	if relatedErr != nil {
		return false, relatedErr
	}
	tx, err := s.db.BeginTx(writeCtx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(writeCtx, `INSERT INTO security_events(ip,kind,path,detail,created_at) VALUES(?,?,?,?,?)`, ip, kind, truncate(path, 500), truncate(detail, 500), now); err != nil {
		return false, err
	}
	var start, attempts int64
	err = tx.QueryRowContext(writeCtx, "SELECT window_start,attempts FROM ip_failures WHERE ip=?", ip).Scan(&start, &attempts)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && start < windowStart) {
		start = now
		attempts = 0
	} else if err != nil {
		return false, err
	}
	attempts++
	_, err = tx.ExecContext(writeCtx, `INSERT INTO ip_failures(ip,window_start,attempts,last_attempt) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET window_start=excluded.window_start,attempts=excluded.attempts,last_attempt=excluded.last_attempt`, ip, start, attempts, now)
	if err != nil {
		return false, err
	}
	banned := attempts >= int64(threshold)
	if banned {
		expires := now + int64(banDuration.Seconds())
		banGroup, err := s.prepareBanGroup(writeCtx, tx, relatedIPs, fmt.Sprintf("unauthorized\x00%s\x00%d", ip, now))
		if err != nil {
			return false, err
		}
		for _, targetIP := range relatedIPs {
			reason := "unauthorized API access"
			if targetIP != ip {
				reason = "paired dual-stack address blocked"
			}
			_, err = tx.ExecContext(writeCtx, `INSERT INTO banned_ips(ip,reason,attempts,created_at,expires_at,ban_group,scope) VALUES(?,?,?,?,?,?, 'public') ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,attempts=excluded.attempts,created_at=excluded.created_at,expires_at=excluded.expires_at,ban_group=excluded.ban_group,scope=CASE WHEN banned_ips.scope='all' THEN 'all' ELSE excluded.scope END`, targetIP, reason, attempts, now, expires, banGroup)
			if err != nil {
				return false, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return banned, nil
}

func (s *Store) relatedDeviceIPs(ctx context.Context, ip string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT sibling.ip
FROM key_ips source JOIN key_ips sibling ON sibling.device_group=source.device_group
WHERE source.ip=? AND source.device_group<>'' ORDER BY sibling.ip`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{ip}
	seen := map[string]bool{ip: true}
	for rows.Next() {
		var related string
		if err := rows.Scan(&related); err != nil {
			return nil, err
		}
		if !seen[related] {
			seen[related] = true
			result = append(result, related)
		}
	}
	return result, rows.Err()
}

func (s *Store) ListBans(ctx context.Context) ([]BannedIP, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT ip,reason,scope,attempts,created_at,expires_at FROM banned_ips WHERE expires_at=0 OR expires_at>? ORDER BY created_at DESC", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []BannedIP
	for rows.Next() {
		var item BannedIP
		if err := rows.Scan(&item.IP, &item.Reason, &item.Scope, &item.Attempts, &item.CreatedAt, &item.ExpiresAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) BanMembers(ctx context.Context, ip string) ([]string, error) {
	var group string
	err := s.db.QueryRowContext(ctx, "SELECT ban_group FROM banned_ips WHERE ip=? AND (expires_at=0 OR expires_at>?)", ip, time.Now().Unix()).Scan(&group)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT ip FROM banned_ips WHERE ban_group=? AND (expires_at=0 OR expires_at>?) ORDER BY ip", group, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var member string
		if err := rows.Scan(&member); err != nil {
			return nil, err
		}
		result = append(result, member)
	}
	return result, rows.Err()
}

func (s *Store) UnbanMembers(ctx context.Context, ip string) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Resolve both the current ACL relation and the durable ban-group relation
	// inside one transaction. The latter survives Key/IP deletion.
	targets := map[string]bool{ip: true}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT sibling.ip
FROM key_ips source JOIN key_ips sibling ON sibling.device_group=source.device_group
WHERE source.ip=? AND source.device_group<>'' ORDER BY sibling.ip`, ip)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var related string
		if err := rows.Scan(&related); err != nil {
			_ = rows.Close()
			return nil, err
		}
		targets[related] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	groups := make(map[string]bool)
	for targetIP := range targets {
		var group string
		err := tx.QueryRowContext(ctx, "SELECT ban_group FROM banned_ips WHERE ip=?", targetIP).Scan(&group)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if group != "" {
			groups[group] = true
		}
	}
	for group := range groups {
		members, err := tx.QueryContext(ctx, "SELECT ip FROM banned_ips WHERE ban_group=?", group)
		if err != nil {
			return nil, err
		}
		for members.Next() {
			var member string
			if err := members.Scan(&member); err != nil {
				_ = members.Close()
				return nil, err
			}
			targets[member] = true
		}
		if err := members.Err(); err != nil {
			_ = members.Close()
			return nil, err
		}
		if err := members.Close(); err != nil {
			return nil, err
		}
	}
	for targetIP := range targets {
		if _, err := tx.ExecContext(ctx, "DELETE FROM banned_ips WHERE ip=?", targetIP); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM ip_failures WHERE ip=?", targetIP); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM status_failures WHERE ip=?", targetIP); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	removed := make([]string, 0, len(targets))
	for targetIP := range targets {
		removed = append(removed, targetIP)
	}
	return removed, nil
}

func (s *Store) Unban(ctx context.Context, ip string) error {
	_, err := s.UnbanMembers(ctx, ip)
	return err
}

func (s *Store) LogUsage(ctx context.Context, keyID, accountID int64, log UsageLog) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO usage_logs(key_id,account_id,ip,method,path,model,status,duration_ms,input_tokens,output_tokens,total_tokens,request_id,error,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, keyID, accountID, log.IP, log.Method, log.Path, truncate(log.Model, 100), log.Status, log.DurationMS, log.InputTokens, log.OutputTokens, log.TotalTokens, truncate(log.RequestID, 200), truncate(log.Error, 500), time.Now().Unix())
	s.reportRuntimeFailure("usage_log", err)
	return err
}
func (s *Store) ListUsage(ctx context.Context, limit int) ([]UsageLog, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT u.id,k.role,a.name,u.ip,u.method,u.path,u.model,u.status,u.duration_ms,u.input_tokens,u.output_tokens,u.total_tokens,u.request_id,u.error,u.created_at FROM usage_logs u JOIN api_keys k ON k.id=u.key_id JOIN accounts a ON a.id=u.account_id ORDER BY u.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []UsageLog
	for rows.Next() {
		var item UsageLog
		if err := rows.Scan(&item.ID, &item.Role, &item.AccountName, &item.IP, &item.Method, &item.Path, &item.Model, &item.Status, &item.DurationMS, &item.InputTokens, &item.OutputTokens, &item.TotalTokens, &item.RequestID, &item.Error, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) Audit(ctx context.Context, actor, action, target, ip string, detail any) error {
	encoded := ""
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			s.reportRuntimeFailure("audit_log", err)
			slog.Error("audit serialization failed", "action", action, "target", target, "error", err)
			return err
		}
		encoded = string(b)
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(writeCtx, `INSERT INTO audit_logs(actor,action,target,ip,detail,created_at) VALUES(?,?,?,?,?,?)`, actor, action, target, ip, truncate(encoded, 2000), time.Now().Unix())
	s.reportRuntimeFailure("audit_log", err)
	if err != nil {
		slog.Error("audit persistence failed", "action", action, "target", target, "error", err)
	}
	return err
}
func (s *Store) ListAudits(ctx context.Context, limit int) ([]AuditLog, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,actor,action,target,ip,detail,created_at FROM audit_logs ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AuditLog
	for rows.Next() {
		var item AuditLog
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.Target, &item.IP, &item.Detail, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
func (s *Store) ListSecurityEvents(ctx context.Context, limit int) ([]SecurityEvent, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,ip,kind,path,detail,created_at FROM security_events ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SecurityEvent
	for rows.Next() {
		var item SecurityEvent
		if err := rows.Scan(&item.ID, &item.IP, &item.Kind, &item.Path, &item.Detail, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) Dashboard(ctx context.Context) (map[string]any, error) {
	result := map[string]any{}
	queries := map[string]string{
		"accounts":       "SELECT COUNT(*) FROM accounts WHERE active=1",
		"keys":           "SELECT COUNT(*) FROM api_keys WHERE status='active'",
		"keys_total":     "SELECT COUNT(*) FROM api_keys WHERE status<>'deleted'",
		"keys_deleted":   "SELECT COUNT(*) FROM api_keys WHERE status='deleted'",
		"calls_total":    "SELECT COUNT(*) FROM usage_logs",
		"requests_today": "SELECT COUNT(*) FROM usage_logs WHERE created_at>=?",
		"blocked_today":  "SELECT COUNT(*) FROM security_events WHERE created_at>=?",
		"bans":           "SELECT COUNT(*) FROM banned_ips WHERE expires_at=0 OR expires_at>?",
	}
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	for key, q := range queries {
		var count int64
		arg := time.Now().Unix()
		if key == "requests_today" || key == "blocked_today" {
			arg = midnight
		}
		if strings.Contains(q, "?") {
			if err := s.db.QueryRowContext(ctx, q, arg).Scan(&count); err != nil {
				return nil, err
			}
		} else if err := s.db.QueryRowContext(ctx, q).Scan(&count); err != nil {
			return nil, err
		}
		result[key] = count
	}
	var tokensToday, errorsToday int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_tokens),0),
COALESCE(SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),0)
FROM usage_logs WHERE created_at>=?`, midnight).Scan(&tokensToday, &errorsToday); err != nil {
		return nil, err
	}
	result["tokens_today"] = tokensToday
	result["errors_today"] = errorsToday
	rows, err := s.db.QueryContext(ctx, `SELECT CASE WHEN TRIM(model)='' THEN '未知模型' ELSE model END,
COUNT(*),COALESCE(SUM(total_tokens),0)
FROM usage_logs WHERE created_at>=?
GROUP BY CASE WHEN TRIM(model)='' THEN '未知模型' ELSE model END
ORDER BY COUNT(*) DESC,COALESCE(SUM(total_tokens),0) DESC LIMIT 8`, midnight)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ranking := make([]ModelUsageRank, 0, 8)
	for rows.Next() {
		var item ModelUsageRank
		if err := rows.Scan(&item.Model, &item.Calls, &item.TotalTokens); err != nil {
			return nil, err
		}
		ranking = append(ranking, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result["model_ranking"] = ranking
	return result, nil
}

func (s *Store) Cleanup(ctx context.Context) error {
	now := time.Now().Unix()
	cutoff := time.Now().Add(-30 * 24 * time.Hour).Unix()
	statements := []struct {
		query string
		args  []any
	}{
		{"DELETE FROM admin_sessions WHERE expires_at<=?", []any{now}},
		{"DELETE FROM banned_ips WHERE expires_at>0 AND expires_at<=?", []any{now}},
		{"DELETE FROM ip_failures WHERE last_attempt<?", []any{time.Now().Add(-24 * time.Hour).Unix()}},
		{"DELETE FROM status_failures WHERE last_attempt<?", []any{time.Now().Add(-24 * time.Hour).Unix()}},
		{"UPDATE invitations SET status='expired',token_enc='',code_hash='',claim_session_hash='',probe_token_hash='',device_token_hash='' WHERE status='pending' AND expires_at<=?", []any{now}},
		{"DELETE FROM session_affinities WHERE expires_at<=?", []any{now}},
		{"DELETE FROM usage_logs WHERE created_at<?", []any{cutoff}},
		{"DELETE FROM security_events WHERE created_at<?", []any{cutoff}},
		{"DELETE FROM audit_logs WHERE created_at<?", []any{cutoff}},
		{"DELETE FROM usage_logs WHERE id<=COALESCE((SELECT id FROM usage_logs ORDER BY id DESC LIMIT 1 OFFSET 200000),0)", nil},
		{"DELETE FROM security_events WHERE id<=COALESCE((SELECT id FROM security_events ORDER BY id DESC LIMIT 1 OFFSET 100000),0)", nil},
		{"DELETE FROM audit_logs WHERE id<=COALESCE((SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1 OFFSET 100000),0)", nil},
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")
	return nil
}

func maskAPIKey(value string) string {
	if len(value) < 16 {
		return "********"
	}
	return value[:8] + "..." + value[len(value)-6:]
}
func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}
func parseID(value string) (int64, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id < 1 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

func ipFamily(ip string) string {
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	return "ipv4"
}
