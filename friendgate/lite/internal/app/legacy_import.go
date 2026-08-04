package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LegacyImportReport is intentionally a data-only report.  It can be saved
// with an administrative audit event or emitted by the migration command
// without exposing any credentials, API keys, IP addresses, or email values.
type LegacyImportReport struct {
	RunID             string           `json:"run_id,omitempty"`
	SourceFingerprint string           `json:"source_fingerprint"`
	Mode              string           `json:"mode"`
	StartedAt         time.Time        `json:"started_at"`
	CompletedAt       time.Time        `json:"completed_at,omitempty"`
	Tables            map[string]Count `json:"tables"`
	Skipped           map[string]int64 `json:"skipped,omitempty"`
	Verified          bool             `json:"verified"`
}

type Count struct {
	Source      int64 `json:"source"`
	Imported    int64 `json:"imported"`
	Destination int64 `json:"destination"`
}

type legacyImportSnapshot struct {
	Admin       legacyAdmin
	Users       []legacyUser
	Accounts    []legacyAccount
	Models      []legacyAccountModel
	Keys        []legacyKey
	KeyIPs      map[int64][]legacyKeyIP
	KeyDevices  map[int64][]legacyKeyDevice
	Invitations []legacyInvitation
	Devices     []legacyDevice
	Usage       []legacyUsage
	Audits      []legacyAudit
	Bans        []legacyBan
}

type legacyAdmin struct{ Username, PasswordHash, TOTPEncrypted string }
type legacyUser struct {
	ID                                          int64
	Email, DisplayName, PasswordHash, Status    string
	APIKeyID, LastLoginAt, CreatedAt, UpdatedAt int64
}
type legacyAccount struct {
	ID                                                                                                         int64
	Name, AccessToken, RefreshToken, AccountRef, ClientID, LastError, PlanType, QuotaError                     string
	Active                                                                                                     bool
	ExpiresAt, LastUsedAt, CooldownUntil, Quota5HResetAt, Quota7DResetAt, QuotaUpdatedAt, CreatedAt, UpdatedAt int64
	Quota5HUsed, Quota7DUsed                                                                                   float64
	ResetCredits                                                                                               int
	ResetCreditTimes                                                                                           string
}
type legacyAccountModel struct {
	AccountID, UpdatedAt                int64
	ModelID, ModelJSON, Object, OwnedBy string
}
type legacyKey struct {
	ID, AccountID, QuotaRequests, UsedRequests, LastUsedAt, CreatedAt, UpdatedAt int64
	Role, KeyHash, PlainKey, MaskedKey, Status                                   string
}
type legacyKeyIP struct {
	IP, Family, Note, Group string
	CreatedAt, LastSeenAt   int64
}
type legacyKeyDevice struct {
	Hash, Note            string
	CreatedAt, LastSeenAt int64
}
type legacyInvitation struct {
	ID, AccountID, QuotaRequests, ExpiresAt, GeneratedAt, CreatedAt, APIKeyID int64
	Role, TokenHash, CodeHash, Status, BindingMode, VerifiedIP, DeviceNote    string
}
type legacyDevice struct {
	ID, UserID, LastSeenAt, CreatedAt, UpdatedAt                                   int64
	PublicKey, Name, Platform, MACHash, MACEncrypted, RegisteredIP, LastIP, Status string
}
type legacyUsage struct {
	ID, KeyID, AccountID, DurationMS, InputTokens, OutputTokens, TotalTokens, CreatedAt int64
	IP, Method, Path, Model, RequestID, Error                                           string
	Status                                                                              int
}
type legacyAudit struct {
	ID, CreatedAt                     int64
	Actor, Action, Target, IP, Detail string
}
type legacyBan struct {
	IP, Reason, Group, Scope       string
	Attempts, CreatedAt, ExpiresAt int64
}

// ImportLegacyToPlatform is deliberately explicit.  It never runs at service
// startup, it never deletes source rows, and apply=false does not mutate the
// PostgreSQL product tables.  Operators should stop write traffic, run a dry
// run, run apply, inspect its verification result, then enable the later
// authority switch in a separate maintenance action.
func (s *Store) ImportLegacyToPlatform(ctx context.Context, apply bool) (LegacyImportReport, error) {
	platform := s.Platform()
	if platform == nil {
		return LegacyImportReport{}, ErrPlatformDatabaseUnavailable
	}
	started := time.Now().UTC()
	snapshot, err := s.readLegacyImportSnapshot(ctx)
	if err != nil {
		return LegacyImportReport{}, err
	}
	report := legacyReport(snapshot, apply, started)
	if !apply {
		report.Verified = true
		report.CompletedAt = time.Now().UTC()
		return report, nil
	}
	if err := platform.applyLegacySnapshot(ctx, snapshot, &report); err != nil {
		return report, err
	}
	report.CompletedAt = time.Now().UTC()
	return report, nil
}

// RunLegacyPlatformImport is the offline command entry point.  The command is
// intentionally separate from the HTTP server so an apply operation can be
// performed while all request writers are stopped.  It reuses the deployed
// data directory, master key and PostgreSQL URL; it does not print secrets.
func RunLegacyPlatformImport(ctx context.Context, apply bool) (LegacyImportReport, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return LegacyImportReport{}, err
	}
	vault, err := NewVault(cfg.MasterKey)
	if err != nil {
		return LegacyImportReport{}, err
	}
	store, err := OpenStore(cfg, vault)
	if err != nil {
		return LegacyImportReport{}, err
	}
	defer store.Close()
	return store.ImportLegacyToPlatform(ctx, apply)
}

func (s *Store) readLegacyImportSnapshot(ctx context.Context) (legacyImportSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return legacyImportSnapshot{}, err
	}
	defer tx.Rollback()
	var snapshot legacyImportSnapshot
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='admin_username'),''), COALESCE((SELECT value FROM settings WHERE key='admin_password_hash'),''), COALESCE((SELECT value FROM settings WHERE key='admin_totp_secret_enc'),'')`).Scan(&snapshot.Admin.Username, &snapshot.Admin.PasswordHash, &snapshot.Admin.TOTPEncrypted); err != nil {
		return snapshot, err
	}
	users, err := tx.QueryContext(ctx, `SELECT id,email,display_name,password_hash,status,COALESCE(api_key_id,0),last_login_at,created_at,updated_at FROM desktop_users ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for users.Next() {
		var row legacyUser
		if err := users.Scan(&row.ID, &row.Email, &row.DisplayName, &row.PasswordHash, &row.Status, &row.APIKeyID, &row.LastLoginAt, &row.CreatedAt, &row.UpdatedAt); err != nil {
			users.Close()
			return snapshot, err
		}
		snapshot.Users = append(snapshot.Users, row)
	}
	if err := users.Close(); err != nil {
		return snapshot, err
	}
	accounts, err := tx.QueryContext(ctx, `SELECT id,name,access_token_enc,refresh_token_enc,chatgpt_account_id,client_id,active,expires_at,last_used_at,last_error,cooldown_until,plan_type,quota_5h_used,quota_5h_reset_at,quota_7d_used,quota_7d_reset_at,quota_updated_at,quota_error,reset_credits,reset_credit_times,created_at,updated_at FROM accounts WHERE access_token_enc<>'' ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for accounts.Next() {
		var row legacyAccount
		var accessEnc, refreshEnc string
		if err := accounts.Scan(&row.ID, &row.Name, &accessEnc, &refreshEnc, &row.AccountRef, &row.ClientID, &row.Active, &row.ExpiresAt, &row.LastUsedAt, &row.LastError, &row.CooldownUntil, &row.PlanType, &row.Quota5HUsed, &row.Quota5HResetAt, &row.Quota7DUsed, &row.Quota7DResetAt, &row.QuotaUpdatedAt, &row.QuotaError, &row.ResetCredits, &row.ResetCreditTimes, &row.CreatedAt, &row.UpdatedAt); err != nil {
			accounts.Close()
			return snapshot, err
		}
		if row.AccessToken, err = s.vault.Decrypt(accessEnc, "account-access"); err != nil {
			accounts.Close()
			return snapshot, fmt.Errorf("decrypt legacy account %d access credential: %w", row.ID, err)
		}
		if refreshEnc != "" {
			if row.RefreshToken, err = s.vault.Decrypt(refreshEnc, "account-refresh"); err != nil {
				accounts.Close()
				return snapshot, fmt.Errorf("decrypt legacy account %d refresh credential: %w", row.ID, err)
			}
		}
		snapshot.Accounts = append(snapshot.Accounts, row)
	}
	if err := accounts.Close(); err != nil {
		return snapshot, err
	}
	models, err := tx.QueryContext(ctx, `SELECT account_id,model_id,model_json,model_object,owned_by,updated_at FROM account_models ORDER BY account_id,model_id`)
	if err != nil {
		return snapshot, err
	}
	for models.Next() {
		var row legacyAccountModel
		if err := models.Scan(&row.AccountID, &row.ModelID, &row.ModelJSON, &row.Object, &row.OwnedBy, &row.UpdatedAt); err != nil {
			models.Close()
			return snapshot, err
		}
		snapshot.Models = append(snapshot.Models, row)
	}
	if err := models.Close(); err != nil {
		return snapshot, err
	}
	keys, err := tx.QueryContext(ctx, `SELECT id,role,key_hash,key_enc,masked_key,account_id,quota_requests,used_requests,status,last_used_at,created_at,updated_at FROM api_keys ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for keys.Next() {
		var row legacyKey
		var encrypted string
		if err := keys.Scan(&row.ID, &row.Role, &row.KeyHash, &encrypted, &row.MaskedKey, &row.AccountID, &row.QuotaRequests, &row.UsedRequests, &row.Status, &row.LastUsedAt, &row.CreatedAt, &row.UpdatedAt); err != nil {
			keys.Close()
			return snapshot, err
		}
		if encrypted != "" {
			if row.PlainKey, err = s.vault.Decrypt(encrypted, "client-api-key"); err != nil {
				keys.Close()
				return snapshot, fmt.Errorf("decrypt legacy API key %d: %w", row.ID, err)
			}
		}
		snapshot.Keys = append(snapshot.Keys, row)
	}
	if err := keys.Close(); err != nil {
		return snapshot, err
	}
	snapshot.KeyIPs, err = readLegacyKeyIPs(ctx, tx)
	if err != nil {
		return snapshot, err
	}
	snapshot.KeyDevices, err = readLegacyKeyDevices(ctx, tx)
	if err != nil {
		return snapshot, err
	}
	invites, err := tx.QueryContext(ctx, `SELECT id,role,token_hash,code_hash,status,COALESCE(account_id,0),quota_requests,expires_at,verified_ip,device_note,binding_mode,COALESCE(api_key_id,0),generated_at,created_at FROM invitations ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for invites.Next() {
		var row legacyInvitation
		if err := invites.Scan(&row.ID, &row.Role, &row.TokenHash, &row.CodeHash, &row.Status, &row.AccountID, &row.QuotaRequests, &row.ExpiresAt, &row.VerifiedIP, &row.DeviceNote, &row.BindingMode, &row.APIKeyID, &row.GeneratedAt, &row.CreatedAt); err != nil {
			invites.Close()
			return snapshot, err
		}
		snapshot.Invitations = append(snapshot.Invitations, row)
	}
	if err := invites.Close(); err != nil {
		return snapshot, err
	}
	devices, err := tx.QueryContext(ctx, `SELECT id,user_id,public_key,name,platform,mac_hash,mac_enc,registered_ip,last_ip,status,last_seen_at,created_at,updated_at FROM desktop_devices ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for devices.Next() {
		var row legacyDevice
		if err := devices.Scan(&row.ID, &row.UserID, &row.PublicKey, &row.Name, &row.Platform, &row.MACHash, &row.MACEncrypted, &row.RegisteredIP, &row.LastIP, &row.Status, &row.LastSeenAt, &row.CreatedAt, &row.UpdatedAt); err != nil {
			devices.Close()
			return snapshot, err
		}
		snapshot.Devices = append(snapshot.Devices, row)
	}
	if err := devices.Close(); err != nil {
		return snapshot, err
	}
	usage, err := tx.QueryContext(ctx, `SELECT id,key_id,account_id,ip,method,path,model,status,duration_ms,input_tokens,output_tokens,total_tokens,request_id,error,created_at FROM usage_logs ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for usage.Next() {
		var row legacyUsage
		if err := usage.Scan(&row.ID, &row.KeyID, &row.AccountID, &row.IP, &row.Method, &row.Path, &row.Model, &row.Status, &row.DurationMS, &row.InputTokens, &row.OutputTokens, &row.TotalTokens, &row.RequestID, &row.Error, &row.CreatedAt); err != nil {
			usage.Close()
			return snapshot, err
		}
		snapshot.Usage = append(snapshot.Usage, row)
	}
	if err := usage.Close(); err != nil {
		return snapshot, err
	}
	audits, err := tx.QueryContext(ctx, `SELECT id,actor,action,target,ip,detail,created_at FROM audit_logs ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for audits.Next() {
		var row legacyAudit
		if err := audits.Scan(&row.ID, &row.Actor, &row.Action, &row.Target, &row.IP, &row.Detail, &row.CreatedAt); err != nil {
			audits.Close()
			return snapshot, err
		}
		snapshot.Audits = append(snapshot.Audits, row)
	}
	if err := audits.Close(); err != nil {
		return snapshot, err
	}
	bans, err := tx.QueryContext(ctx, `SELECT ip,reason,attempts,created_at,expires_at,ban_group,scope FROM banned_ips ORDER BY ip`)
	if err != nil {
		return snapshot, err
	}
	for bans.Next() {
		var row legacyBan
		if err := bans.Scan(&row.IP, &row.Reason, &row.Attempts, &row.CreatedAt, &row.ExpiresAt, &row.Group, &row.Scope); err != nil {
			bans.Close()
			return snapshot, err
		}
		snapshot.Bans = append(snapshot.Bans, row)
	}
	if err := bans.Close(); err != nil {
		return snapshot, err
	}
	if err := tx.Commit(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func readLegacyKeyIPs(ctx context.Context, tx *sql.Tx) (map[int64][]legacyKeyIP, error) {
	rows, err := tx.QueryContext(ctx, `SELECT key_id,ip,family,device_note,device_group,created_at,last_seen_at FROM key_ips ORDER BY key_id,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[int64][]legacyKeyIP)
	for rows.Next() {
		var id int64
		var row legacyKeyIP
		if err := rows.Scan(&id, &row.IP, &row.Family, &row.Note, &row.Group, &row.CreatedAt, &row.LastSeenAt); err != nil {
			return nil, err
		}
		result[id] = append(result[id], row)
	}
	return result, rows.Err()
}
func readLegacyKeyDevices(ctx context.Context, tx *sql.Tx) (map[int64][]legacyKeyDevice, error) {
	rows, err := tx.QueryContext(ctx, `SELECT key_id,device_token_hash,device_note,created_at,last_seen_at FROM key_devices ORDER BY key_id,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[int64][]legacyKeyDevice)
	for rows.Next() {
		var id int64
		var row legacyKeyDevice
		if err := rows.Scan(&id, &row.Hash, &row.Note, &row.CreatedAt, &row.LastSeenAt); err != nil {
			return nil, err
		}
		result[id] = append(result[id], row)
	}
	return result, rows.Err()
}

func legacyReport(snapshot legacyImportSnapshot, apply bool, started time.Time) LegacyImportReport {
	mode := "dry_run"
	if apply {
		mode = "apply"
	}
	tables := map[string]Count{
		"users": {Source: int64(len(snapshot.Users))}, "accounts": {Source: int64(len(snapshot.Accounts))}, "account_models": {Source: int64(len(snapshot.Models))}, "api_keys": {Source: int64(len(snapshot.Keys))}, "invitations": {Source: int64(len(snapshot.Invitations))}, "devices": {Source: int64(len(snapshot.Devices))}, "usage": {Source: int64(len(snapshot.Usage))}, "audit": {Source: int64(len(snapshot.Audits))}, "ip_bans": {Source: int64(len(snapshot.Bans))},
	}
	return LegacyImportReport{SourceFingerprint: legacyFingerprint(snapshot), Mode: mode, StartedAt: started, Tables: tables, Skipped: map[string]int64{"user_sessions": 0, "desktop_sessions": 0, "desktop_auth_flows": 0}}
}

func legacyFingerprint(snapshot legacyImportSnapshot) string {
	parts := []string{snapshot.Admin.Username, strconv.Itoa(len(snapshot.Users)), strconv.Itoa(len(snapshot.Accounts)), strconv.Itoa(len(snapshot.Models)), strconv.Itoa(len(snapshot.Keys)), strconv.Itoa(len(snapshot.Invitations)), strconv.Itoa(len(snapshot.Devices)), strconv.Itoa(len(snapshot.Usage)), strconv.Itoa(len(snapshot.Audits)), strconv.Itoa(len(snapshot.Bans))}
	for _, item := range snapshot.Users {
		parts = append(parts, "u:"+strconv.FormatInt(item.ID, 10)+":"+item.Email+":"+strconv.FormatInt(item.UpdatedAt, 10))
	}
	for _, item := range snapshot.Accounts {
		parts = append(parts, "a:"+strconv.FormatInt(item.ID, 10)+":"+item.AccountRef+":"+strconv.FormatInt(item.UpdatedAt, 10))
	}
	for _, item := range snapshot.Keys {
		parts = append(parts, "k:"+strconv.FormatInt(item.ID, 10)+":"+item.KeyHash+":"+item.Status+":"+strconv.FormatInt(item.UpdatedAt, 10))
	}
	for _, item := range snapshot.Invitations {
		parts = append(parts, "i:"+strconv.FormatInt(item.ID, 10)+":"+item.TokenHash+":"+item.Status)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func (s *PlatformStore) applyLegacySnapshot(ctx context.Context, snapshot legacyImportSnapshot, report *LegacyImportReport) (err error) {
	report.RunID = newPlatformID()
	if _, err = s.db.ExecContext(ctx, `INSERT INTO legacy_import_runs(id,source_fingerprint,mode,status,report,started_at) VALUES($1,$2,'apply','running',$3,$4)`, report.RunID, report.SourceFingerprint, mustJSON(report), report.StartedAt); err != nil {
		return err
	}
	fail := func(cause error) error {
		_, _ = s.db.ExecContext(context.WithoutCancel(ctx), `UPDATE legacy_import_runs SET status='failed',completed_at=now(),error_text=$2,report=$3 WHERE id=$1`, report.RunID, truncate(cause.Error(), 500), mustJSON(report))
		return cause
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fail(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(912260204)`); err != nil {
		return fail(err)
	}
	if err = s.importLegacyAdmin(ctx, tx, snapshot.Admin, report.RunID); err != nil {
		return fail(fmt.Errorf("import administrator: %w", err))
	}
	userByKey := make(map[int64]string)
	for _, row := range snapshot.Users {
		id := legacyPlatformID("user", row.ID)
		if err = s.importLegacyUser(ctx, tx, row, id, report.RunID); err != nil {
			return fail(fmt.Errorf("import user %d: %w", row.ID, err))
		}
		if row.APIKeyID > 0 {
			userByKey[row.APIKeyID] = id
		}
		markImported(report, "users")
	}
	connectionID := legacyPlatformID("provider_connection", "chatgpt-oauth")
	if err = s.importLegacyProvider(ctx, tx, connectionID); err != nil {
		return fail(fmt.Errorf("import provider: %w", err))
	}
	accountIDs := make(map[int64]string)
	for _, row := range snapshot.Accounts {
		id := legacyPlatformID("upstream_account", row.ID)
		accountIDs[row.ID] = id
		if err = s.importLegacyAccount(ctx, tx, connectionID, row, id, report.RunID); err != nil {
			return fail(fmt.Errorf("import account %d: %w", row.ID, err))
		}
		if err = s.importLegacyRoutePool(ctx, tx, row.ID, id, report.RunID); err != nil {
			return fail(fmt.Errorf("import route pool for account %d: %w", row.ID, err))
		}
		markImported(report, "accounts")
	}
	modelIDs := make(map[string]string)
	for _, row := range snapshot.Models {
		if _, exists := accountIDs[row.AccountID]; !exists {
			continue
		}
		id, importErr := s.importLegacyModel(ctx, tx, row, report.RunID)
		if importErr != nil {
			return fail(fmt.Errorf("import model %q: %w", row.ModelID, importErr))
		}
		modelIDs[row.ModelID] = id
		if err = s.importLegacyModelRoutes(ctx, tx, row, id, accountIDs[row.AccountID]); err != nil {
			return fail(fmt.Errorf("import model routes for %q: %w", row.ModelID, err))
		}
		markImported(report, "account_models")
	}
	keyIDs := make(map[int64]string)
	for _, row := range snapshot.Keys {
		accountID, ok := accountIDs[row.AccountID]
		if !ok {
			return fail(fmt.Errorf("legacy API key %d references missing account %d", row.ID, row.AccountID))
		}
		userID := userByKey[row.ID]
		if userID == "" {
			userID = legacyPlatformID("key_owner", row.ID)
			if err = s.importKeyOwner(ctx, tx, userID, row.Role, report.RunID); err != nil {
				return fail(fmt.Errorf("import key owner %d: %w", row.ID, err))
			}
		}
		id := legacyPlatformID("api_key", row.ID)
		keyIDs[row.ID] = id
		if err = s.importLegacyKey(ctx, tx, row, id, userID, legacyPlatformID("route_pool", row.AccountID), snapshot.KeyIPs[row.ID], snapshot.KeyDevices[row.ID], report.RunID); err != nil {
			return fail(fmt.Errorf("import API key %d: %w", row.ID, err))
		}
		markImported(report, "api_keys")
		_ = accountID
	}
	for _, row := range snapshot.Invitations {
		if err = s.importLegacyInvitation(ctx, tx, row, keyIDs[row.APIKeyID], report.RunID); err != nil {
			return fail(fmt.Errorf("import invitation %d: %w", row.ID, err))
		}
		markImported(report, "invitations")
	}
	userIDs := make(map[int64]string)
	for _, row := range snapshot.Users {
		userIDs[row.ID] = legacyPlatformID("user", row.ID)
	}
	for _, row := range snapshot.Devices {
		if userIDs[row.UserID] == "" {
			continue
		}
		if err = s.importLegacyDevice(ctx, tx, row, userIDs[row.UserID], report.RunID); err != nil {
			return fail(fmt.Errorf("import device %d: %w", row.ID, err))
		}
		markImported(report, "devices")
	}
	for _, row := range snapshot.Usage {
		if err = s.importLegacyUsage(ctx, tx, row, keyIDs[row.KeyID], accountIDs[row.AccountID], modelIDs[row.Model], report.RunID); err != nil {
			return fail(fmt.Errorf("import usage %d: %w", row.ID, err))
		}
		markImported(report, "usage")
	}
	for _, row := range snapshot.Audits {
		if err = s.importLegacyAudit(ctx, tx, row); err != nil {
			return fail(fmt.Errorf("import audit %d: %w", row.ID, err))
		}
		markImported(report, "audit")
	}
	for _, row := range snapshot.Bans {
		if err = s.importLegacyBan(ctx, tx, row); err != nil {
			return fail(fmt.Errorf("import IP ban: %w", err))
		}
		markImported(report, "ip_bans")
	}
	if err = s.verifyLegacyImport(ctx, tx, report); err != nil {
		return fail(err)
	}
	report.Verified = true
	report.CompletedAt = time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE legacy_import_runs SET status='completed',completed_at=$2,report=$3 WHERE id=$1`, report.RunID, report.CompletedAt, mustJSON(report)); err != nil {
		return fail(err)
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	return nil
}

func (s *PlatformStore) importLegacyAdmin(ctx context.Context, tx *sql.Tx, row legacyAdmin, runID string) error {
	if strings.TrimSpace(row.Username) == "" || strings.TrimSpace(row.PasswordHash) == "" {
		return nil
	}
	id := legacyPlatformID("administrator", row.Username)
	totp := ""
	var err error
	if row.TOTPEncrypted != "" {
		plain, decryptErr := s.vault.Decrypt(row.TOTPEncrypted, "admin-totp")
		if decryptErr != nil {
			return fmt.Errorf("decrypt legacy administrator TOTP: %w", decryptErr)
		}
		totp, err = s.encryptPlatformSecret(plain, "platform-admin-totp")
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,email,display_name,status,password_hash) VALUES($1,$2,$3,$4,'active',$5) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,password_hash=excluded.password_hash,updated_at=now()`, id, DefaultPlatformTenantID(), "administrator@local.invalid", row.Username, row.PasswordHash); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO administrators(user_id,username,password_hash,totp_secret_enc,role,status) VALUES($1,$2,$3,$4,'owner','active') ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,password_hash=excluded.password_hash,totp_secret_enc=excluded.totp_secret_enc,updated_at=now()`, id, row.Username, row.PasswordHash, totp); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "administrator", row.Username, id, runID)
}

func (s *PlatformStore) importLegacyUser(ctx context.Context, tx *sql.Tx, row legacyUser, id, runID string) error {
	status := row.Status
	if status != "active" && status != "suspended" {
		status = "suspended"
	}
	email := strings.ToLower(strings.TrimSpace(row.Email))
	if email == "" {
		email = "legacy-user-" + strconv.FormatInt(row.ID, 10) + "@local.invalid"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,email,display_name,status,password_hash,last_login_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET email=excluded.email,display_name=excluded.display_name,status=excluded.status,password_hash=excluded.password_hash,last_login_at=excluded.last_login_at,updated_at=excluded.updated_at`, id, DefaultPlatformTenantID(), email, row.DisplayName, status, row.PasswordHash, legacyTime(row.LastLoginAt), legacyTime(row.CreatedAt), legacyTime(row.UpdatedAt)); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "user", row.ID, id, runID)
}

func (s *PlatformStore) importKeyOwner(ctx context.Context, tx *sql.Tx, id, label, runID string) error {
	email := "legacy-key-" + strings.ReplaceAll(id, "-", "") + "@local.invalid"
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,email,display_name,status,password_hash) VALUES($1,$2,$3,$4,'active','') ON CONFLICT(id) DO NOTHING`, id, DefaultPlatformTenantID(), email, "Imported key: "+truncate(label, 80)); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "key_owner", id, id, runID)
}

func (s *PlatformStore) importLegacyProvider(ctx context.Context, tx *sql.Tx, id string) error {
	settings := json.RawMessage(`{"connector":"chatgpt","imported":true,"state":"requires_post_migration_health_check"}`)
	_, err := tx.ExecContext(ctx, `INSERT INTO provider_connections(id,tenant_id,provider_kind,provider_name,base_url,settings,status) VALUES($1,$2,'oauth','chatgpt','',$3,'draft') ON CONFLICT(id) DO UPDATE SET settings=excluded.settings,updated_at=now()`, id, DefaultPlatformTenantID(), string(settings))
	return err
}

func (s *PlatformStore) importLegacyAccount(ctx context.Context, tx *sql.Tx, connectionID string, row legacyAccount, id, runID string) error {
	credential := map[string]any{"access_token": row.AccessToken, "refresh_token": row.RefreshToken, "client_id": row.ClientID, "account_id": row.AccountRef, "expires_at": row.ExpiresAt}
	plain, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	encrypted, err := s.encryptPlatformSecret(string(plain), "platform-upstream-account-credential")
	if err != nil {
		return err
	}
	status := "active"
	if !row.Active {
		status = "disabled"
	} else if row.CooldownUntil > time.Now().Unix() {
		status = "cooldown"
	}
	quota, _ := json.Marshal(map[string]any{"plan_type": row.PlanType, "five_hour_used": row.Quota5HUsed, "five_hour_reset_at": row.Quota5HResetAt, "seven_day_used": row.Quota7DUsed, "seven_day_reset_at": row.Quota7DResetAt, "updated_at": row.QuotaUpdatedAt, "error": row.QuotaError, "reset_credits": row.ResetCredits, "reset_credit_times": json.RawMessage(defaultJSONObject(row.ResetCreditTimes, `[]`))})
	refHash := tokenHash(row.AccountRef)
	if _, err = tx.ExecContext(ctx, `INSERT INTO upstream_accounts(id,connection_id,external_account_ref_hash,label,credential_enc,model_catalog,quota_state,status,cooldown_until,last_used_at,last_error,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'[]'::jsonb,$6::jsonb,$7,$8,$9,$10,$11,$12) ON CONFLICT(id) DO UPDATE SET label=excluded.label,credential_enc=excluded.credential_enc,quota_state=excluded.quota_state,status=excluded.status,cooldown_until=excluded.cooldown_until,last_used_at=excluded.last_used_at,last_error=excluded.last_error,updated_at=excluded.updated_at`, id, connectionID, refHash, row.Name, encrypted, string(quota), status, nullableLegacyTime(row.CooldownUntil), nullableLegacyTime(row.LastUsedAt), truncate(row.LastError, 500), legacyTime(row.CreatedAt), legacyTime(row.UpdatedAt)); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "upstream_account", row.ID, id, runID)
}

func (s *PlatformStore) importLegacyRoutePool(ctx context.Context, tx *sql.Tx, accountID int64, accountUUID, runID string) error {
	id := legacyPlatformID("route_pool", accountID)
	name := "Imported account " + strconv.FormatInt(accountID, 10)
	if _, err := tx.ExecContext(ctx, `INSERT INTO route_pools(id,tenant_id,name,status,selection_policy) VALUES($1,$2,$3,'active','fixed') ON CONFLICT(id) DO NOTHING`, id, DefaultPlatformTenantID(), name); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO route_pool_members(id,route_pool_id,upstream_account_id,priority,weight,enabled) VALUES($1,$2,$3,0,100,true) ON CONFLICT(route_pool_id,upstream_account_id) DO UPDATE SET enabled=true,updated_at=now()`, legacyPlatformID("route_pool_member", accountID), id, accountUUID); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "route_pool", accountID, id, runID)
}

func (s *PlatformStore) importLegacyModel(ctx context.Context, tx *sql.Tx, row legacyAccountModel, runID string) (string, error) {
	id := legacyPlatformID("platform_model", row.ModelID)
	key := legacyModelKey(row.ModelID)
	display := strings.TrimSpace(row.ModelID)
	if display == "" {
		display = key
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_models(id,model_key,display_name,description,category,capabilities,billing,status) VALUES($1,$2,$3,'Imported model','chat','{}'::jsonb,'{}'::jsonb,'active') ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,updated_at=now()`, id, key, display); err != nil {
		return "", err
	}
	for _, scope := range []ProductScope{ProductScopeChat, ProductScopeAgent, ProductScopeExternalAPI} {
		for _, protocol := range []string{"responses", "chat_completions"} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO product_model_publications(id,model_id,product_scope,protocol,enabled,default_for_scope,plan_rules) VALUES($1,$2,$3,$4,true,false,'{}'::jsonb) ON CONFLICT(model_id,product_scope,protocol) DO NOTHING`, newPlatformID(), id, scope, protocol); err != nil {
				return "", err
			}
		}
	}
	if err := recordLegacyMap(ctx, tx, "platform_model", row.ModelID, id, runID); err != nil {
		return "", err
	}
	return id, nil
}

func (s *PlatformStore) importLegacyModelRoutes(ctx context.Context, tx *sql.Tx, row legacyAccountModel, modelID, accountID string) error {
	poolID := legacyPlatformID("route_pool", row.AccountID)
	for _, scope := range []ProductScope{ProductScopeChat, ProductScopeAgent, ProductScopeExternalAPI} {
		for _, protocol := range []string{"responses", "chat_completions"} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO model_route_targets(id,model_id,product_scope,protocol,route_pool_id,upstream_model_id,priority,enabled) VALUES($1,$2,$3,$4,$5,$6,100,true) ON CONFLICT(model_id,product_scope,protocol,route_pool_id,upstream_model_id) DO UPDATE SET enabled=true,updated_at=now()`, newPlatformID(), modelID, scope, protocol, poolID, row.ModelID); err != nil {
				return err
			}
		}
	}
	_ = accountID
	return nil
}

func (s *PlatformStore) importLegacyKey(ctx context.Context, tx *sql.Tx, row legacyKey, id, userID, poolID string, ips []legacyKeyIP, devices []legacyKeyDevice, runID string) error {
	status := row.Status
	if status != "active" && status != "disabled" && status != "deleted" {
		status = "disabled"
	}
	encrypted := ""
	var err error
	if row.PlainKey != "" {
		encrypted, err = s.encryptPlatformSecret(row.PlainKey, "platform-api-key")
		if err != nil {
			return err
		}
	}
	ipPolicy, _ := json.Marshal(map[string]any{"mode": policyMode(len(ips) > 0), "addresses": ips})
	devicePolicy, _ := json.Marshal(map[string]any{"mode": policyMode(len(devices) > 0), "credentials": devices})
	if _, err = tx.ExecContext(ctx, `INSERT INTO api_keys_v2(id,user_id,route_pool_id,label,key_hash,key_enc,status,ip_policy,device_policy,metadata,last_used_at,disabled_at,deleted_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,CASE WHEN $7='disabled' THEN now() ELSE NULL END,CASE WHEN $7='deleted' THEN now() ELSE NULL END,$12,$13) ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id,route_pool_id=excluded.route_pool_id,label=excluded.label,key_hash=excluded.key_hash,key_enc=excluded.key_enc,status=excluded.status,ip_policy=excluded.ip_policy,device_policy=excluded.device_policy,metadata=excluded.metadata,last_used_at=excluded.last_used_at,disabled_at=excluded.disabled_at,deleted_at=excluded.deleted_at,updated_at=excluded.updated_at`, id, userID, poolID, truncate(row.Role, 160), row.KeyHash, encrypted, status, string(ipPolicy), string(devicePolicy), mustJSON(map[string]any{"legacy_key_id": row.ID, "quota_requests": row.QuotaRequests, "used_requests": row.UsedRequests, "masked_key": row.MaskedKey}), nullableLegacyTime(row.LastUsedAt), legacyTime(row.CreatedAt), legacyTime(row.UpdatedAt)); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "api_key", row.ID, id, runID)
}

func (s *PlatformStore) importLegacyInvitation(ctx context.Context, tx *sql.Tx, row legacyInvitation, keyID, runID string) error {
	id := legacyPlatformID("invitation", row.ID)
	status := row.Status
	switch status {
	case "pending", "claimed", "revoked", "expired":
	default:
		status = "expired"
	}
	if status == "claimed" && keyID == "" {
		status = "expired"
	}
	policy, _ := json.Marshal(map[string]any{"binding_mode": row.BindingMode, "legacy_account_id": row.AccountID, "legacy_key_id": row.APIKeyID, "quota_requests": row.QuotaRequests, "verified_ip": row.VerifiedIP, "device_note": row.DeviceNote, "imported_api_key_id": keyID})
	if _, err := tx.ExecContext(ctx, `INSERT INTO invitations_v2(id,tenant_id,role_label,token_hash,code_hash,status,policy,expires_at,claimed_at,revoked_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,CASE WHEN $6='claimed' THEN $9::timestamptz ELSE NULL END,CASE WHEN $6='revoked' THEN $9::timestamptz ELSE NULL END,$10) ON CONFLICT(id) DO UPDATE SET role_label=excluded.role_label,status=excluded.status,policy=excluded.policy,expires_at=excluded.expires_at,claimed_at=excluded.claimed_at,revoked_at=excluded.revoked_at`, id, DefaultPlatformTenantID(), truncate(row.Role, 160), row.TokenHash, row.CodeHash, status, string(policy), legacyTime(row.ExpiresAt), legacyTime(row.GeneratedAt), legacyTime(row.CreatedAt)); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "invitation", row.ID, id, runID)
}

func (s *PlatformStore) importLegacyDevice(ctx context.Context, tx *sql.Tx, row legacyDevice, userID, runID string) error {
	public, err := base64.RawURLEncoding.DecodeString(row.PublicKey)
	if err != nil {
		public = []byte(row.PublicKey)
	}
	if len(public) == 0 {
		return fmt.Errorf("legacy device %d has no public key", row.ID)
	}
	macEnc := ""
	if row.MACEncrypted != "" {
		plain, decryptErr := s.vault.Decrypt(row.MACEncrypted, "desktop-device-mac")
		if decryptErr != nil {
			return fmt.Errorf("decrypt legacy device %d MAC: %w", row.ID, decryptErr)
		}
		macEnc, err = s.encryptPlatformSecret(plain, "platform-device-mac")
		if err != nil {
			return err
		}
	}
	status := row.Status
	if status != "active" && status != "reverify_required" && status != "revoked" {
		status = "reverify_required"
	}
	id := legacyPlatformID("device", row.ID)
	var revokedAt any
	if status == "revoked" {
		revokedAt = legacyTime(row.UpdatedAt)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_devices(id,user_id,public_key,public_key_fingerprint,mac_hash,mac_enc,device_name,platform,status,registered_ip,last_ip,last_seen_at,verified_at,revoked_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id,mac_hash=excluded.mac_hash,mac_enc=excluded.mac_enc,device_name=excluded.device_name,platform=excluded.platform,status=excluded.status,last_ip=excluded.last_ip,last_seen_at=excluded.last_seen_at,revoked_at=excluded.revoked_at,updated_at=excluded.updated_at`, id, userID, public, tokenHash(row.PublicKey), row.MACHash, macEnc, truncate(row.Name, 120), truncate(row.Platform, 80), status, row.RegisteredIP, row.LastIP, nullableLegacyTime(row.LastSeenAt), legacyTime(row.CreatedAt), revokedAt, legacyTime(row.CreatedAt), legacyTime(row.UpdatedAt)); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "device", row.ID, id, runID)
}

func (s *PlatformStore) importLegacyUsage(ctx context.Context, tx *sql.Tx, row legacyUsage, keyID, accountID, modelID, runID string) error {
	id := legacyPlatformID("usage", row.ID)
	requestID := strings.TrimSpace(row.RequestID)
	if requestID == "" {
		requestID = "legacy-usage-" + strconv.FormatInt(row.ID, 10)
	} else {
		requestID = "legacy-" + strconv.FormatInt(row.ID, 10) + "-" + requestID
	}
	protocol := "responses"
	if strings.Contains(row.Path, "chat/completions") {
		protocol = "chat_completions"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO usage_records(id,tenant_id,api_key_id,model_id,upstream_account_id,product_scope,protocol,request_id,status_code,input_tokens,output_tokens,billed_tokens,estimated,error_code,duration_ms,created_at) VALUES($1,$2,NULLIF($3,'')::uuid,NULLIF($4,'')::uuid,NULLIF($5,'')::uuid,'external_api',$6,$7,$8,$9,$10,$11,true,$12,$13,$14) ON CONFLICT(id) DO NOTHING`, id, DefaultPlatformTenantID(), keyID, modelID, accountID, protocol, truncate(requestID, 240), row.Status, row.InputTokens, row.OutputTokens, row.TotalTokens, truncate(row.Error, 160), row.DurationMS, legacyTime(row.CreatedAt)); err != nil {
		return err
	}
	return recordLegacyMap(ctx, tx, "usage", row.ID, id, runID)
}

func (s *PlatformStore) importLegacyAudit(ctx context.Context, tx *sql.Tx, row legacyAudit) error {
	id := legacyPlatformID("audit", row.ID)
	metadata := mustJSON(map[string]any{"detail": truncate(row.Detail, 500), "legacy_actor": truncate(row.Actor, 120)})
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(id,tenant_id,actor_kind,action,target_kind,target_id,ip,metadata,created_at) VALUES($1,$2,'legacy',$3,'legacy',$4,$5,$6::jsonb,$7) ON CONFLICT(id) DO NOTHING`, id, DefaultPlatformTenantID(), truncate(row.Action, 160), truncate(row.Target, 240), row.IP, metadata, legacyTime(row.CreatedAt))
	return err
}
func (s *PlatformStore) importLegacyBan(ctx context.Context, tx *sql.Tx, row legacyBan) error {
	id := legacyPlatformID("ip_ban", row.IP)
	scope := "all"
	if row.Scope == "guide" {
		scope = "guide"
	}
	permanent := row.ExpiresAt <= 0
	var expires any
	if !permanent {
		expires = legacyTime(row.ExpiresAt)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO ip_bans_v2(id,tenant_id,ip_or_prefix,scope,reason,permanent,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET reason=excluded.reason,scope=excluded.scope,permanent=excluded.permanent,expires_at=excluded.expires_at`, id, DefaultPlatformTenantID(), row.IP, scope, truncate(row.Reason, 500), permanent, expires, legacyTime(row.CreatedAt))
	return err
}

func (s *PlatformStore) verifyLegacyImport(ctx context.Context, tx *sql.Tx, report *LegacyImportReport) error {
	for kind, table := range map[string]string{"users": "user", "accounts": "upstream_account", "api_keys": "api_key", "invitations": "invitation", "devices": "device", "usage": "usage"} {
		expected := report.Tables[kind].Source
		var actual int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM legacy_identity_map WHERE source_kind=$1`, table).Scan(&actual); err != nil {
			return err
		}
		item := report.Tables[kind]
		item.Destination = actual
		report.Tables[kind] = item
		if actual < expected {
			return fmt.Errorf("legacy import verification failed for %s: expected at least %d mapped rows, got %d", kind, expected, actual)
		}
	}
	return nil
}

func recordLegacyMap(ctx context.Context, tx *sql.Tx, kind string, source any, targetID, runID string) error {
	if strings.TrimSpace(runID) == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO legacy_identity_map(source_kind,source_id,target_id,import_run_id) VALUES($1,$2,$3,$4) ON CONFLICT(source_kind,source_id) DO NOTHING`, kind, fmt.Sprint(source), targetID, runID)
	return err
}
func markImported(report *LegacyImportReport, table string) {
	item := report.Tables[table]
	item.Imported++
	report.Tables[table] = item
}
func legacyPlatformID(kind string, source any) string {
	sum := sha256.Sum256([]byte("infinite-ai-transition:" + kind + ":" + fmt.Sprint(source)))
	raw := sum[:16]
	raw[6] = (raw[6] & 0x0f) | 0x50
	raw[8] = (raw[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(raw)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:]
}
func legacyModelKey(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if modelKeyPattern.MatchString(raw) {
		return raw
	}
	sum := sha256.Sum256([]byte(raw))
	return "imported-" + hex.EncodeToString(sum[:12])
}
func legacyTime(value int64) time.Time {
	if value <= 0 {
		return time.Unix(0, 0).UTC()
	}
	return time.Unix(value, 0).UTC()
}
func nullableLegacyTime(value int64) any {
	if value <= 0 {
		return nil
	}
	return legacyTime(value)
}
func policyMode(bound bool) string {
	if bound {
		return "allow_list"
	}
	return "unrestricted"
}
func defaultJSONObject(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	var target any
	if json.Unmarshal([]byte(value), &target) != nil {
		return fallback
	}
	return value
}
func mustJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
