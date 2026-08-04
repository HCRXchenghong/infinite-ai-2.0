package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type desktopAuthFlow struct {
	DeviceCodeHash string
	PublicKey      string
	DeviceName     string
	Platform       string
	MACHash        string
	MACEncrypted   string
	RequestIP      string
	BrowserIP      string
	UserID         int64
	Status         string
	ExpiresAt      int64
}

type desktopSessionAuth struct {
	SessionID      int64
	UserID         int64
	DeviceID       int64
	PublicKey      string
	MACHash        string
	UserEmail      string
	DisplayName    string
	DeviceName     string
	APIKeyID       int64
	AccessExpires  int64
	RefreshExpires int64
	RevokedAt      int64
}

func normalizeDesktopEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeDesktopMAC(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer("-", ":", ".", "", " ", "").Replace(value)
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return ""
	}
	for _, part := range parts {
		if len(part) != 2 || strings.IndexFunc(part, func(r rune) bool {
			return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'))
		}) >= 0 {
			return ""
		}
	}
	return strings.Join(parts, ":")
}

func (s *Store) DesktopPolicy(ctx context.Context, publicBaseURL string) DesktopPolicy {
	policy := DesktopPolicy{
		RegistrationEnabled: true,
		ExternalAPIMode:     "authenticated_public",
		PublicAPIEnabled:    true,
		OfficialDesktopOnly: false,
		GatewayBaseURL:      strings.TrimRight(publicBaseURL, "/"),
		ProviderName:        "Infinite AI FriendGate",
		DefaultModel:        "gpt-5.6",
	}
	values := make(map[string]string)
	for _, key := range []string{
		"desktop_registration_enabled", "external_api_mode", "public_api_enabled", "official_desktop_only",
		"desktop_provider_name", "desktop_default_model", "desktop_allowed_models", "desktop_system_prompt",
	} {
		values[key] = s.Setting(ctx, key)
	}
	if values["desktop_registration_enabled"] == "false" {
		policy.RegistrationEnabled = false
	}
	policy.ExternalAPIMode = normalizeExternalAPIMode(values["external_api_mode"], values["public_api_enabled"], values["official_desktop_only"])
	policy.PublicAPIEnabled = policy.ExternalAPIMode == "authenticated_public"
	policy.OfficialDesktopOnly = policy.ExternalAPIMode == "official_client_only"
	if value := strings.TrimSpace(values["desktop_provider_name"]); value != "" {
		policy.ProviderName = value
	}
	if value := strings.TrimSpace(values["desktop_default_model"]); value != "" {
		policy.DefaultModel = value
	}
	_ = json.Unmarshal([]byte(values["desktop_allowed_models"]), &policy.AllowedModels)
	policy.SystemPrompt = values["desktop_system_prompt"]
	return policy
}

func (s *Store) SaveDesktopPolicy(ctx context.Context, policy DesktopPolicy) error {
	// Old clients only submit the two booleans. If they conflict with the
	// default mode, honor the explicit legacy values for this one transition.
	mode := policy.ExternalAPIMode
	if mode == "authenticated_public" && (!policy.PublicAPIEnabled || policy.OfficialDesktopOnly) {
		mode = ""
	}
	policy.ExternalAPIMode = normalizeExternalAPIMode(mode, fmt.Sprint(policy.PublicAPIEnabled), fmt.Sprint(policy.OfficialDesktopOnly))
	policy.PublicAPIEnabled = policy.ExternalAPIMode == "authenticated_public"
	policy.OfficialDesktopOnly = policy.ExternalAPIMode == "official_client_only"
	models, err := json.Marshal(policy.AllowedModels)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	values := map[string]string{
		"desktop_registration_enabled": fmt.Sprint(policy.RegistrationEnabled),
		"external_api_mode":            policy.ExternalAPIMode,
		"public_api_enabled":           fmt.Sprint(policy.PublicAPIEnabled),
		"official_desktop_only":        fmt.Sprint(policy.OfficialDesktopOnly),
		"desktop_provider_name":        strings.TrimSpace(policy.ProviderName),
		"desktop_default_model":        strings.TrimSpace(policy.DefaultModel),
		"desktop_allowed_models":       string(models),
		"desktop_system_prompt":        policy.SystemPrompt,
	}
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func normalizeExternalAPIMode(mode, legacyPublic, legacyOfficial string) string {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "authenticated_public", "official_client_only", "disabled":
		return strings.TrimSpace(strings.ToLower(mode))
	}
	if strings.TrimSpace(strings.ToLower(legacyPublic)) == "false" {
		return "disabled"
	}
	if strings.TrimSpace(strings.ToLower(legacyOfficial)) == "true" {
		return "official_client_only"
	}
	return "authenticated_public"
}

func (s *Store) CreateDesktopUser(ctx context.Context, email, displayName, password string) (*DesktopUser, error) {
	email = normalizeDesktopEmail(email)
	displayName = strings.TrimSpace(displayName)
	hash, err := passwordHash(password, 600_000)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `INSERT INTO desktop_users(email,display_name,password_hash,status,created_at,updated_at)
VALUES(?,?,?,'active',?,?)`, email, displayName, hash, now, now)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &DesktopUser{ID: id, Email: email, DisplayName: displayName, Status: "active", CreatedAt: now}, nil
}

func (s *Store) AuthenticateDesktopUser(ctx context.Context, email, password string) (*DesktopUser, error) {
	var item DesktopUser
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT id,email,display_name,password_hash,status,COALESCE(api_key_id,0),last_login_at,created_at
FROM desktop_users WHERE email=?`, normalizeDesktopEmail(email)).Scan(&item.ID, &item.Email, &item.DisplayName, &hash, &item.Status, &item.APIKeyID, &item.LastLoginAt, &item.CreatedAt)
	if err != nil || !passwordVerify(hash, password) {
		return nil, ErrInvalidAdminCredentials
	}
	if item.Status != "active" {
		return nil, ErrUserInactive
	}
	item.LastLoginAt = time.Now().Unix()
	_, err = s.db.ExecContext(ctx, "UPDATE desktop_users SET last_login_at=?,updated_at=? WHERE id=? AND status='active'", item.LastLoginAt, item.LastLoginAt, item.ID)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Store) NewUserSession(ctx context.Context, userID int64, ip string, ttl time.Duration) (string, string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	_, err = s.db.ExecContext(ctx, `INSERT INTO user_sessions(token_hash,user_id,csrf_token,ip,expires_at,created_at) VALUES(?,?,?,?,?,?)`,
		tokenHash(token), userID, csrf, ip, now.Add(ttl).Unix(), now.Unix())
	return token, csrf, err
}

func (s *Store) UserSession(ctx context.Context, token, ip string) (*DesktopUser, string, error) {
	if strings.TrimSpace(token) == "" {
		return nil, "", ErrDesktopSessionInvalid
	}
	var item DesktopUser
	var csrf string
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.email,u.display_name,u.status,COALESCE(u.api_key_id,0),u.last_login_at,u.created_at,s.csrf_token
FROM user_sessions s JOIN desktop_users u ON u.id=s.user_id
WHERE s.token_hash=? AND s.ip=? AND s.expires_at>? AND u.status='active'`, tokenHash(token), ip, time.Now().Unix()).
		Scan(&item.ID, &item.Email, &item.DisplayName, &item.Status, &item.APIKeyID, &item.LastLoginAt, &item.CreatedAt, &csrf)
	if err != nil {
		return nil, "", ErrDesktopSessionInvalid
	}
	return &item, csrf, nil
}

func (s *Store) DeleteUserSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM user_sessions WHERE token_hash=?", tokenHash(token))
	return err
}

func (s *Store) CreateDesktopAuthFlow(ctx context.Context, deviceCode, userCode, publicKey, deviceName, platform, mac, requestIP string, ttl time.Duration) error {
	mac = normalizeDesktopMAC(mac)
	if mac == "" {
		return errors.New("desktop MAC address is required")
	}
	macEnc, err := s.vault.Encrypt(mac, "desktop-device-mac")
	if err != nil {
		return err
	}
	now := time.Now()
	_, err = s.db.ExecContext(ctx, `INSERT INTO desktop_auth_flows(
device_code_hash,user_code_hash,public_key,device_name,platform,mac_hash,mac_enc,request_ip,status,expires_at,created_at
) VALUES(?,?,?,?,?,?,?,?, 'pending',?,?)`, tokenHash(deviceCode), tokenHash(strings.ToUpper(userCode)), publicKey, deviceName, platform, tokenHash(mac), macEnc, requestIP, now.Add(ttl).Unix(), now.Unix())
	return err
}

func (s *Store) DesktopAuthFlowByDeviceCode(ctx context.Context, deviceCode string) (*desktopAuthFlow, error) {
	var item desktopAuthFlow
	err := s.db.QueryRowContext(ctx, `SELECT device_code_hash,public_key,device_name,platform,mac_hash,mac_enc,request_ip,browser_ip,COALESCE(user_id,0),status,expires_at
FROM desktop_auth_flows WHERE device_code_hash=?`, tokenHash(deviceCode)).
		Scan(&item.DeviceCodeHash, &item.PublicKey, &item.DeviceName, &item.Platform, &item.MACHash, &item.MACEncrypted, &item.RequestIP, &item.BrowserIP, &item.UserID, &item.Status, &item.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDesktopFlowExpired
	}
	if err != nil {
		return nil, err
	}
	if item.ExpiresAt <= time.Now().Unix() {
		_, _ = s.db.ExecContext(ctx, "UPDATE desktop_auth_flows SET status='expired' WHERE device_code_hash=? AND status='pending'", item.DeviceCodeHash)
		return nil, ErrDesktopFlowExpired
	}
	return &item, nil
}

func (s *Store) DesktopAuthFlowForPortal(ctx context.Context, userCode string) (*desktopAuthFlow, error) {
	var item desktopAuthFlow
	err := s.db.QueryRowContext(ctx, `SELECT device_code_hash,public_key,device_name,platform,mac_hash,mac_enc,request_ip,browser_ip,COALESCE(user_id,0),status,expires_at
FROM desktop_auth_flows WHERE user_code_hash=?`, tokenHash(strings.ToUpper(strings.TrimSpace(userCode)))).
		Scan(&item.DeviceCodeHash, &item.PublicKey, &item.DeviceName, &item.Platform, &item.MACHash, &item.MACEncrypted, &item.RequestIP, &item.BrowserIP, &item.UserID, &item.Status, &item.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) || item.ExpiresAt <= time.Now().Unix() {
		return nil, ErrDesktopFlowExpired
	}
	return &item, err
}

func (s *Store) ApproveDesktopAuthFlow(ctx context.Context, userCode string, userID int64, browserIP string) error {
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `UPDATE desktop_auth_flows SET status='approved',user_id=?,browser_ip=?,approved_at=?
WHERE user_code_hash=? AND status='pending' AND expires_at>?`, userID, browserIP, now, tokenHash(strings.ToUpper(strings.TrimSpace(userCode))), now)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrDesktopFlowExpired
	}
	return nil
}

func (s *Store) ConsumeApprovedDesktopFlow(ctx context.Context, deviceCode string, accessTTL, refreshTTL time.Duration) (access, refresh string, auth *desktopSessionAuth, err error) {
	access, err = randomToken(32)
	if err != nil {
		return "", "", nil, err
	}
	refresh, err = randomToken(48)
	if err != nil {
		return "", "", nil, err
	}
	access = "fgds_" + access
	refresh = "fgdr_" + refresh
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", nil, err
	}
	defer tx.Rollback()
	var flow desktopAuthFlow
	err = tx.QueryRowContext(ctx, `SELECT device_code_hash,public_key,device_name,platform,mac_hash,mac_enc,request_ip,browser_ip,COALESCE(user_id,0),status,expires_at
FROM desktop_auth_flows WHERE device_code_hash=?`, tokenHash(deviceCode)).
		Scan(&flow.DeviceCodeHash, &flow.PublicKey, &flow.DeviceName, &flow.Platform, &flow.MACHash, &flow.MACEncrypted, &flow.RequestIP, &flow.BrowserIP, &flow.UserID, &flow.Status, &flow.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) || flow.ExpiresAt <= now {
		return "", "", nil, ErrDesktopFlowExpired
	}
	if err != nil {
		return "", "", nil, err
	}
	if flow.Status == "pending" {
		return "", "", nil, ErrDesktopFlowPending
	}
	if flow.Status != "approved" || flow.UserID == 0 {
		return "", "", nil, ErrDesktopFlowExpired
	}
	var userStatus string
	if err := tx.QueryRowContext(ctx, "SELECT status FROM desktop_users WHERE id=?", flow.UserID).Scan(&userStatus); err != nil || userStatus != "active" {
		return "", "", nil, ErrUserInactive
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO desktop_devices(user_id,public_key,name,platform,mac_hash,mac_enc,registered_ip,last_ip,status,last_seen_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?, 'active',?,?,?)
ON CONFLICT(public_key) DO UPDATE SET user_id=excluded.user_id,name=excluded.name,platform=excluded.platform,mac_hash=excluded.mac_hash,mac_enc=excluded.mac_enc,last_ip=excluded.last_ip,status='active',last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`,
		flow.UserID, flow.PublicKey, flow.DeviceName, flow.Platform, flow.MACHash, flow.MACEncrypted, flow.BrowserIP, flow.RequestIP, now, now, now)
	if err != nil {
		return "", "", nil, err
	}
	var deviceID int64
	if err = tx.QueryRowContext(ctx, "SELECT id FROM desktop_devices WHERE public_key=?", flow.PublicKey).Scan(&deviceID); err != nil {
		return "", "", nil, err
	}
	accessExpires := now + int64(accessTTL.Seconds())
	refreshExpires := now + int64(refreshTTL.Seconds())
	sessionResult, err := tx.ExecContext(ctx, `INSERT INTO desktop_sessions(user_id,device_id,access_hash,refresh_hash,access_expires_at,refresh_expires_at,last_ip,last_seen_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?)`, flow.UserID, deviceID, tokenHash(access), tokenHash(refresh), accessExpires, refreshExpires, flow.RequestIP, now, now, now)
	if err != nil {
		return "", "", nil, err
	}
	sessionID, err := sessionResult.LastInsertId()
	if err != nil {
		return "", "", nil, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE desktop_auth_flows SET status='consumed' WHERE device_code_hash=? AND status='approved'", flow.DeviceCodeHash); err != nil {
		return "", "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", "", nil, err
	}
	return access, refresh, &desktopSessionAuth{SessionID: sessionID, UserID: flow.UserID, DeviceID: deviceID, PublicKey: flow.PublicKey, DeviceName: flow.DeviceName, AccessExpires: accessExpires, RefreshExpires: refreshExpires}, nil
}

func (s *Store) DesktopSessionByAccess(ctx context.Context, accessToken string) (*desktopSessionAuth, error) {
	return s.desktopSession(ctx, "s.access_hash", tokenHash(accessToken), true)
}

func (s *Store) DesktopSessionByRefresh(ctx context.Context, refreshToken string) (*desktopSessionAuth, error) {
	return s.desktopSession(ctx, "s.refresh_hash", tokenHash(refreshToken), false)
}

func (s *Store) desktopSession(ctx context.Context, column, hash string, access bool) (*desktopSessionAuth, error) {
	if column != "s.access_hash" && column != "s.refresh_hash" {
		return nil, ErrDesktopSessionInvalid
	}
	var item desktopSessionAuth
	query := `SELECT s.id,s.user_id,s.device_id,d.public_key,d.mac_hash,u.email,u.display_name,d.name,COALESCE(u.api_key_id,0),s.access_expires_at,s.refresh_expires_at,s.revoked_at
FROM desktop_sessions s JOIN desktop_users u ON u.id=s.user_id JOIN desktop_devices d ON d.id=s.device_id AND d.user_id=s.user_id
WHERE ` + column + `=? AND s.revoked_at=0 AND u.status='active' AND d.status='active'`
	err := s.db.QueryRowContext(ctx, query, hash).Scan(&item.SessionID, &item.UserID, &item.DeviceID, &item.PublicKey, &item.MACHash, &item.UserEmail, &item.DisplayName, &item.DeviceName, &item.APIKeyID, &item.AccessExpires, &item.RefreshExpires, &item.RevokedAt)
	if err != nil || (access && item.AccessExpires <= time.Now().Unix()) || (!access && item.RefreshExpires <= time.Now().Unix()) {
		return nil, ErrDesktopSessionInvalid
	}
	return &item, nil
}

// RequireDesktopMACReverification invalidates every session for a device
// whose locally signed MAC fingerprint no longer matches enrollment. MAC is
// an auxiliary signal; the Ed25519 public key remains the hard identity, so a
// change requires a fresh verification instead of a permanent ban.
func (s *Store) RequireDesktopMACReverification(ctx context.Context, deviceID int64) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE desktop_devices SET status='reverify_required',updated_at=? WHERE id=? AND status='active'", now, deviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE desktop_sessions SET revoked_at=?,updated_at=? WHERE device_id=? AND revoked_at=0", now, now, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConsumeDesktopNonce(ctx context.Context, sessionID int64, nonce string, expiresAt int64) error {
	_, _ = s.db.ExecContext(ctx, "DELETE FROM desktop_nonces WHERE expires_at<=?", time.Now().Unix())
	_, err := s.db.ExecContext(ctx, "INSERT INTO desktop_nonces(session_id,nonce_hash,expires_at) VALUES(?,?,?)", sessionID, tokenHash(nonce), expiresAt)
	if err != nil {
		return ErrReplayDetected
	}
	return nil
}

func (s *Store) RotateDesktopSession(ctx context.Context, sessionID int64, currentRefresh string, accessTTL, refreshTTL time.Duration) (string, string, int64, int64, error) {
	if !strings.HasPrefix(currentRefresh, "fgdr_") {
		return "", "", 0, 0, ErrDesktopSessionInvalid
	}
	accessRaw, err := randomToken(32)
	if err != nil {
		return "", "", 0, 0, err
	}
	refreshRaw, err := randomToken(48)
	if err != nil {
		return "", "", 0, 0, err
	}
	access, refresh := "fgds_"+accessRaw, "fgdr_"+refreshRaw
	now := time.Now().Unix()
	accessExpires, refreshExpires := now+int64(accessTTL.Seconds()), now+int64(refreshTTL.Seconds())
	result, err := s.db.ExecContext(ctx, `UPDATE desktop_sessions SET access_hash=?,refresh_hash=?,access_expires_at=?,refresh_expires_at=?,updated_at=?
	WHERE id=? AND refresh_hash=? AND revoked_at=0 AND refresh_expires_at>?`, tokenHash(access), tokenHash(refresh), accessExpires, refreshExpires, now, sessionID, tokenHash(currentRefresh), now)
	if err != nil {
		return "", "", 0, 0, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return "", "", 0, 0, ErrDesktopSessionInvalid
	}
	return access, refresh, accessExpires, refreshExpires, nil
}

func (s *Store) TouchDesktopSession(ctx context.Context, sessionID int64, ip string) {
	now := time.Now().Unix()
	_, _ = s.db.ExecContext(ctx, "UPDATE desktop_sessions SET last_ip=?,last_seen_at=?,updated_at=? WHERE id=? AND revoked_at=0", ip, now, now, sessionID)
	_, _ = s.db.ExecContext(ctx, `UPDATE desktop_devices SET last_ip=?,last_seen_at=?,updated_at=?
WHERE id=(SELECT device_id FROM desktop_sessions WHERE id=?) AND status='active'`, ip, now, now, sessionID)
}

func (s *Store) RevokeDesktopSession(ctx context.Context, sessionID int64) error {
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, "UPDATE desktop_sessions SET revoked_at=?,updated_at=? WHERE id=? AND revoked_at=0", now, now, sessionID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokeDesktopDevice(ctx context.Context, deviceID, ownerUserID int64) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := "UPDATE desktop_devices SET status='revoked',updated_at=? WHERE id=? AND status='active'"
	args := []any{now, deviceID}
	if ownerUserID > 0 {
		query += " AND user_id=?"
		args = append(args, ownerUserID)
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "UPDATE desktop_sessions SET revoked_at=?,updated_at=? WHERE device_id=? AND revoked_at=0", now, now, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListDesktopUsers(ctx context.Context) ([]DesktopUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id,u.email,u.display_name,u.status,COALESCE(u.api_key_id,0),COALESCE(k.role,''),u.last_login_at,u.created_at
FROM desktop_users u LEFT JOIN api_keys k ON k.id=u.api_key_id ORDER BY u.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DesktopUser
	for rows.Next() {
		var item DesktopUser
		if err := rows.Scan(&item.ID, &item.Email, &item.DisplayName, &item.Status, &item.APIKeyID, &item.KeyRole, &item.LastLoginAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) UpdateDesktopUser(ctx context.Context, userID, apiKeyID int64, status string) error {
	if status != "active" && status != "disabled" {
		return errors.New("invalid desktop user status")
	}
	var key any
	if apiKeyID > 0 {
		var keyStatus string
		if err := s.db.QueryRowContext(ctx, "SELECT status FROM api_keys WHERE id=?", apiKeyID).Scan(&keyStatus); err != nil || keyStatus == "deleted" {
			return ErrNotFound
		}
		key = apiKeyID
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE desktop_users SET api_key_id=?,status=?,updated_at=? WHERE id=?", key, status, now, userID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	if status != "active" {
		if _, err := tx.ExecContext(ctx, "DELETE FROM user_sessions WHERE user_id=?", userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE desktop_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at=0", now, now, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListDesktopDevices(ctx context.Context, userID int64) ([]DesktopDevice, error) {
	query := `SELECT d.id,d.user_id,u.email,d.name,d.platform,d.mac_enc,d.registered_ip,d.last_ip,d.status,d.last_seen_at,d.created_at
FROM desktop_devices d JOIN desktop_users u ON u.id=d.user_id`
	var args []any
	if userID > 0 {
		query += " WHERE d.user_id=?"
		args = append(args, userID)
	}
	query += " ORDER BY d.id DESC"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DesktopDevice
	for rows.Next() {
		var item DesktopDevice
		var encrypted string
		if err := rows.Scan(&item.ID, &item.UserID, &item.UserEmail, &item.Name, &item.Platform, &encrypted, &item.RegisteredIP, &item.LastIP, &item.Status, &item.LastSeenAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		if encrypted != "" {
			item.MAC, err = s.vault.Decrypt(encrypted, "desktop-device-mac")
			if err != nil {
				return nil, err
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) DesktopAPIKey(ctx context.Context, keyID int64) (*APIKey, error) {
	var item APIKey
	err := s.db.QueryRowContext(ctx, `SELECT id,role,masked_key,quota_requests,used_requests,status,last_used_at,created_at,account_id
FROM api_keys WHERE id=? AND status='active'`, keyID).Scan(&item.ID, &item.Role, &item.MaskedKey, &item.QuotaRequests, &item.UsedRequests, &item.Status, &item.LastUsedAt, &item.CreatedAt, &item.AccountID)
	if err != nil {
		return nil, ErrUserNotProvisioned
	}
	return &item, nil
}

func (s *Store) DesktopModelsForKey(ctx context.Context, keyID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT model.model_id
FROM api_keys key JOIN account_models model ON model.account_id=key.account_id
WHERE key.id=? AND key.status='active' ORDER BY model.model_id`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var model string
		if err := rows.Scan(&model); err != nil {
			return nil, err
		}
		result = append(result, model)
	}
	return result, rows.Err()
}
