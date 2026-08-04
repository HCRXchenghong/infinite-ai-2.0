package app

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var (
	ErrPlatformDeviceFlowPending = errors.New("platform device approval is pending")
	ErrPlatformDeviceFlowExpired = errors.New("platform device approval is expired")
	ErrPlatformDeviceSession     = errors.New("platform device session is invalid")
	ErrPlatformDeviceMACChanged  = errors.New("platform device MAC binding changed")
	ErrPlatformAgentSubKey       = errors.New("platform agent sub key is invalid")
)

type PlatformDeviceFlowInput struct {
	DeviceCode string
	UserCode   string
	PublicKey  []byte
	DeviceName string
	Platform   string
	MAC        string
	RequestIP  string
	TTL        time.Duration
}

type PlatformDeviceAuthFlow struct {
	ID           string
	PublicKey    []byte
	DeviceName   string
	Platform     string
	MACHash      string
	MACProof     string
	MACEncrypted string
	RequestIP    string
	BrowserIP    string
	UserID       string
	Status       string
	ExpiresAt    time.Time
	ApprovedAt   *time.Time
	CreatedAt    time.Time
}

// PlatformDeviceSessionAuth contains only verifier material. It must not be
// serialized into administrator or user APIs because the device public key is
// used to validate signatures for every Agent request.
type PlatformDeviceSessionAuth struct {
	SessionID      string
	UserID         string
	DeviceID       string
	PublicKey      []byte
	MACProofHash   string
	UserEmail      string
	DisplayName    string
	DeviceName     string
	DevicePlatform string
	AccessExpires  time.Time
	RefreshExpires time.Time
}

type PlatformDevice struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	UserEmail    string     `json:"user_email"`
	DeviceName   string     `json:"device_name"`
	Platform     string     `json:"platform"`
	Fingerprint  string     `json:"fingerprint"`
	Status       string     `json:"status"`
	RegisteredIP string     `json:"registered_ip"`
	LastIP       string     `json:"last_ip"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type PlatformProject struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	SelectedModelID string    `json:"selected_model_id,omitempty"`
	ToolPolicy      []byte    `json:"tool_policy"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type PlatformProjectInput struct {
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	SelectedModelID string `json:"selected_model_id,omitempty"`
	ToolPolicy      []byte `json:"tool_policy,omitempty"`
}

// PlatformProjectPatch uses pointers so an omitted JSON field means "leave it
// unchanged".  Empty strings remain meaningful for editable fields such as a
// project description; this prevents a PATCH that only archives a project
// from silently clearing its model or policy.
type PlatformProjectPatch struct {
	Name            *string `json:"name,omitempty"`
	Description     *string `json:"description,omitempty"`
	SelectedModelID *string `json:"selected_model_id,omitempty"`
	ToolPolicy      *[]byte `json:"tool_policy,omitempty"`
	Status          *string `json:"status,omitempty"`
}

type PlatformAgentSubKey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	DeviceID   string     `json:"device_id"`
	ProjectID  string     `json:"project_id,omitempty"`
	Status     string     `json:"status"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s *PlatformStore) CreatePlatformDeviceAuthFlow(ctx context.Context, input PlatformDeviceFlowInput) error {
	input.DeviceCode = strings.TrimSpace(input.DeviceCode)
	input.UserCode = strings.ToUpper(strings.TrimSpace(input.UserCode))
	input.DeviceName = strings.TrimSpace(input.DeviceName)
	input.Platform = strings.TrimSpace(input.Platform)
	input.MAC = normalizeDesktopMAC(input.MAC)
	if input.DeviceCode == "" || input.UserCode == "" || len(input.PublicKey) != 32 || input.DeviceName == "" || len(input.DeviceName) > 120 || len(input.Platform) > 80 || input.MAC == "" || input.TTL <= 0 || input.TTL > 15*time.Minute {
		return ErrInvalidPlatformModel
	}
	if s.vault == nil {
		return ErrPlatformDatabaseUnavailable
	}
	macEnc, err := s.vault.Encrypt(input.MAC, "platform-device-mac")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO platform_device_auth_flows(id,device_code_hash,user_code_hash,public_key,device_name,platform,mac_hash,mac_proof_hash,mac_enc,request_ip,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, newPlatformID(), tokenHash(input.DeviceCode), tokenHash(input.UserCode), input.PublicKey, input.DeviceName, input.Platform, s.vault.Namespace("platform-device-mac", input.MAC), tokenHash(input.MAC), macEnc, truncate(strings.TrimSpace(input.RequestIP), 128), time.Now().UTC().Add(input.TTL))
	return err
}

func (s *PlatformStore) PlatformDeviceFlowByDeviceCode(ctx context.Context, deviceCode string) (*PlatformDeviceAuthFlow, error) {
	return s.platformDeviceFlow(ctx, "device_code_hash", tokenHash(strings.TrimSpace(deviceCode)))
}

func (s *PlatformStore) PlatformDeviceFlowByUserCode(ctx context.Context, userCode string) (*PlatformDeviceAuthFlow, error) {
	return s.platformDeviceFlow(ctx, "user_code_hash", tokenHash(strings.ToUpper(strings.TrimSpace(userCode))))
}

func (s *PlatformStore) platformDeviceFlow(ctx context.Context, column, hash string) (*PlatformDeviceAuthFlow, error) {
	if column != "device_code_hash" && column != "user_code_hash" || hash == "" {
		return nil, ErrPlatformDeviceFlowExpired
	}
	flow := &PlatformDeviceAuthFlow{}
	var approved sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id,public_key,device_name,platform,mac_hash,mac_proof_hash,mac_enc,request_ip,browser_ip,COALESCE(user_id::text,''),status,expires_at,approved_at,created_at
FROM platform_device_auth_flows WHERE `+column+`=$1`, hash).Scan(&flow.ID, &flow.PublicKey, &flow.DeviceName, &flow.Platform, &flow.MACHash, &flow.MACProof, &flow.MACEncrypted, &flow.RequestIP, &flow.BrowserIP, &flow.UserID, &flow.Status, &flow.ExpiresAt, &approved, &flow.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPlatformDeviceFlowExpired
	}
	if err != nil {
		return nil, err
	}
	if !flow.ExpiresAt.After(time.Now().UTC()) {
		_, _ = s.db.ExecContext(ctx, `UPDATE platform_device_auth_flows SET status='expired',updated_at=now() WHERE id=$1 AND status IN ('pending','approved')`, flow.ID)
		return nil, ErrPlatformDeviceFlowExpired
	}
	if approved.Valid {
		value := approved.Time
		flow.ApprovedAt = &value
	}
	return flow, nil
}

func (s *PlatformStore) ApprovePlatformDeviceFlow(ctx context.Context, userCode, userID, browserIP string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE platform_device_auth_flows f SET status='approved',user_id=$2,browser_ip=$3,approved_at=now(),updated_at=now()
WHERE f.user_code_hash=$1 AND f.status='pending' AND f.expires_at>now() AND EXISTS(SELECT 1 FROM users u WHERE u.id=$2 AND u.status='active')`, tokenHash(strings.ToUpper(strings.TrimSpace(userCode))), strings.TrimSpace(userID), truncate(strings.TrimSpace(browserIP), 128))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrPlatformDeviceFlowExpired
	}
	return nil
}

func (s *PlatformStore) ConsumeApprovedPlatformDeviceFlow(ctx context.Context, deviceCode string, accessTTL, refreshTTL time.Duration) (access, refresh string, auth *PlatformDeviceSessionAuth, err error) {
	if accessTTL <= 0 || refreshTTL <= accessTTL || refreshTTL > 90*24*time.Hour {
		return "", "", nil, ErrInvalidPlatformModel
	}
	accessRaw, err := randomToken(32)
	if err != nil {
		return "", "", nil, err
	}
	refreshRaw, err := randomToken(48)
	if err != nil {
		return "", "", nil, err
	}
	access, refresh = "fgds_"+accessRaw, "fgdr_"+refreshRaw
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", "", nil, err
	}
	defer func() { _ = tx.Rollback() }()
	flow := &PlatformDeviceAuthFlow{}
	err = tx.QueryRowContext(ctx, `SELECT id,public_key,device_name,platform,mac_hash,mac_proof_hash,mac_enc,request_ip,browser_ip,COALESCE(user_id::text,''),status,expires_at,approved_at,created_at
FROM platform_device_auth_flows WHERE device_code_hash=$1 FOR UPDATE`, tokenHash(strings.TrimSpace(deviceCode))).Scan(&flow.ID, &flow.PublicKey, &flow.DeviceName, &flow.Platform, &flow.MACHash, &flow.MACProof, &flow.MACEncrypted, &flow.RequestIP, &flow.BrowserIP, &flow.UserID, &flow.Status, &flow.ExpiresAt, new(sql.NullTime), &flow.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) || !flow.ExpiresAt.After(time.Now().UTC()) || flow.Status == "consumed" || flow.Status == "expired" || flow.Status == "revoked" {
		return "", "", nil, ErrPlatformDeviceFlowExpired
	}
	if err != nil {
		return "", "", nil, err
	}
	if flow.Status == "pending" {
		return "", "", nil, ErrPlatformDeviceFlowPending
	}
	if flow.Status != "approved" || flow.UserID == "" {
		return "", "", nil, ErrPlatformDeviceFlowExpired
	}
	if s.vault == nil {
		return "", "", nil, ErrPlatformDatabaseUnavailable
	}
	macEnc := flow.MACEncrypted
	if _, err := s.vault.Decrypt(macEnc, "platform-device-mac"); err != nil {
		return "", "", nil, ErrPlatformDeviceSession
	}
	var userStatus string
	var userEmail, displayName string
	if err := tx.QueryRowContext(ctx, `SELECT status,email,display_name FROM users WHERE id=$1 FOR SHARE`, flow.UserID).Scan(&userStatus, &userEmail, &displayName); err != nil || userStatus != "active" {
		return "", "", nil, ErrPlatformDeviceSession
	}
	var deviceID, deviceUserID string
	err = tx.QueryRowContext(ctx, `SELECT id::text,user_id::text FROM user_devices WHERE public_key=$1 FOR UPDATE`, flow.PublicKey).Scan(&deviceID, &deviceUserID)
	if errors.Is(err, sql.ErrNoRows) {
		deviceID = newPlatformID()
		_, err = tx.ExecContext(ctx, `INSERT INTO user_devices(id,user_id,public_key,public_key_fingerprint,mac_hash,mac_proof_hash,mac_enc,device_name,platform,status,registered_ip,last_ip,last_seen_at,verified_at)
	VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,now(),now())`, deviceID, flow.UserID, flow.PublicKey, tokenHash(string(flow.PublicKey)), flow.MACHash, flow.MACProof, macEnc, flow.DeviceName, flow.Platform, flow.BrowserIP, flow.RequestIP)
		if err != nil {
			return "", "", nil, err
		}
	} else if err != nil {
		return "", "", nil, err
	} else if deviceUserID != flow.UserID {
		return "", "", nil, ErrPlatformDeviceSession
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE user_devices SET mac_hash=$2,mac_proof_hash=$3,mac_enc=$4,device_name=$5,platform=$6,status='active',registered_ip=$7,last_ip=$8,last_seen_at=now(),verified_at=now(),revoked_at=NULL,updated_at=now() WHERE id=$1`, deviceID, flow.MACHash, flow.MACProof, macEnc, flow.DeviceName, flow.Platform, flow.BrowserIP, flow.RequestIP)
		if err != nil {
			return "", "", nil, err
		}
	}
	now := time.Now().UTC()
	auth = &PlatformDeviceSessionAuth{SessionID: newPlatformID(), UserID: flow.UserID, DeviceID: deviceID, PublicKey: append([]byte(nil), flow.PublicKey...), MACProofHash: flow.MACProof, UserEmail: userEmail, DisplayName: displayName, DeviceName: flow.DeviceName, DevicePlatform: flow.Platform, AccessExpires: now.Add(accessTTL), RefreshExpires: now.Add(refreshTTL)}
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_device_sessions(id,user_id,device_id,access_hash,refresh_hash,access_expires_at,refresh_expires_at,last_ip) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, auth.SessionID, auth.UserID, auth.DeviceID, tokenHash(access), tokenHash(refresh), auth.AccessExpires, auth.RefreshExpires, flow.RequestIP); err != nil {
		return "", "", nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE platform_device_auth_flows SET status='consumed',consumed_at=now(),updated_at=now() WHERE id=$1 AND status='approved'`, flow.ID); err != nil {
		return "", "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", "", nil, err
	}
	return access, refresh, auth, nil
}

func (s *PlatformStore) PlatformDeviceSessionByAccess(ctx context.Context, token string) (*PlatformDeviceSessionAuth, error) {
	return s.platformDeviceSession(ctx, "access_hash", tokenHash(strings.TrimSpace(token)), true)
}

func (s *PlatformStore) PlatformDeviceSessionByRefresh(ctx context.Context, token string) (*PlatformDeviceSessionAuth, error) {
	return s.platformDeviceSession(ctx, "refresh_hash", tokenHash(strings.TrimSpace(token)), false)
}

func (s *PlatformStore) platformDeviceSession(ctx context.Context, column, hash string, access bool) (*PlatformDeviceSessionAuth, error) {
	if (column != "access_hash" && column != "refresh_hash") || hash == "" {
		return nil, ErrPlatformDeviceSession
	}
	item := &PlatformDeviceSessionAuth{}
	query := `SELECT s.id::text,s.user_id::text,s.device_id::text,d.public_key,d.mac_proof_hash,u.email,u.display_name,d.device_name,d.platform,s.access_expires_at,s.refresh_expires_at
FROM platform_device_sessions s JOIN users u ON u.id=s.user_id AND u.status='active' JOIN user_devices d ON d.id=s.device_id AND d.user_id=s.user_id AND d.status='active'
WHERE s.` + column + `=$1 AND s.revoked_at IS NULL`
	err := s.db.QueryRowContext(ctx, query, hash).Scan(&item.SessionID, &item.UserID, &item.DeviceID, &item.PublicKey, &item.MACProofHash, &item.UserEmail, &item.DisplayName, &item.DeviceName, &item.DevicePlatform, &item.AccessExpires, &item.RefreshExpires)
	if err != nil || (access && !item.AccessExpires.After(time.Now().UTC())) || (!access && !item.RefreshExpires.After(time.Now().UTC())) {
		return nil, ErrPlatformDeviceSession
	}
	return item, nil
}

func (s *PlatformStore) ConsumePlatformDeviceNonce(ctx context.Context, sessionID, nonce string, expiresAt time.Time) error {
	if sessionID == "" || nonce == "" || !expiresAt.After(time.Now().UTC()) {
		return ErrReplayDetected
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM platform_device_nonces WHERE expires_at<=now()`)
	_, err := s.db.ExecContext(ctx, `INSERT INTO platform_device_nonces(session_id,nonce_hash,expires_at) VALUES($1,$2,$3)`, sessionID, tokenHash(nonce), expiresAt)
	if err != nil {
		return ErrReplayDetected
	}
	return nil
}

func (s *PlatformStore) RotatePlatformDeviceSession(ctx context.Context, sessionID, currentRefresh string, accessTTL, refreshTTL time.Duration) (string, string, time.Time, time.Time, error) {
	if !strings.HasPrefix(currentRefresh, "fgdr_") || sessionID == "" || accessTTL <= 0 || refreshTTL <= accessTTL {
		return "", "", time.Time{}, time.Time{}, ErrPlatformDeviceSession
	}
	accessRaw, err := randomToken(32)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	refreshRaw, err := randomToken(48)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	access, refresh := "fgds_"+accessRaw, "fgdr_"+refreshRaw
	now := time.Now().UTC()
	accessExpiry, refreshExpiry := now.Add(accessTTL), now.Add(refreshTTL)
	result, err := s.db.ExecContext(ctx, `UPDATE platform_device_sessions SET access_hash=$2,refresh_hash=$3,access_expires_at=$4,refresh_expires_at=$5,updated_at=now()
WHERE id=$1 AND refresh_hash=$6 AND revoked_at IS NULL AND refresh_expires_at>now()`, sessionID, tokenHash(access), tokenHash(refresh), accessExpiry, refreshExpiry, tokenHash(currentRefresh))
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return "", "", time.Time{}, time.Time{}, ErrPlatformDeviceSession
	}
	return access, refresh, accessExpiry, refreshExpiry, nil
}

func (s *PlatformStore) TouchPlatformDeviceSession(ctx context.Context, sessionID, ip string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE platform_device_sessions SET last_ip=$2,last_seen_at=now(),updated_at=now() WHERE id=$1 AND revoked_at IS NULL`, sessionID, truncate(strings.TrimSpace(ip), 128))
	_, _ = s.db.ExecContext(ctx, `UPDATE user_devices SET last_ip=$2,last_seen_at=now(),updated_at=now() WHERE id=(SELECT device_id FROM platform_device_sessions WHERE id=$1) AND status='active'`, sessionID, truncate(strings.TrimSpace(ip), 128))
}

func (s *PlatformStore) RevokePlatformDevice(ctx context.Context, deviceID, ownerID string) error {
	query := `UPDATE user_devices SET status='revoked',revoked_at=now(),updated_at=now() WHERE id=$1 AND status IN ('active','reverify_required')`
	args := []any{strings.TrimSpace(deviceID)}
	if strings.TrimSpace(ownerID) != "" {
		query += " AND user_id=$2"
		args = append(args, strings.TrimSpace(ownerID))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE platform_device_sessions SET revoked_at=now(),updated_at=now() WHERE device_id=$1 AND revoked_at IS NULL`, strings.TrimSpace(deviceID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_sub_keys SET status='revoked',revoked_at=now(),updated_at=now() WHERE device_id=$1 AND status='active'`, strings.TrimSpace(deviceID)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PlatformStore) RequirePlatformDeviceMACReverification(ctx context.Context, deviceID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE user_devices SET status='reverify_required',updated_at=now() WHERE id=$1 AND status='active'`, strings.TrimSpace(deviceID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE platform_device_sessions SET revoked_at=now(),updated_at=now() WHERE device_id=$1 AND revoked_at IS NULL`, strings.TrimSpace(deviceID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_sub_keys SET status='revoked',revoked_at=now(),updated_at=now() WHERE device_id=$1 AND status='active'`, strings.TrimSpace(deviceID)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PlatformStore) RevokePlatformDeviceSession(ctx context.Context, sessionID, userID, deviceID string) error {
	sessionID, userID, deviceID = strings.TrimSpace(sessionID), strings.TrimSpace(userID), strings.TrimSpace(deviceID)
	if sessionID == "" || userID == "" || deviceID == "" {
		return ErrPlatformDeviceSession
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE platform_device_sessions SET revoked_at=now(),updated_at=now() WHERE id=$1 AND user_id=$2 AND device_id=$3 AND revoked_at IS NULL`, sessionID, userID, deviceID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrPlatformDeviceSession
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_sub_keys SET status='revoked',revoked_at=now(),updated_at=now() WHERE user_id=$1 AND device_id=$2 AND status='active'`, userID, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PlatformStore) ListPlatformDevices(ctx context.Context, ownerID string) ([]PlatformDevice, error) {
	query := `SELECT d.id::text,d.user_id::text,u.email,d.device_name,d.platform,d.public_key_fingerprint,d.status,d.registered_ip,d.last_ip,d.last_seen_at,d.created_at
FROM user_devices d JOIN users u ON u.id=d.user_id WHERE u.tenant_id=$1`
	args := []any{DefaultPlatformTenantID()}
	if strings.TrimSpace(ownerID) != "" {
		query += " AND d.user_id=$2"
		args = append(args, strings.TrimSpace(ownerID))
	}
	query += " ORDER BY d.created_at DESC"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformDevice, 0)
	for rows.Next() {
		var item PlatformDevice
		var last sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserID, &item.UserEmail, &item.DeviceName, &item.Platform, &item.Fingerprint, &item.Status, &item.RegisteredIP, &item.LastIP, &last, &item.CreatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			value := last.Time
			item.LastSeenAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) CreatePlatformProject(ctx context.Context, userID string, input PlatformProjectInput) (*PlatformProject, error) {
	userID, input.Name, input.Description = strings.TrimSpace(userID), strings.TrimSpace(input.Name), strings.TrimSpace(input.Description)
	if userID == "" || input.Name == "" || len(input.Name) > 120 || len(input.Description) > 4000 || (input.SelectedModelID != "" && len(input.SelectedModelID) > 64) {
		return nil, ErrInvalidPlatformModel
	}
	if len(input.ToolPolicy) == 0 {
		input.ToolPolicy = []byte(`{}`)
	}
	if !isJSONObject(input.ToolPolicy) {
		return nil, ErrInvalidPlatformModel
	}
	item := &PlatformProject{ID: newPlatformID(), UserID: userID, Name: input.Name, Description: input.Description, SelectedModelID: strings.TrimSpace(input.SelectedModelID), ToolPolicy: append([]byte(nil), input.ToolPolicy...), Status: "active"}
	err := s.db.QueryRowContext(ctx, `INSERT INTO projects(id,user_id,name,description,selected_model_id,tool_policy,status) SELECT $1,$2,$3,$4,NULLIF($5,'')::uuid,$6::jsonb,'active' WHERE EXISTS(SELECT 1 FROM users WHERE id=$2 AND status='active') RETURNING created_at,updated_at`, item.ID, item.UserID, item.Name, item.Description, item.SelectedModelID, string(item.ToolPolicy)).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return item, nil
}

func (s *PlatformStore) ListPlatformProjects(ctx context.Context, userID string) ([]PlatformProject, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,user_id::text,name,description,COALESCE(selected_model_id::text,''),tool_policy,status,created_at,updated_at FROM projects WHERE user_id=$1 ORDER BY updated_at DESC`, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformProject, 0)
	for rows.Next() {
		var item PlatformProject
		if err := rows.Scan(&item.ID, &item.UserID, &item.Name, &item.Description, &item.SelectedModelID, &item.ToolPolicy, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) UpdatePlatformProject(ctx context.Context, userID, projectID string, patch PlatformProjectPatch) (*PlatformProject, error) {
	userID, projectID = strings.TrimSpace(userID), strings.TrimSpace(projectID)
	if userID == "" || projectID == "" {
		return nil, ErrInvalidPlatformModel
	}

	var name, description, modelID, status any
	var toolPolicy any
	modelProvided, policyProvided := false, false
	if patch.Name != nil {
		value := strings.TrimSpace(*patch.Name)
		if value == "" || len(value) > 120 {
			return nil, ErrInvalidPlatformModel
		}
		name = value
	}
	if patch.Description != nil {
		value := strings.TrimSpace(*patch.Description)
		if len(value) > 4000 {
			return nil, ErrInvalidPlatformModel
		}
		description = value
	}
	if patch.SelectedModelID != nil {
		value := strings.TrimSpace(*patch.SelectedModelID)
		if len(value) > 64 {
			return nil, ErrInvalidPlatformModel
		}
		modelID, modelProvided = value, true
	}
	if patch.ToolPolicy != nil {
		value := *patch.ToolPolicy
		if len(value) == 0 || !isJSONObject(value) {
			return nil, ErrInvalidPlatformModel
		}
		toolPolicy, policyProvided = string(value), true
	}
	if patch.Status != nil {
		value := strings.TrimSpace(*patch.Status)
		if value != "active" && value != "archived" {
			return nil, ErrInvalidPlatformModel
		}
		status = value
	}
	if name == nil && description == nil && !modelProvided && !policyProvided && status == nil {
		return nil, ErrInvalidPlatformModel
	}

	item := &PlatformProject{ID: projectID, UserID: userID}
	const query = `UPDATE projects SET
	name=COALESCE($3,name),
	description=COALESCE($4,description),
	selected_model_id=CASE WHEN $5 THEN NULLIF($6,'')::uuid ELSE selected_model_id END,
	tool_policy=CASE WHEN $7 THEN $8::jsonb ELSE tool_policy END,
	status=COALESCE($9,status),updated_at=now()
WHERE id=$1 AND user_id=$2
RETURNING name,description,COALESCE(selected_model_id::text,''),tool_policy,status,created_at,updated_at`
	err := s.db.QueryRowContext(ctx, query, item.ID, item.UserID, name, description, modelProvided, modelID, policyProvided, toolPolicy, status).Scan(
		&item.Name, &item.Description, &item.SelectedModelID, &item.ToolPolicy, &item.Status, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PlatformStore) DeletePlatformProject(ctx context.Context, userID, projectID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE id=$1 AND user_id=$2`, strings.TrimSpace(projectID), strings.TrimSpace(userID))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *PlatformStore) CreatePlatformAgentSubKey(ctx context.Context, userID, deviceID, projectID string, ttl time.Duration) (*PlatformAgentSubKey, string, error) {
	userID, deviceID, projectID = strings.TrimSpace(userID), strings.TrimSpace(deviceID), strings.TrimSpace(projectID)
	if userID == "" || deviceID == "" || ttl <= 0 || ttl > 24*time.Hour || s.vault == nil {
		return nil, "", ErrInvalidPlatformModel
	}
	plainRaw, err := randomToken(32)
	if err != nil {
		return nil, "", err
	}
	plain := "fgsk_" + plainRaw
	enc, err := s.encryptPlatformSecret(plain, "platform-agent-sub-key")
	if err != nil {
		return nil, "", err
	}
	item := &PlatformAgentSubKey{ID: newPlatformID(), UserID: userID, DeviceID: deviceID, ProjectID: projectID, Status: "active", ExpiresAt: time.Now().UTC().Add(ttl)}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = tx.Rollback() }()
	var valid bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_devices d JOIN users u ON u.id=d.user_id WHERE d.id=$1 AND d.user_id=$2 AND d.status='active' AND u.status='active')`, deviceID, userID).Scan(&valid); err != nil {
		return nil, "", err
	}
	if !valid {
		return nil, "", ErrPlatformDeviceSession
	}
	if projectID != "" {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND user_id=$2 AND status='active')`, projectID, userID).Scan(&valid); err != nil {
			return nil, "", err
		}
		if !valid {
			return nil, "", ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_sub_keys(id,user_id,device_id,project_id,key_hash,key_enc,status,expires_at) VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,'active',$7)`, item.ID, item.UserID, item.DeviceID, item.ProjectID, tokenHash(plain), enc, item.ExpiresAt); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	return item, plain, nil
}

func (s *PlatformStore) RevokePlatformAgentSubKey(ctx context.Context, id, ownerID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE agent_sub_keys SET status='revoked',revoked_at=now(),updated_at=now() WHERE id=$1 AND user_id=$2 AND status='active'`, strings.TrimSpace(id), strings.TrimSpace(ownerID))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *PlatformStore) ListPlatformAgentSubKeys(ctx context.Context, userID, deviceID string) ([]PlatformAgentSubKey, error) {
	query := `SELECT id::text,user_id::text,device_id::text,COALESCE(project_id::text,''),status,expires_at,last_used_at,created_at FROM agent_sub_keys WHERE user_id=$1`
	args := []any{strings.TrimSpace(userID)}
	if strings.TrimSpace(deviceID) != "" {
		query += " AND device_id=$2"
		args = append(args, strings.TrimSpace(deviceID))
	}
	query += " ORDER BY created_at DESC"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformAgentSubKey, 0)
	for rows.Next() {
		var item PlatformAgentSubKey
		var last sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserID, &item.DeviceID, &item.ProjectID, &item.Status, &item.ExpiresAt, &last, &item.CreatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			v := last.Time
			item.LastUsedAt = &v
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
