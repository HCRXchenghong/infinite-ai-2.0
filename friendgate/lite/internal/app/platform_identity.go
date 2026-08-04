package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"net/netip"
	"strings"
	"time"
)

var (
	ErrRegistrationClosed    = errors.New("user registration is closed")
	ErrRegistrationInvite    = errors.New("a valid user invitation is required")
	ErrPlatformInviteInvalid = errors.New("user invitation is invalid or expired")
	ErrPlatformKeyInactive   = errors.New("platform API key is inactive")
	ErrPlatformKeyIPDenied   = errors.New("platform API key IP policy denied request")
)

type RegistrationMode string

const (
	RegistrationClosed     RegistrationMode = "closed"
	RegistrationInviteOnly RegistrationMode = "invite_only"
	RegistrationPublic     RegistrationMode = "public"
)

func (m RegistrationMode) Valid() bool {
	return m == RegistrationClosed || m == RegistrationInviteOnly || m == RegistrationPublic
}

type PlatformUser struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type PlatformUserRegistration struct {
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	Password        string `json:"password"`
	InvitationToken string `json:"invitation_token,omitempty"`
	InvitationCode  string `json:"invitation_code,omitempty"`
}

type PlatformUserSession struct {
	User      PlatformUser `json:"user"`
	CSRFToken string       `json:"csrf_token,omitempty"`
}

type PlatformInvitationInput struct {
	RoleLabel string          `json:"role_label"`
	Policy    json.RawMessage `json:"policy,omitempty"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type PlatformInvitationSecret struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PlatformInvitation struct {
	ID        string          `json:"id"`
	RoleLabel string          `json:"role_label"`
	Status    string          `json:"status"`
	Policy    json.RawMessage `json:"policy"`
	ExpiresAt time.Time       `json:"expires_at"`
	ClaimedBy string          `json:"claimed_by,omitempty"`
	ClaimedAt *time.Time      `json:"claimed_at,omitempty"`
	RevokedAt *time.Time      `json:"revoked_at,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type PlatformAPIKeyInput struct {
	UserID       string                  `json:"user_id"`
	RoutePoolID  string                  `json:"route_pool_id,omitempty"`
	Label        string                  `json:"label"`
	Scopes       []PlatformKeyScopeInput `json:"scopes"`
	IPPolicy     json.RawMessage         `json:"ip_policy,omitempty"`
	DevicePolicy json.RawMessage         `json:"device_policy,omitempty"`
	ExpiresAt    *time.Time              `json:"expires_at,omitempty"`
}

type PlatformKeyScopeInput struct {
	ProductScope ProductScope `json:"product_scope"`
	ModelID      string       `json:"model_id"`
}

type PlatformAPIKey struct {
	ID          string                  `json:"id"`
	UserID      string                  `json:"user_id"`
	RoutePoolID string                  `json:"route_pool_id,omitempty"`
	Label       string                  `json:"label"`
	MaskedKey   string                  `json:"masked_key"`
	Version     int64                   `json:"version"`
	Status      string                  `json:"status"`
	ExpiresAt   *time.Time              `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time              `json:"last_used_at,omitempty"`
	Scopes      []PlatformKeyScopeInput `json:"scopes,omitempty"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

// RegistrationMode reads the single tenant policy. A missing setting fails
// closed to invitation-only rather than unexpectedly opening registration.
func (s *PlatformStore) RegistrationMode(ctx context.Context) (RegistrationMode, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value::text FROM platform_settings WHERE tenant_id=$1 AND key='registration_mode'`, DefaultPlatformTenantID()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return RegistrationInviteOnly, nil
	}
	if err != nil {
		return "", err
	}
	var mode RegistrationMode
	if json.Unmarshal([]byte(raw), &mode) != nil || !mode.Valid() {
		return RegistrationInviteOnly, nil
	}
	return mode, nil
}

func (s *PlatformStore) SetRegistrationMode(ctx context.Context, mode RegistrationMode, actorID string) error {
	if !mode.Valid() {
		return ErrInvalidPlatformModel
	}
	var actor any
	if strings.TrimSpace(actorID) != "" {
		actor = actorID
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO platform_settings(tenant_id,key,value,updated_by,updated_at) VALUES($1,'registration_mode',$2::jsonb,$3,now()) ON CONFLICT(tenant_id,key) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=now()`, DefaultPlatformTenantID(), mustJSON(string(mode)), actor)
	return err
}

func (s *PlatformStore) ListPlatformUsers(ctx context.Context) ([]PlatformUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,email,display_name,status,last_login_at,created_at,updated_at FROM users WHERE tenant_id=$1 ORDER BY created_at DESC`, DefaultPlatformTenantID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformUser, 0)
	for rows.Next() {
		var item PlatformUser
		var last sql.NullTime
		if err := rows.Scan(&item.ID, &item.Email, &item.DisplayName, &item.Status, &last, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			item.LastLoginAt = &last.Time
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) SetPlatformUserStatus(ctx context.Context, userID, status string) error {
	status = strings.TrimSpace(strings.ToLower(status))
	if status != "active" && status != "suspended" && status != "deleted" {
		return ErrInvalidPlatformModel
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE users SET status=$2,updated_at=now() WHERE id=$1 AND tenant_id=$3`, strings.TrimSpace(userID), status, DefaultPlatformTenantID())
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	if status != "active" {
		if _, err := tx.ExecContext(ctx, `UPDATE user_sessions SET status='revoked',revoked_at=now() WHERE user_id=$1 AND status='active'`, strings.TrimSpace(userID)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE api_keys_v2 SET status='disabled',key_version=key_version+1,disabled_at=now(),updated_at=now() WHERE user_id=$1 AND status='active'`, strings.TrimSpace(userID)); err != nil {
			return err
		}
		// Suspending a user must be just as immediate for the desktop Agent as
		// it is for browser and external API sessions.  A future re-enable
		// requires the device to complete a fresh browser approval instead of
		// silently reviving an old hardware binding.
		if _, err := tx.ExecContext(ctx, `UPDATE platform_device_sessions SET revoked_at=now(),updated_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, strings.TrimSpace(userID)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_sub_keys SET status='revoked',revoked_at=now(),updated_at=now() WHERE user_id=$1 AND status='active'`, strings.TrimSpace(userID)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_devices SET status='reverify_required',updated_at=now() WHERE user_id=$1 AND status='active'`, strings.TrimSpace(userID)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PlatformStore) RegisterUser(ctx context.Context, input PlatformUserRegistration) (*PlatformUser, error) {
	if err := validatePlatformRegistration(&input); err != nil {
		return nil, err
	}
	mode, err := s.RegistrationMode(ctx)
	if err != nil {
		return nil, err
	}
	if mode == RegistrationClosed {
		return nil, ErrRegistrationClosed
	}
	if mode == RegistrationInviteOnly && (strings.TrimSpace(input.InvitationToken) == "" || strings.TrimSpace(input.InvitationCode) == "") {
		return nil, ErrRegistrationInvite
	}
	hash, err := passwordHash(input.Password, 600_000)
	if err != nil {
		return nil, err
	}
	user := &PlatformUser{ID: newPlatformID(), Email: normalizePlatformEmail(input.Email), DisplayName: strings.TrimSpace(input.DisplayName), Status: "active"}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	invitationID := ""
	if mode == RegistrationInviteOnly {
		invitationID, err = verifyPlatformInvitation(ctx, tx, input.InvitationToken, input.InvitationCode)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO users(id,tenant_id,email,display_name,status,password_hash) VALUES($1,$2,$3,$4,'active',$5) RETURNING created_at,updated_at`, user.ID, DefaultPlatformTenantID(), user.Email, user.DisplayName, hash).Scan(&user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, err
	}
	// Every newly registered user receives the current Free plan as two fully
	// separate wallet allocations. This makes Chat and Agent accounting usable
	// from the first request while preserving the hard no-cross-spend boundary.
	if err := provisionDefaultFreePlan(ctx, tx, user.ID); err != nil {
		return nil, err
	}
	if invitationID != "" {
		result, claimErr := tx.ExecContext(ctx, `UPDATE invitations_v2 SET status='claimed',claimed_by=$2,claimed_at=now() WHERE id=$1 AND status='pending'`, invitationID, user.ID)
		if claimErr != nil {
			return nil, claimErr
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return nil, ErrPlatformInviteInvalid
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return user, nil
}

func provisionDefaultFreePlan(ctx context.Context, tx *sql.Tx, userID string) error {
	var version struct {
		id, planID                string
		chatMonthly, agentMonthly int64
		chatRolling, agentRolling int64
	}
	err := tx.QueryRowContext(ctx, `SELECT v.id::text,v.plan_id::text,v.chat_monthly_tokens,v.agent_monthly_tokens,v.chat_rolling_5h_tokens,v.agent_rolling_5h_tokens
FROM plans p JOIN plan_versions v ON v.plan_id=p.id AND v.ends_at IS NULL
WHERE p.code='free' AND p.status='active' FOR SHARE`).Scan(&version.id, &version.planID, &version.chatMonthly, &version.agentMonthly, &version.chatRolling, &version.agentRolling)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidPlan
	}
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	monthlyEnds := now.AddDate(0, 1, 0)
	subscriptionID := newPlatformID()
	snapshot := mustJSON(map[string]any{"plan_code": "free", "plan_version_id": version.id, "assigned_at": now.Format(time.RFC3339)})
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscriptions(id,user_id,plan_version_id,status,source,starts_at,ends_at,snapshot) VALUES($1,$2,$3,'active','free_assignment',$4,$5,$6::jsonb)`, subscriptionID, userID, version.id, now, monthlyEnds, snapshot); err != nil {
		return err
	}
	allocations := []struct {
		scope            ProductScope
		monthly, rolling int64
	}{
		{ProductScopeChat, version.chatMonthly, version.chatRolling},
		{ProductScopeAgent, version.agentMonthly, version.agentRolling},
	}
	for _, allocation := range allocations {
		walletID := newPlatformID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO wallet_accounts(id,user_id,product_scope) VALUES($1,$2,$3)`, walletID, userID, allocation.scope); err != nil {
			return err
		}
		for _, bucket := range []struct {
			window string
			starts time.Time
			ends   time.Time
			tokens int64
		}{
			{"monthly", now, monthlyEnds, allocation.monthly},
			{"rolling_5h", now, now.Add(5 * time.Hour), allocation.rolling},
		} {
			bucketID := newPlatformID()
			if _, err := tx.ExecContext(ctx, `INSERT INTO quota_buckets(id,wallet_account_id,window_kind,starts_at,ends_at,granted_tokens,source_subscription_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, bucketID, walletID, bucket.window, bucket.starts, bucket.ends, bucket.tokens, subscriptionID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_entries(id,wallet_account_id,quota_bucket_id,entry_type,tokens,reference_type,reference_id,reason) VALUES($1,$2,$3,'grant',$4,'subscription',$5,'initial free plan allocation')`, newPlatformID(), walletID, bucketID, bucket.tokens, subscriptionID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *PlatformStore) AuthenticateUser(ctx context.Context, email, password string) (*PlatformUser, error) {
	email = normalizePlatformEmail(email)
	var user PlatformUser
	var hash string
	var last sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id::text,email,display_name,status,password_hash,last_login_at,created_at,updated_at FROM users WHERE tenant_id=$1 AND email=$2`, DefaultPlatformTenantID(), email).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Status, &hash, &last, &user.CreatedAt, &user.UpdatedAt)
	if err != nil || user.Status != "active" || !passwordVerify(hash, password) {
		return nil, ErrInvalidAdminCredentials
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at=$2,updated_at=$2 WHERE id=$1 AND status='active'`, user.ID, now); err != nil {
		return nil, err
	}
	user.LastLoginAt = &now
	return &user, nil
}

func (s *PlatformStore) NewPlatformUserSession(ctx context.Context, userID, ip, userAgent string, ttl time.Duration) (string, string, error) {
	if ttl <= 0 || ttl > 90*24*time.Hour {
		return "", "", ErrInvalidPlatformModel
	}
	token, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return "", "", err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO user_sessions(id,user_id,token_hash,csrf_token_hash,ip_prefix,user_agent_hash,status,expires_at) SELECT $1,id,$2,$3,$4,$5,'active',$6 FROM users WHERE id=$7 AND status='active'`, newPlatformID(), tokenHash(token), tokenHash(csrf), platformIPPrefix(ip), tokenHash(truncate(userAgent, 512)), time.Now().UTC().Add(ttl), strings.TrimSpace(userID))
	if err != nil {
		return "", "", err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return "", "", ErrUserInactive
	}
	return token, csrf, nil
}

func (s *PlatformStore) PlatformUserSession(ctx context.Context, token, ip, userAgent string) (*PlatformUser, error) {
	var user PlatformUser
	var last sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT u.id::text,u.email,u.display_name,u.status,u.last_login_at,u.created_at,u.updated_at FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.status='active' AND s.expires_at>now() AND (s.ip_prefix='' OR s.ip_prefix=$2) AND (s.user_agent_hash='' OR s.user_agent_hash=$3) AND u.status='active'`, tokenHash(token), platformIPPrefix(ip), tokenHash(truncate(userAgent, 512))).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Status, &last, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, ErrUserInactive
	}
	if last.Valid {
		user.LastLoginAt = &last.Time
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE user_sessions SET last_seen_at=now() WHERE token_hash=$1 AND status='active'`, tokenHash(token))
	return &user, nil
}

func (s *PlatformStore) VerifyPlatformCSRF(ctx context.Context, token, csrf string) bool {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_sessions WHERE token_hash=$1 AND csrf_token_hash=$2 AND status='active' AND expires_at>now()`, tokenHash(token), tokenHash(csrf)).Scan(&count)
	return err == nil && count == 1
}
func (s *PlatformStore) RevokePlatformUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_sessions SET status='revoked',revoked_at=now() WHERE user_id=$1 AND status='active'`, strings.TrimSpace(userID))
	return err
}

// RevokePlatformUserSession is the single-browser logout primitive. Account
// suspension/password reset uses RevokePlatformUserSessions instead.
func (s *PlatformStore) RevokePlatformUserSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_sessions SET status='revoked',revoked_at=now() WHERE token_hash=$1 AND status='active'`, tokenHash(strings.TrimSpace(token)))
	return err
}

// RotatePlatformUserCSRF gives a resumed browser a fresh mutation token
// without ever storing the plaintext CSRF secret in PostgreSQL. Session cookie
// validation is repeated in the same statement, including IP prefix and
// User-Agent binding, so a stolen cookie cannot ask for a usable CSRF token
// from a different client fingerprint.
func (s *PlatformStore) RotatePlatformUserCSRF(ctx context.Context, token, ip, userAgent string) (string, error) {
	csrf, err := randomToken(24)
	if err != nil {
		return "", err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE user_sessions SET csrf_token_hash=$1,last_seen_at=now()
WHERE token_hash=$2 AND status='active' AND expires_at>now() AND (ip_prefix='' OR ip_prefix=$3) AND (user_agent_hash='' OR user_agent_hash=$4)`, tokenHash(csrf), tokenHash(strings.TrimSpace(token)), platformIPPrefix(ip), tokenHash(truncate(userAgent, 512)))
	if err != nil {
		return "", err
	}
	if updated, _ := result.RowsAffected(); updated != 1 {
		return "", ErrUserInactive
	}
	return csrf, nil
}

func (s *PlatformStore) CreatePlatformInvitation(ctx context.Context, input PlatformInvitationInput) (*PlatformInvitationSecret, error) {
	input.RoleLabel = strings.TrimSpace(input.RoleLabel)
	if input.RoleLabel == "" || len(input.RoleLabel) > 160 || input.ExpiresAt.Before(time.Now().UTC().Add(time.Minute)) {
		return nil, ErrInvalidPlatformModel
	}
	if len(input.Policy) == 0 {
		input.Policy = json.RawMessage(`{}`)
	}
	if !isJSONObject(input.Policy) {
		return nil, ErrInvalidPlatformModel
	}
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	code, err := randomDigits(6)
	if err != nil {
		return nil, err
	}
	codeHash, err := passwordHash(code, 150_000)
	if err != nil {
		return nil, err
	}
	item := &PlatformInvitationSecret{ID: newPlatformID(), Token: "iuinv_" + token, Code: code, ExpiresAt: input.ExpiresAt.UTC()}
	_, err = s.db.ExecContext(ctx, `INSERT INTO invitations_v2(id,tenant_id,role_label,token_hash,code_hash,status,policy,expires_at) VALUES($1,$2,$3,$4,$5,'pending',$6::jsonb,$7)`, item.ID, DefaultPlatformTenantID(), input.RoleLabel, tokenHash(item.Token), codeHash, string(input.Policy), item.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return item, nil
}
func (s *PlatformStore) ListPlatformInvitations(ctx context.Context) ([]PlatformInvitation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,role_label,status,policy,expires_at,COALESCE(claimed_by::text,''),claimed_at,revoked_at,created_at FROM invitations_v2 WHERE tenant_id=$1 AND status<>'deleted' ORDER BY created_at DESC`, DefaultPlatformTenantID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformInvitation, 0)
	for rows.Next() {
		var item PlatformInvitation
		var claimed, revoked sql.NullTime
		if err := rows.Scan(&item.ID, &item.RoleLabel, &item.Status, &item.Policy, &item.ExpiresAt, &item.ClaimedBy, &claimed, &revoked, &item.CreatedAt); err != nil {
			return nil, err
		}
		if claimed.Valid {
			item.ClaimedAt = &claimed.Time
		}
		if revoked.Valid {
			item.RevokedAt = &revoked.Time
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *PlatformStore) RevokePlatformInvitation(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE invitations_v2 SET status='revoked',revoked_at=now() WHERE id=$1 AND status='pending' AND expires_at>now()`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}
func (s *PlatformStore) DeletePlatformInvitation(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE invitations_v2 SET status='deleted',deleted_at=now(),token_hash='',code_hash='' WHERE id=$1 AND status IN ('claimed','revoked','expired','deleted')`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *PlatformStore) CreatePlatformAPIKey(ctx context.Context, input PlatformAPIKeyInput) (*PlatformAPIKey, string, error) {
	if err := validatePlatformAPIKeyInput(&input); err != nil {
		return nil, "", err
	}
	plain, err := randomToken(32)
	if err != nil {
		return nil, "", err
	}
	plain = "sk-ia_" + plain
	encrypted, err := s.encryptPlatformSecret(plain, "platform-api-key")
	if err != nil {
		return nil, "", err
	}
	item := &PlatformAPIKey{ID: newPlatformID(), UserID: input.UserID, RoutePoolID: input.RoutePoolID, Label: input.Label, MaskedKey: maskPlatformKey(plain), Version: 1, Status: "active", ExpiresAt: input.ExpiresAt, Scopes: append([]PlatformKeyScopeInput(nil), input.Scopes...)}
	if len(input.IPPolicy) == 0 {
		input.IPPolicy = json.RawMessage(`{"mode":"unrestricted"}`)
	}
	if len(input.DevicePolicy) == 0 {
		input.DevicePolicy = json.RawMessage(`{"mode":"unrestricted"}`)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var pool any
	if input.RoutePoolID != "" {
		pool = input.RoutePoolID
	}
	if err = tx.QueryRowContext(ctx, `INSERT INTO api_keys_v2(id,user_id,route_pool_id,label,key_hash,key_enc,key_version,status,expires_at,ip_policy,device_policy) SELECT $1,u.id,$2,$3,$4,$5,1,'active',$6,$7::jsonb,$8::jsonb FROM users u WHERE u.id=$9 AND u.status='active' RETURNING created_at,updated_at`, item.ID, pool, item.Label, tokenHash(plain), encrypted, item.ExpiresAt, string(input.IPPolicy), string(input.DevicePolicy), item.UserID).Scan(&item.CreatedAt, &item.UpdatedAt); err != nil {
		return nil, "", err
	}
	for _, scope := range item.Scopes {
		if _, err = tx.ExecContext(ctx, `INSERT INTO api_key_scopes(api_key_id,product_scope,model_id) VALUES($1,$2,$3)`, item.ID, scope.ProductScope, scope.ModelID); err != nil {
			return nil, "", err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return item, plain, nil
}

func (s *PlatformStore) ListPlatformAPIKeys(ctx context.Context) ([]PlatformAPIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,user_id::text,COALESCE(route_pool_id::text,''),label,key_enc,key_version,status,expires_at,last_used_at,created_at,updated_at FROM api_keys_v2 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformAPIKey, 0)
	index := make(map[string]int)
	for rows.Next() {
		var item PlatformAPIKey
		var encrypted string
		var expires, last sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserID, &item.RoutePoolID, &item.Label, &encrypted, &item.Version, &item.Status, &expires, &last, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if expires.Valid {
			item.ExpiresAt = &expires.Time
		}
		if last.Valid {
			item.LastUsedAt = &last.Time
		}
		item.MaskedKey = "unavailable"
		if encrypted != "" {
			if plain, err := s.decryptPlatformSecret(encrypted, "platform-api-key"); err == nil {
				item.MaskedKey = maskPlatformKey(plain)
			}
		}
		index[item.ID] = len(items)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	scopeRows, err := s.db.QueryContext(ctx, `SELECT api_key_id::text,product_scope,model_id::text FROM api_key_scopes ORDER BY api_key_id,product_scope,model_id`)
	if err != nil {
		return nil, err
	}
	defer scopeRows.Close()
	for scopeRows.Next() {
		var keyID string
		var scope PlatformKeyScopeInput
		if err := scopeRows.Scan(&keyID, &scope.ProductScope, &scope.ModelID); err != nil {
			return nil, err
		}
		if itemIndex, ok := index[keyID]; ok {
			items[itemIndex].Scopes = append(items[itemIndex].Scopes, scope)
		}
	}
	return items, scopeRows.Err()
}

func (s *PlatformStore) CopyPlatformAPIKey(ctx context.Context, id string) (string, error) {
	var encrypted string
	err := s.db.QueryRowContext(ctx, `SELECT key_enc FROM api_keys_v2 WHERE id=$1 AND status='active'`, strings.TrimSpace(id)).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return s.decryptPlatformSecret(encrypted, "platform-api-key")
}
func (s *PlatformStore) SetPlatformAPIKeyStatus(ctx context.Context, id, status string) error {
	status = strings.TrimSpace(strings.ToLower(status))
	if status != "active" && status != "disabled" {
		return ErrInvalidPlatformModel
	}
	result, err := s.db.ExecContext(ctx, `UPDATE api_keys_v2 SET status=$2,key_version=key_version+1,disabled_at=CASE WHEN $2='disabled' THEN now() ELSE NULL END,updated_at=now() WHERE id=$1 AND status<>'deleted'`, strings.TrimSpace(id), status)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}
func (s *PlatformStore) DeletePlatformAPIKey(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE api_keys_v2 SET status='deleted',key_version=key_version+1,key_enc='',disabled_at=now(),deleted_at=now(),updated_at=now() WHERE id=$1 AND status<>'deleted'`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *PlatformStore) AuthorizePlatformAPIKey(ctx context.Context, plain, ip string) (*PlatformAPIKey, error) {
	var item PlatformAPIKey
	var expires, last sql.NullTime
	var policy json.RawMessage
	err := s.db.QueryRowContext(ctx, `SELECT k.id::text,k.user_id::text,COALESCE(k.route_pool_id::text,''),k.label,k.key_version,k.status,k.expires_at,k.last_used_at,k.ip_policy,k.created_at,k.updated_at
FROM api_keys_v2 k
JOIN users u ON u.id=k.user_id AND u.status='active'
WHERE k.key_hash=$1 AND k.status='active' AND (k.expires_at IS NULL OR k.expires_at>now())`, tokenHash(strings.TrimSpace(plain))).Scan(&item.ID, &item.UserID, &item.RoutePoolID, &item.Label, &item.Version, &item.Status, &expires, &last, &policy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, ErrPlatformKeyInactive
	}
	if expires.Valid {
		item.ExpiresAt = &expires.Time
	}
	if last.Valid {
		item.LastUsedAt = &last.Time
	}
	if !platformIPAllowed(policy, ip) {
		return nil, ErrPlatformKeyIPDenied
	}
	rows, err := s.db.QueryContext(ctx, `SELECT product_scope,model_id::text FROM api_key_scopes WHERE api_key_id=$1 ORDER BY product_scope,model_id`, item.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var scope PlatformKeyScopeInput
		if err := rows.Scan(&scope.ProductScope, &scope.ModelID); err != nil {
			return nil, err
		}
		item.Scopes = append(item.Scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_keys_v2 SET last_used_at=now(),updated_at=now() WHERE id=$1 AND status='active'`, item.ID)
	return &item, nil
}

func verifyPlatformInvitation(ctx context.Context, tx *sql.Tx, token, code string) (string, error) {
	var id, hash, status string
	var expires time.Time
	err := tx.QueryRowContext(ctx, `SELECT id::text,code_hash,status,expires_at FROM invitations_v2 WHERE token_hash=$1 FOR UPDATE`, tokenHash(strings.TrimSpace(token))).Scan(&id, &hash, &status, &expires)
	if err != nil {
		return "", ErrPlatformInviteInvalid
	}
	if status != "pending" || !expires.After(time.Now().UTC()) || !passwordVerify(hash, strings.TrimSpace(code)) {
		return "", ErrPlatformInviteInvalid
	}
	return id, nil
}

func validatePlatformRegistration(input *PlatformUserRegistration) error {
	input.Email = normalizePlatformEmail(input.Email)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if parsed, err := mail.ParseAddress(input.Email); err != nil || parsed.Address != input.Email || len(input.Email) > 254 {
		return ErrInvalidPlatformModel
	}
	if len(input.DisplayName) < 1 || len(input.DisplayName) > 80 || len(input.Password) < 12 || len(input.Password) > 256 {
		return ErrInvalidPlatformModel
	}
	return nil
}
func validatePlatformAPIKeyInput(input *PlatformAPIKeyInput) error {
	input.UserID = strings.TrimSpace(input.UserID)
	input.RoutePoolID = strings.TrimSpace(input.RoutePoolID)
	input.Label = strings.TrimSpace(input.Label)
	if input.UserID == "" || input.Label == "" || len(input.Label) > 160 || len(input.Scopes) == 0 {
		return ErrInvalidPlatformModel
	}
	if input.ExpiresAt != nil && input.ExpiresAt.Before(time.Now().UTC()) {
		return ErrInvalidPlatformModel
	}
	for _, scope := range input.Scopes {
		if !scope.ProductScope.Valid() || strings.TrimSpace(scope.ModelID) == "" {
			return ErrInvalidPlatformModel
		}
	}
	for _, raw := range []json.RawMessage{input.IPPolicy, input.DevicePolicy} {
		if len(raw) > 0 && !isJSONObject(raw) {
			return ErrInvalidPlatformModel
		}
	}
	return nil
}
func normalizePlatformEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func platformIPPrefix(raw string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	bits := 64
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address.Unmap(), bits).Masked().String()
}
func platformIPAllowed(raw json.RawMessage, ip string) bool {
	var policy struct {
		Mode      string   `json:"mode"`
		Addresses []string `json:"addresses"`
	}
	if json.Unmarshal(raw, &policy) != nil || policy.Mode == "" || policy.Mode == "unrestricted" {
		return true
	}
	if policy.Mode != "allow_list" {
		return false
	}
	candidate, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	for _, value := range policy.Addresses {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(value)); err == nil && prefix.Contains(candidate) {
			return true
		}
		if address, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil && address == candidate {
			return true
		}
	}
	return false
}
func maskPlatformKey(plain string) string {
	if len(plain) <= 12 {
		return "********"
	}
	return plain[:7] + "…" + plain[len(plain)-4:]
}
